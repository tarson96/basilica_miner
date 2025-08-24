//! # Validator Communications
//!
//! Simplified gRPC server for handling validator requests according to SPEC v1.6.
//! Primary responsibilities:
//! - Authenticate validators
//! - List available executors
//! - Coordinate SSH access to executors

use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::executor_manager::AvailableExecutor;

use tonic::{transport::Server, Request, Response, Status};
use tonic_health::server::health_reporter;
use tracing::{debug, error, info, warn};

use basilica_common::identity::Hotkey;
use basilica_protocol::miner_discovery::{
    miner_discovery_server::{MinerDiscovery, MinerDiscoveryServer},
    CloseSshSessionRequest, CloseSshSessionResponse, ExecutorConnectionDetails,
    InitiateSshSessionRequest, InitiateSshSessionResponse, LeaseOfferResponse, LeaseRequest,
    ListSshSessionsRequest, ListSshSessionsResponse, MinerAuthResponse, SessionInitRequest,
    SessionInitResponse, ValidatorAuthRequest,
};

use crate::auth::JwtAuthService;
use crate::config::{MinerConfig, SecurityConfig, ValidatorCommsConfig};
use crate::executor_manager::ExecutorManager;
use crate::persistence::RegistrationDb;
use crate::ssh::{SshSessionOrchestrator, ValidatorAccessService};
use crate::validator_discovery::ValidatorDiscovery;

/// Validator communications server
#[derive(Clone)]
pub struct ValidatorCommsServer {
    config: ValidatorCommsConfig,
    security_config: SecurityConfig,
    executor_manager: Arc<ExecutorManager>,
    db: RegistrationDb,
    ssh_access_service: ValidatorAccessService,
    pub jwt_service: Arc<JwtAuthService>,
    validator_discovery: Option<Arc<ValidatorDiscovery>>,
    ssh_session_orchestrator: Option<Arc<SshSessionOrchestrator>>,
    endpoint_registry: Arc<RwLock<HashMap<String, String>>>,
    bittensor_service: Option<Arc<bittensor::Service>>,
}

impl ValidatorCommsServer {
    /// Create a new validator communications server
    pub async fn new(
        config: ValidatorCommsConfig,
        security_config: SecurityConfig,
        executor_manager: Arc<ExecutorManager>,
        db: RegistrationDb,
        ssh_access_service: ValidatorAccessService,
        validator_discovery: Option<Arc<ValidatorDiscovery>>,
    ) -> Result<Self> {
        info!("Initializing validator communications server");

        // Initialize JWT service
        let jwt_service = Arc::new(JwtAuthService::new(
            &security_config.jwt_secret,
            "basilica-miner".to_string(),
            "basilica-miner".to_string(),
            chrono::Duration::seconds(security_config.token_expiration.as_secs() as i64),
        )?);

        Ok(Self {
            config,
            security_config,
            executor_manager,
            db,
            ssh_access_service,
            jwt_service,
            validator_discovery,
            ssh_session_orchestrator: None,
            endpoint_registry: Arc::new(RwLock::new(HashMap::new())),
            bittensor_service: None,
        })
    }

    /// Set SSH session orchestrator
    pub fn with_ssh_session_orchestrator(
        mut self,
        orchestrator: Arc<SshSessionOrchestrator>,
    ) -> Self {
        self.ssh_session_orchestrator = Some(orchestrator);
        self
    }

    /// Set Bittensor service for signing responses
    pub fn with_bittensor_service(mut self, service: Arc<bittensor::Service>) -> Self {
        self.bittensor_service = Some(service);
        self
    }

    /// Start serving gRPC requests
    pub async fn serve(&self, addr: SocketAddr) -> Result<()> {
        info!("Starting validator communications server on {}", addr);

        let miner_discovery_service = MinerDiscoveryService {
            _config: self.config.clone(),
            security_config: self.security_config.clone(),
            executor_manager: self.executor_manager.clone(),
            db: self.db.clone(),
            ssh_access_service: self.ssh_access_service.clone(),
            jwt_service: self.jwt_service.clone(),
            validator_discovery: self.validator_discovery.clone(),
            ssh_session_orchestrator: self.ssh_session_orchestrator.clone(),
            bittensor_service: self.bittensor_service.clone(),
        };

        // Create health reporter
        let (mut health_reporter, health_service) = health_reporter();

        // Set the service as serving
        health_reporter
            .set_serving::<MinerDiscoveryServer<MinerDiscoveryService>>()
            .await;

        let server = Server::builder()
            .add_service(health_service)
            .add_service(MinerDiscoveryServer::new(miner_discovery_service))
            .serve(addr);

        info!("Validator communications server started successfully");

        if let Err(e) = server.await {
            error!("Validator communications server error: {}", e);
            return Err(e.into());
        }

        Ok(())
    }

    /// Start the gRPC server with advertised address configuration
    pub async fn start_server_with_advertised_config(&self, config: &MinerConfig) -> Result<()> {
        let listen_addr: SocketAddr =
            config.server.listen_address().parse().with_context(|| {
                format!("Invalid listen address: {}", config.server.listen_address())
            })?;
        let advertised_endpoint = config.get_advertised_grpc_endpoint();

        info!("Starting miner gRPC server with advertised address support:");
        info!("  Internal binding: {}", listen_addr);
        info!("  Advertised endpoint: {}", advertised_endpoint);
        info!(
            "  Address separation: {}",
            config.server.has_address_separation()
        );

        // Validate configuration before starting
        config
            .validate_advertised_addresses()
            .with_context(|| "Invalid advertised address configuration")?;

        // Create gRPC services
        let miner_discovery_service = MinerDiscoveryService {
            _config: self.config.clone(),
            security_config: self.security_config.clone(),
            executor_manager: self.executor_manager.clone(),
            db: self.db.clone(),
            ssh_access_service: self.ssh_access_service.clone(),
            jwt_service: self.jwt_service.clone(),
            validator_discovery: self.validator_discovery.clone(),
            ssh_session_orchestrator: self.ssh_session_orchestrator.clone(),
            bittensor_service: self.bittensor_service.clone(),
        };

        // Create health reporter
        let (mut health_reporter, health_service) = health_reporter();

        // Set the service as serving
        health_reporter
            .set_serving::<MinerDiscoveryServer<MinerDiscoveryService>>()
            .await;

        // Configure server with TLS if advertised endpoint uses HTTPS
        let mut server_builder = Server::builder();

        if advertised_endpoint.starts_with("https://") {
            info!("Configuring TLS for advertised HTTPS endpoint");
            if let Some(tls_config) = self.load_tls_config(config).await? {
                server_builder = server_builder.tls_config(tls_config)?;
            } else {
                warn!("HTTPS advertised endpoint specified but no TLS configuration found");
            }
        }

        let server = server_builder
            .add_service(health_service)
            .add_service(MinerDiscoveryServer::new(miner_discovery_service))
            .serve(listen_addr);

        // Register advertised endpoint with service discovery
        self.register_advertised_endpoint(&advertised_endpoint)
            .await?;

        // Start background tasks for endpoint validation
        self.start_endpoint_health_monitor(&advertised_endpoint)
            .await?;

        info!("Miner gRPC server successfully started and advertised");
        server.await?;
        Ok(())
    }

    /// Register the advertised endpoint with internal service registry
    async fn register_advertised_endpoint(&self, endpoint: &str) -> Result<()> {
        info!("Registering advertised gRPC endpoint: {}", endpoint);

        // Store advertised endpoint for discovery responses
        let mut endpoint_registry = self.endpoint_registry.write().await;
        endpoint_registry.insert("grpc_endpoint".to_string(), endpoint.to_string());
        endpoint_registry.insert(
            "registration_timestamp".to_string(),
            chrono::Utc::now().to_rfc3339(),
        );

        // Validate endpoint accessibility
        self.validate_endpoint_accessibility(endpoint).await?;

        info!("Successfully registered advertised gRPC endpoint");
        Ok(())
    }

    /// Validate that the advertised endpoint is accessible
    async fn validate_endpoint_accessibility(&self, endpoint: &str) -> Result<()> {
        let url = url::Url::parse(endpoint)
            .with_context(|| format!("Invalid endpoint URL: {endpoint}"))?;

        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("No host in endpoint URL"))?;
        let port = url
            .port()
            .ok_or_else(|| anyhow!("No port in endpoint URL"))?;

        // Test basic connectivity
        match tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect((host, port)),
        )
        .await
        {
            Ok(Ok(_)) => {
                info!("Advertised endpoint {} is accessible", endpoint);
                Ok(())
            }
            Ok(Err(e)) => {
                warn!("Advertised endpoint {} is not accessible: {}", endpoint, e);
                Err(anyhow!("Endpoint not accessible: {}", e))
            }
            Err(_) => {
                warn!(
                    "Timeout testing accessibility of advertised endpoint {}",
                    endpoint
                );
                Err(anyhow!("Endpoint accessibility test timed out"))
            }
        }
    }

    /// Start health monitoring for advertised endpoint
    async fn start_endpoint_health_monitor(&self, endpoint: &str) -> Result<()> {
        let endpoint = endpoint.to_string();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));

            loop {
                interval.tick().await;

                if let Err(e) = Self::check_endpoint_health(&endpoint).await {
                    warn!("Advertised endpoint health check failed: {}", e);
                } else {
                    debug!("Advertised endpoint health check passed: {}", endpoint);
                }
            }
        });

        Ok(())
    }

    /// Check health of advertised endpoint
    async fn check_endpoint_health(endpoint: &str) -> Result<()> {
        let url = url::Url::parse(endpoint)?;
        let host = url.host_str().ok_or_else(|| anyhow!("No host"))?;
        let port = url.port().ok_or_else(|| anyhow!("No port"))?;

        tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::TcpStream::connect((host, port)),
        )
        .await??;

        Ok(())
    }

    /// Load TLS configuration for HTTPS endpoints
    async fn load_tls_config(
        &self,
        _config: &MinerConfig,
    ) -> Result<Option<tonic::transport::ServerTlsConfig>> {
        // TLS configuration loading logic would be implemented here
        // This would typically load certificates from configuration
        Ok(None)
    }
}

/// Simplified gRPC service implementation for miner discovery
#[derive(Clone)]
struct MinerDiscoveryService {
    _config: ValidatorCommsConfig,
    security_config: SecurityConfig,
    executor_manager: Arc<ExecutorManager>,
    db: RegistrationDb,
    ssh_access_service: ValidatorAccessService,
    jwt_service: Arc<JwtAuthService>,
    validator_discovery: Option<Arc<ValidatorDiscovery>>,
    ssh_session_orchestrator: Option<Arc<SshSessionOrchestrator>>,
    bittensor_service: Option<Arc<bittensor::Service>>,
}

#[tonic::async_trait]
impl MinerDiscovery for MinerDiscoveryService {
    /// Authenticate a validator using Bittensor signature
    async fn authenticate_validator(
        &self,
        request: Request<ValidatorAuthRequest>,
    ) -> Result<Response<MinerAuthResponse>, Status> {
        let auth_request = request.into_inner();

        debug!(
            "Received authentication request from validator: {}",
            auth_request.validator_hotkey
        );

        // Verify the signature if enabled
        if self.security_config.verify_signatures {
            // Parse validator hotkey
            let validator_hotkey = Hotkey::new(auth_request.validator_hotkey.clone())
                .map_err(|e| Status::invalid_argument(format!("Invalid hotkey: {e}")))?;

            // Verify signature using bittensor crate
            if let Err(e) = bittensor::utils::verify_bittensor_signature(
                &validator_hotkey,
                &auth_request.signature,
                auth_request.nonce.as_bytes(),
            ) {
                warn!(
                    "Signature verification failed for validator {}: {}",
                    auth_request.validator_hotkey, e
                );
                return Err(Status::unauthenticated("Invalid signature"));
            }
        }

        // Check if validator is in allowlist (if configured)
        if !self.security_config.allowed_validators.is_empty() {
            let validator_hotkey = Hotkey::new(auth_request.validator_hotkey.clone())
                .map_err(|e| Status::invalid_argument(format!("Invalid hotkey: {e}")))?;

            if !self
                .security_config
                .allowed_validators
                .contains(&validator_hotkey)
            {
                warn!(
                    "Validator {} not in allowlist",
                    auth_request.validator_hotkey
                );
                return Err(Status::permission_denied("Validator not authorized"));
            }
        }

        // Record validator interaction
        if let Err(e) = self
            .db
            .update_validator_interaction(&auth_request.validator_hotkey, true)
            .await
        {
            error!("Failed to record validator interaction: {}", e);
        }

        // Parse validator hotkey for JWT
        let validator_hotkey = Hotkey::new(auth_request.validator_hotkey.clone())
            .map_err(|e| Status::invalid_argument(format!("Invalid hotkey: {e}")))?;

        // Generate session ID
        let session_id = format!("session_{}", uuid::Uuid::new_v4());

        // Define validator permissions
        let permissions = vec![
            "executor.list".to_string(),
            "executor.access".to_string(),
            "executor.lease".to_string(),
        ];

        // Extract IP address from request metadata if available
        // Note: In production, you would extract this from the transport layer
        let ip_address = None;

        // Generate JWT token
        let session_token = self
            .jwt_service
            .generate_token(&validator_hotkey, &session_id, permissions, ip_address)
            .await
            .map_err(|e| {
                error!("Failed to generate JWT token: {}", e);
                Status::internal("Failed to generate authentication token")
            })?;

        info!(
            "Successfully authenticated validator: {} with session: {}",
            auth_request.validator_hotkey, session_id
        );

        // Calculate expiration time
        let expires_at = chrono::Utc::now()
            + chrono::Duration::seconds(self.security_config.token_expiration.as_secs() as i64);

        // Get miner's hotkey and create signature
        let (miner_hotkey, miner_signature, response_nonce) =
            if let Some(ref bittensor_service) = self.bittensor_service {
                // Generate response nonce for signature
                let response_nonce = uuid::Uuid::new_v4().to_string();
                let miner_hotkey = bittensor_service.get_account_id().to_string();

                // Create canonical data to sign: validator_hotkey:response_nonce:session_token
                let canonical_data = format!(
                    "MINER_AUTH_RESPONSE:{}:{}:{}",
                    auth_request.validator_hotkey, response_nonce, session_token
                );

                // Sign the canonical data
                let signature = bittensor_service
                    .sign_data(canonical_data.as_bytes())
                    .map_err(|e| {
                        error!("Failed to sign authentication response: {}", e);
                        Status::internal("Failed to sign authentication response")
                    })?;

                (miner_hotkey, signature, response_nonce)
            } else {
                // Bittensor service not available - leave fields empty
                warn!("Bittensor service not available for signing miner response");
                (String::new(), String::new(), String::new())
            };

        let response = MinerAuthResponse {
            authenticated: true,
            session_token,
            expires_at: Some(basilica_protocol::common::Timestamp {
                value: Some(prost_types::Timestamp::from(std::time::SystemTime::from(
                    expires_at,
                ))),
            }),
            error: None,
            miner_hotkey,
            miner_signature,
            response_nonce,
        };

        Ok(Response::new(response))
    }

    /// Request available executor leases from miner (adapted to list executors)
    async fn request_executor_lease(
        &self,
        request: Request<LeaseRequest>,
    ) -> Result<Response<LeaseOfferResponse>, Status> {
        let lease_request = request.into_inner();

        debug!("Received executor lease request");

        // Validate JWT token
        let claims = self
            .jwt_service
            .validate_token(&lease_request.session_token)
            .await
            .map_err(|e| {
                debug!("Token validation failed: {}", e);
                Status::unauthenticated("Invalid or expired session token")
            })?;

        // Check if validator has permission to list executors
        if !claims.permissions.contains(&"executor.list".to_string()) {
            return Err(Status::permission_denied("Insufficient permissions"));
        }

        debug!("Validated lease request from validator: {}", claims.sub);

        // Check if validator discovery is enabled and has assignments for this validator
        let executors = if let Some(ref discovery) = self.validator_discovery {
            // Get assigned executor IDs for this validator
            if let Some(assigned_executor_ids) =
                discovery.get_validator_assignments(&claims.sub).await
            {
                debug!(
                    "Found {} assigned executors for validator {}",
                    assigned_executor_ids.len(),
                    claims.sub
                );

                // Get all available executors
                let all_executors = self
                    .executor_manager
                    .list_available()
                    .await
                    .map_err(|e| Status::internal(format!("Failed to list executors: {e}")))?;

                // Filter to only assigned executors
                all_executors
                    .into_iter()
                    .filter(|exec| assigned_executor_ids.contains(&exec.id))
                    .collect()
            } else {
                // No assignments for this validator
                warn!("No executor assignments found for validator {}", claims.sub);
                Vec::new()
            }
        } else {
            // Validator discovery disabled - return all available executors (original behavior)
            debug!("Validator discovery disabled, returning all available executors");
            self.executor_manager
                .list_available()
                .await
                .map_err(|e| Status::internal(format!("Failed to list executors: {e}")))?
        };

        // Convert to ExecutorConnectionDetails
        let executor_details: Vec<ExecutorConnectionDetails> = executors
            .into_iter()
            .map(|exec| {
                let gpu_spec = create_gpu_spec_from_executor(&exec);
                ExecutorConnectionDetails {
                    executor_id: exec.id,
                    grpc_endpoint: exec.grpc_address,
                    gpu_spec,
                    available_resources: exec.resources.map(|r| {
                        basilica_protocol::common::ResourceLimits {
                            max_cpu_cores: r.cpu_percent as u32,
                            max_memory_mb: r.memory_mb,
                            max_storage_mb: 0, // Not provided in ResourceUsageStats
                            max_containers: 1,
                            max_bandwidth_mbps: 0.0,
                            max_gpus: exec.gpu_count,
                        }
                    }),
                    status: "available".to_string(),
                }
            })
            .collect();

        info!("Returning {} available executors", executor_details.len());

        let response = LeaseOfferResponse {
            available_executors: executor_details,
            error: None,
        };

        Ok(Response::new(response))
    }

    /// Initiate session with specific executor (adapted for SSH access)
    async fn initiate_executor_session(
        &self,
        request: Request<SessionInitRequest>,
    ) -> Result<Response<SessionInitResponse>, Status> {
        let session_request = request.into_inner();

        debug!(
            "Received session init request for executor {}",
            session_request.executor_id
        );

        // Validate JWT token
        let claims = self
            .jwt_service
            .validate_token(&session_request.session_token)
            .await
            .map_err(|e| {
                debug!("Token validation failed: {}", e);
                Status::unauthenticated("Invalid or expired session token")
            })?;

        // Check if validator has permission to access executors
        if !claims.permissions.contains(&"executor.access".to_string()) {
            return Err(Status::permission_denied("Insufficient permissions"));
        }

        // Verify the validator hotkey matches
        if claims.sub != session_request.validator_hotkey {
            return Err(Status::permission_denied("Token validator mismatch"));
        }

        debug!(
            "Validated session init request from validator: {}",
            claims.sub
        );

        // Create SSH session for the validator to access the executor
        let connection_string = match self
            .ssh_access_service
            .provision_validator_access(
                &session_request.validator_hotkey,
                &session_request.executor_id,
                None, // Use default timeout
            )
            .await
        {
            Ok(connection) => connection,
            Err(e) => {
                error!("Failed to provision SSH access: {}", e);
                return Err(Status::internal(format!(
                    "Failed to create SSH access: {e}"
                )));
            }
        };

        let session_id = format!("session_{}", Uuid::new_v4().simple());

        // Record the session initiation
        if let Err(e) = self
            .db
            .record_validator_interaction(
                &session_request.validator_hotkey,
                "session_init",
                true,
                Some(
                    serde_json::json!({
                        "executor_id": session_request.executor_id,
                        "session_type": session_request.session_type,
                    })
                    .to_string(),
                ),
            )
            .await
        {
            error!("Failed to record session initiation: {}", e);
        }

        let response = SessionInitResponse {
            success: true,
            session_id,
            access_credentials: connection_string,
            error: None,
        };

        Ok(Response::new(response))
    }

    /// Initiate SSH session with public key
    async fn initiate_ssh_session(
        &self,
        request: Request<InitiateSshSessionRequest>,
    ) -> Result<Response<InitiateSshSessionResponse>, Status> {
        let req = request.into_inner();

        debug!(
            "Received SSH session request from validator {} for executor {}",
            req.validator_hotkey, req.executor_id
        );

        // Check if SSH session orchestrator is available
        let orchestrator = self
            .ssh_session_orchestrator
            .as_ref()
            .ok_or_else(|| Status::internal("SSH session management not configured"))?;

        // Use orchestrator to create session
        match orchestrator.create_session(req).await {
            Ok(response) => {
                info!("SSH session created successfully: {}", response.session_id);
                Ok(Response::new(response))
            }
            Err(e) => {
                error!("Failed to create SSH session: {}", e);
                Err(Status::internal(format!(
                    "Failed to create SSH session: {e}"
                )))
            }
        }
    }

    /// Close SSH session
    async fn close_ssh_session(
        &self,
        request: Request<CloseSshSessionRequest>,
    ) -> Result<Response<CloseSshSessionResponse>, Status> {
        let req = request.into_inner();

        debug!(
            "Received close SSH session request from validator {} for session {}",
            req.validator_hotkey, req.session_id
        );

        // Check if SSH session orchestrator is available
        let orchestrator = self
            .ssh_session_orchestrator
            .as_ref()
            .ok_or_else(|| Status::internal("SSH session management not configured"))?;

        // Use orchestrator to close session
        match orchestrator.close_session(req).await {
            Ok(response) => {
                info!("SSH session closed successfully");
                Ok(Response::new(response))
            }
            Err(e) => {
                error!("Failed to close SSH session: {}", e);
                Err(Status::internal(format!(
                    "Failed to close SSH session: {e}"
                )))
            }
        }
    }

    /// List SSH sessions
    async fn list_ssh_sessions(
        &self,
        request: Request<ListSshSessionsRequest>,
    ) -> Result<Response<ListSshSessionsResponse>, Status> {
        let req = request.into_inner();

        debug!(
            "Received list SSH sessions request from validator {}",
            req.validator_hotkey
        );

        // Check if SSH session orchestrator is available
        let orchestrator = self
            .ssh_session_orchestrator
            .as_ref()
            .ok_or_else(|| Status::internal("SSH session management not configured"))?;

        // Use orchestrator to list sessions
        match orchestrator.list_sessions(req).await {
            Ok(response) => {
                info!("Listed {} SSH sessions", response.sessions.len());
                Ok(Response::new(response))
            }
            Err(e) => {
                error!("Failed to list SSH sessions: {}", e);
                Err(Status::internal(format!(
                    "Failed to list SSH sessions: {e}"
                )))
            }
        }
    }
}

/// Create GPU spec from available executor information
fn create_gpu_spec_from_executor(
    exec: &AvailableExecutor,
) -> Option<basilica_protocol::common::GpuSpec> {
    if exec.gpu_count == 0 {
        return None;
    }

    // Use available runtime information from ResourceUsageStats if present
    if let Some(ref resources) = exec.resources {
        // Take first GPU metrics as representative (could be extended to handle multiple GPUs)
        let gpu_utilization = resources.gpu_utilization.first().copied().unwrap_or(0.0);
        let gpu_memory_mb = resources.gpu_memory_mb.first().copied().unwrap_or(0);
        let memory_utilization = if gpu_memory_mb > 0 {
            (gpu_memory_mb as f64 / (gpu_memory_mb as f64 * 1.2)).min(100.0)
        } else {
            0.0
        };

        Some(basilica_protocol::common::GpuSpec {
            model: format!("GPU-{}", &exec.id[..8.min(exec.id.len())]), // Placeholder based on executor ID
            memory_mb: gpu_memory_mb,
            uuid: format!("gpu-{}-{}", exec.id, 0), // Generate deterministic UUID
            driver_version: "unknown".to_string(),
            cuda_version: "unknown".to_string(),
            utilization_percent: gpu_utilization,
            memory_utilization_percent: memory_utilization,
            temperature_celsius: 0.0, // Not available from current data
            power_watts: 0.0,         // Not available from current data
            core_clock_mhz: 0,
            memory_clock_mhz: 0,
            compute_capability: "unknown".to_string(),
        })
    } else {
        // Fallback for executors without resource stats
        Some(basilica_protocol::common::GpuSpec {
            model: format!("GPU-{}", &exec.id[..8.min(exec.id.len())]),
            memory_mb: 0,
            uuid: format!("gpu-{}-{}", exec.id, 0),
            driver_version: "unknown".to_string(),
            cuda_version: "unknown".to_string(),
            utilization_percent: 0.0,
            memory_utilization_percent: 0.0,
            temperature_celsius: 0.0,
            power_watts: 0.0,
            core_clock_mhz: 0,
            memory_clock_mhz: 0,
            compute_capability: "unknown".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use basilica_common::{ssh::DefaultSshService, DatabaseConfig};

    use super::*;
    use crate::config::ExecutorConfig;

    #[tokio::test]
    async fn test_validator_auth_with_production_verification() {
        let config = ValidatorCommsConfig::default();
        let security_config = SecurityConfig {
            verify_signatures: true,
            ..Default::default()
        };

        let miner_config = crate::config::MinerConfig {
            executor_management: crate::config::ExecutorManagementConfig {
                executors: vec![ExecutorConfig {
                    grpc_address: "127.0.0.1:50051".to_string(),
                    host: "127.0.0.1".to_string(),
                    port: 50051,
                    ssh_port: 22,
                    ssh_username: "testuser".to_string(),
                    enabled: true,
                    metadata: None,
                }],
                ..Default::default()
            },
            database: basilica_common::config::DatabaseConfig {
                url: "sqlite::memory:".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };

        let db = RegistrationDb::new(&miner_config.database).await.unwrap();
        let executor_manager = Arc::new(
            ExecutorManager::new(&miner_config, db.clone())
                .await
                .unwrap(),
        );

        // Create SSH access service for testing
        let ssh_config = crate::ssh::MinerSshConfig {
            key_directory: std::path::PathBuf::from("/tmp/test_ssh_keys"),
            ..crate::ssh::MinerSshConfig::default()
        };
        let ssh_service = std::sync::Arc::new(
            basilica_common::ssh::manager::DefaultSshService::new(ssh_config.clone()).unwrap(),
        );
        let ssh_access_service = crate::ssh::ValidatorAccessService::new(
            ssh_config,
            ssh_service,
            executor_manager.clone(),
            db.clone(),
        )
        .await
        .unwrap();

        // Create JWT service for testing
        let jwt_service = Arc::new(
            JwtAuthService::new(
                "test_secret_key_that_is_long_enough_for_security",
                "test-miner".to_string(),
                "test-miner".to_string(),
                chrono::Duration::hours(1),
            )
            .unwrap(),
        );

        let service = MinerDiscoveryService {
            _config: config,
            security_config,
            executor_manager,
            db,
            ssh_access_service,
            jwt_service,
            validator_discovery: None,
            ssh_session_orchestrator: None,
            bittensor_service: None,
        };

        // Test with production-level verification enabled
        let test_hotkey = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
        let nonce = "test-nonce";

        // Use a signature that should fail verification (testing the verification path)
        let invalid_signature = "deadbeef".repeat(16); // 64-byte hex string but invalid signature

        let request = ValidatorAuthRequest {
            validator_hotkey: test_hotkey.to_string(),
            signature: invalid_signature,
            nonce: nonce.to_string(),
            timestamp: None,
        };

        // This should fail authentication due to invalid signature
        let result = service.authenticate_validator(Request::new(request)).await;

        // Verify that the authentication fails with proper signature verification
        assert!(
            result.is_err(),
            "Authentication should fail with invalid signature"
        );
        if let Err(status) = result {
            assert_eq!(status.code(), tonic::Code::Unauthenticated);
            assert!(status.message().contains("Invalid signature"));
        }
    }

    #[tokio::test]
    async fn test_miner_signature_fields_populated_without_bittensor_service() {
        // This test verifies that when bittensor service is not available,
        // the miner signature fields are empty but the authentication still succeeds
        let config = ValidatorCommsConfig::default();
        let security_config = SecurityConfig {
            verify_signatures: false, // Don't verify validator sig for this test
            ..Default::default()
        };

        let miner_config = crate::config::MinerConfig {
            executor_management: crate::config::ExecutorManagementConfig {
                executors: vec![ExecutorConfig {
                    grpc_address: "127.0.0.1:50051".to_string(),
                    host: "127.0.0.1".to_string(),
                    port: 50051,
                    ssh_port: 22,
                    ssh_username: "testuser".to_string(),
                    enabled: true,
                    metadata: None,
                }],
                ..Default::default()
            },
            database: DatabaseConfig {
                url: "sqlite::memory:".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };

        let db = RegistrationDb::new(&miner_config.database).await.unwrap();
        let executor_manager = Arc::new(
            ExecutorManager::new(&miner_config, db.clone())
                .await
                .unwrap(),
        );

        // Create SSH access service for testing
        let ssh_config = crate::ssh::MinerSshConfig {
            key_directory: std::path::PathBuf::from("/tmp/test_ssh_keys"),
            ..crate::ssh::MinerSshConfig::default()
        };
        let ssh_service = std::sync::Arc::new(DefaultSshService::new(ssh_config.clone()).unwrap());
        let ssh_access_service = crate::ssh::ValidatorAccessService::new(
            ssh_config,
            ssh_service,
            executor_manager.clone(),
            db.clone(),
        )
        .await
        .unwrap();

        // Create JWT service for testing
        let jwt_service = Arc::new(
            JwtAuthService::new(
                "test_secret_key_that_is_long_enough_for_security",
                "test-miner".to_string(),
                "test-miner".to_string(),
                chrono::Duration::hours(1),
            )
            .unwrap(),
        );

        // Create service WITHOUT bittensor service
        let service = MinerDiscoveryService {
            _config: config,
            security_config,
            executor_manager,
            db,
            ssh_access_service,
            jwt_service,
            validator_discovery: None,
            ssh_session_orchestrator: None,
            bittensor_service: None, // No bittensor service
        };

        // Create authentication request
        let validator_hotkey = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
        let nonce = "test-nonce-123";

        let request = ValidatorAuthRequest {
            validator_hotkey: validator_hotkey.to_string(),
            signature: "validator_signature".to_string(), // Dummy sig since we disabled verification
            nonce: nonce.to_string(),
            timestamp: None,
        };

        // Call authenticate_validator
        let response = service.authenticate_validator(Request::new(request)).await;

        // Should succeed
        assert!(response.is_ok(), "Authentication should succeed");

        let auth_response = response.unwrap().into_inner();
        assert!(auth_response.authenticated);

        // Verify miner signature fields are empty when no bittensor service
        assert!(
            auth_response.miner_hotkey.is_empty(),
            "Miner hotkey should be empty without bittensor service"
        );
        assert!(
            auth_response.miner_signature.is_empty(),
            "Miner signature should be empty without bittensor service"
        );
        assert!(
            auth_response.response_nonce.is_empty(),
            "Response nonce should be empty without bittensor service"
        );
    }

    #[tokio::test]
    async fn test_validator_auth_signature_verification_path() {
        let config = ValidatorCommsConfig::default();
        let security_config = SecurityConfig {
            verify_signatures: true,
            ..Default::default()
        };

        let miner_config = crate::config::MinerConfig {
            executor_management: crate::config::ExecutorManagementConfig {
                executors: vec![ExecutorConfig {
                    grpc_address: "127.0.0.1:50051".to_string(),
                    host: "127.0.0.1".to_string(),
                    port: 50051,
                    ssh_port: 22,
                    ssh_username: "testuser".to_string(),
                    enabled: true,
                    metadata: None,
                }],
                ..Default::default()
            },
            database: basilica_common::config::DatabaseConfig {
                url: "sqlite::memory:".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };

        let db = RegistrationDb::new(&miner_config.database).await.unwrap();
        let executor_manager = Arc::new(
            ExecutorManager::new(&miner_config, db.clone())
                .await
                .unwrap(),
        );

        // Create SSH access service for testing
        let ssh_config = crate::ssh::MinerSshConfig {
            key_directory: std::path::PathBuf::from("/tmp/test_ssh_keys"),
            ..crate::ssh::MinerSshConfig::default()
        };
        let ssh_service = std::sync::Arc::new(
            basilica_common::ssh::manager::DefaultSshService::new(ssh_config.clone()).unwrap(),
        );
        let ssh_access_service = crate::ssh::ValidatorAccessService::new(
            ssh_config,
            ssh_service,
            executor_manager.clone(),
            db.clone(),
        )
        .await
        .unwrap();

        // Create JWT service for testing
        let jwt_service = Arc::new(
            JwtAuthService::new(
                "test_secret_key_that_is_long_enough_for_security",
                "test-miner".to_string(),
                "test-miner".to_string(),
                chrono::Duration::hours(1),
            )
            .unwrap(),
        );

        let service = MinerDiscoveryService {
            _config: config,
            security_config,
            executor_manager,
            db,
            ssh_access_service,
            jwt_service,
            validator_discovery: None,
            ssh_session_orchestrator: None,
            bittensor_service: None,
        };

        // Test various invalid signature scenarios to ensure production verification works

        // Test 1: Empty signature
        let request = ValidatorAuthRequest {
            validator_hotkey: "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".to_string(),
            signature: "".to_string(),
            nonce: "test-nonce".to_string(),
            timestamp: None,
        };

        let result = service.authenticate_validator(Request::new(request)).await;
        assert!(result.is_err(), "Empty signature should fail");

        // Test 2: Invalid hex signature
        let request = ValidatorAuthRequest {
            validator_hotkey: "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".to_string(),
            signature: "invalid_hex_!@#$".to_string(),
            nonce: "test-nonce".to_string(),
            timestamp: None,
        };

        let result = service.authenticate_validator(Request::new(request)).await;
        assert!(result.is_err(), "Invalid hex signature should fail");

        // Test 3: Wrong length signature
        let request = ValidatorAuthRequest {
            validator_hotkey: "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".to_string(),
            signature: "deadbeef".to_string(), // Too short
            nonce: "test-nonce".to_string(),
            timestamp: None,
        };

        let result = service.authenticate_validator(Request::new(request)).await;
        assert!(result.is_err(), "Wrong length signature should fail");
    }
}
