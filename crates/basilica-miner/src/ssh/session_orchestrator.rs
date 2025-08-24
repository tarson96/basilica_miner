//! SSH Session Orchestrator for Miner
//!
//! Manages SSH sessions between validators and executors, handling session lifecycle,
//! key management, and cleanup.

use anyhow::{Context, Result};
use basilica_protocol::miner_discovery::{
    CloseSshSessionRequest, CloseSshSessionResponse, InitiateSshSessionRequest,
    InitiateSshSessionResponse, ListSshSessionsRequest, ListSshSessionsResponse,
    SshSession as ProtoSshSession, SshSessionStatus,
};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, error, info};
use uuid::Uuid;

use crate::executor_auth::ExecutorAuthService;
use crate::executors::{
    ExecutorConnectionManager, ExecutorGrpcClient, ExecutorGrpcConfig, ExecutorInfo,
};

/// SSH Session information
#[derive(Debug, Clone)]
pub struct SshSession {
    pub session_id: String,
    pub validator_hotkey: String,
    pub executor_id: String,
    pub _validator_public_key: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub status: SshSessionStatus,
    pub _purpose: String,
    pub _metadata: Option<String>,
}

/// Rate limit information per validator
#[derive(Debug, Clone)]
struct RateLimitInfo {
    session_count: usize,
    window_start: DateTime<Utc>,
}

/// SSH Session Orchestrator
pub struct SshSessionOrchestrator {
    /// Active sessions indexed by session ID
    sessions: Arc<RwLock<HashMap<String, SshSession>>>,
    /// Sessions indexed by validator hotkey for rate limiting
    sessions_by_validator: Arc<RwLock<HashMap<String, Vec<String>>>>,
    /// Executor connection manager
    executor_manager: Arc<ExecutorConnectionManager>,
    /// gRPC client for executor communication
    executor_grpc_client: ExecutorGrpcClient,
    /// Rate limiting info
    rate_limits: Arc<RwLock<HashMap<String, RateLimitInfo>>>,
    /// Configuration
    config: SshSessionConfig,
}

/// Configuration for SSH session management
#[derive(Debug, Clone)]
pub struct SshSessionConfig {
    /// Maximum concurrent sessions per validator
    pub max_sessions_per_validator: usize,
    /// Session rate limit (sessions per hour)
    pub session_rate_limit: usize,
    /// Session cleanup interval
    pub cleanup_interval: Duration,
    /// Maximum session duration
    pub max_session_duration: Duration,
    /// Enable audit logging
    pub enable_audit_log: bool,
}

impl Default for SshSessionConfig {
    fn default() -> Self {
        Self {
            max_sessions_per_validator: 5,
            session_rate_limit: 20,
            cleanup_interval: Duration::from_secs(60),
            max_session_duration: Duration::from_secs(3600),
            enable_audit_log: true,
        }
    }
}

impl SshSessionOrchestrator {
    /// Create a new SSH session orchestrator
    pub fn new(executor_manager: Arc<ExecutorConnectionManager>, config: SshSessionConfig) -> Self {
        let executor_grpc_client = ExecutorGrpcClient::new(ExecutorGrpcConfig::default());

        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            sessions_by_validator: Arc::new(RwLock::new(HashMap::new())),
            executor_manager,
            executor_grpc_client,
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Create a new SSH session orchestrator with authentication
    pub fn new_with_auth(
        executor_manager: Arc<ExecutorConnectionManager>,
        config: SshSessionConfig,
        auth_service: Arc<ExecutorAuthService>,
    ) -> Self {
        let executor_grpc_client =
            ExecutorGrpcClient::new_with_auth(ExecutorGrpcConfig::default(), auth_service);

        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            sessions_by_validator: Arc::new(RwLock::new(HashMap::new())),
            executor_manager,
            executor_grpc_client,
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Create a new SSH session
    pub async fn create_session(
        &self,
        request: InitiateSshSessionRequest,
    ) -> Result<InitiateSshSessionResponse> {
        info!(
            "Creating SSH session for validator {} to executor {}",
            request.validator_hotkey, request.executor_id
        );

        // DEBUG: Log the SSH public key received from validator
        debug!(
            "SSH public key received from validator: '{}' (length: {} chars)",
            request.validator_public_key,
            request.validator_public_key.len()
        );

        // Validate request
        self.validate_session_request(&request)?;

        // Check rate limits
        self.check_rate_limits(&request.validator_hotkey).await?;

        // Check concurrent session limits
        self.check_concurrent_limits(&request.validator_hotkey)
            .await?;

        // Generate session ID
        let session_id = format!("ssh-session-{}", Uuid::new_v4());

        // Get executor information (without establishing SSH connection)
        let executor_info = self
            .executor_manager
            .get_executor_info(&request.executor_id)
            .await
            .context("Failed to get executor information")?;

        // Add validator's public key to executor via gRPC and get actual SSH username
        debug!(
            "Forwarding SSH public key to executor {} via gRPC: '{}'",
            executor_info.id, request.validator_public_key
        );

        // Check if this is a rental session and adjust permissions accordingly
        let permissions = if request.rental_mode {
            if request.rental_id.is_empty() {
                return Err(anyhow::anyhow!(
                    "Rental ID is required when rental_mode is true"
                ));
            }
            info!("Creating rental session for rental {}", request.rental_id);
            "rental"
        } else {
            "validation"
        };

        let actual_ssh_username = self
            .add_validator_key_to_executor(
                &executor_info,
                &request.validator_hotkey,
                &request.validator_public_key,
                request.session_duration_secs as u64,
                permissions,
                request.rental_mode,
            )
            .await?;

        // Create session record
        let now = Utc::now();
        let expires_at = now
            + chrono::Duration::from_std(Duration::from_secs(request.session_duration_secs as u64))
                .unwrap();

        let session = SshSession {
            session_id: session_id.clone(),
            validator_hotkey: request.validator_hotkey.clone(),
            executor_id: request.executor_id.clone(),
            _validator_public_key: request.validator_public_key.clone(),
            created_at: now,
            expires_at,
            status: SshSessionStatus::Active,
            _purpose: request.purpose.clone(),
            _metadata: Some(request.session_metadata.clone()),
        };

        // Store session
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session_id.clone(), session.clone());
        }

        // Update validator's session list
        {
            let mut sessions_by_validator = self.sessions_by_validator.write().await;
            sessions_by_validator
                .entry(request.validator_hotkey.clone())
                .or_insert_with(Vec::new)
                .push(session_id.clone());
        }

        // Log audit event
        if self.config.enable_audit_log {
            self.log_audit_event(
                &session_id,
                &request.validator_hotkey,
                &request.executor_id,
                "session_created",
                true,
                None,
            )
            .await;
        }

        // Schedule cleanup
        let orchestrator = self.clone();
        let session_id_clone = session_id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(request.session_duration_secs as u64)).await;
            if let Err(e) = orchestrator
                .cleanup_expired_session(&session_id_clone)
                .await
            {
                error!(
                    "Failed to cleanup expired session {}: {}",
                    session_id_clone, e
                );
            }
        });

        Ok(InitiateSshSessionResponse {
            session_id,
            access_credentials: format!(
                "{}@{}:{}",
                actual_ssh_username, executor_info.host, executor_info.ssh_port
            ),
            expires_at: expires_at.timestamp(),
            executor_id: request.executor_id,
            status: SshSessionStatus::Active as i32,
        })
    }

    /// Close an SSH session
    pub async fn close_session(
        &self,
        request: CloseSshSessionRequest,
    ) -> Result<CloseSshSessionResponse> {
        info!("Closing SSH session {}", request.session_id);

        // Get session
        let session = {
            let sessions = self.sessions.read().await;
            sessions.get(&request.session_id).cloned()
        };

        let session =
            session.ok_or_else(|| anyhow::anyhow!("Session not found: {}", request.session_id))?;

        // Verify ownership
        if session.validator_hotkey != request.validator_hotkey {
            return Err(anyhow::anyhow!("Unauthorized: not session owner"));
        }

        // Remove key from executor
        self.remove_validator_key_from_executor(&session).await?;

        // Update session status
        {
            let mut sessions = self.sessions.write().await;
            if let Some(session) = sessions.get_mut(&request.session_id) {
                session.status = SshSessionStatus::Expired;
            }
        }

        // Log audit event
        if self.config.enable_audit_log {
            self.log_audit_event(
                &request.session_id,
                &request.validator_hotkey,
                &session.executor_id,
                "session_closed",
                true,
                Some(&request.reason),
            )
            .await;
        }

        Ok(CloseSshSessionResponse {
            success: true,
            message: "Session closed successfully".to_string(),
        })
    }

    /// List SSH sessions for a validator
    pub async fn list_sessions(
        &self,
        request: ListSshSessionsRequest,
    ) -> Result<ListSshSessionsResponse> {
        let sessions = self.sessions.read().await;

        let validator_sessions: Vec<ProtoSshSession> = sessions
            .values()
            .filter(|s| {
                s.validator_hotkey == request.validator_hotkey
                    && (request.include_expired || s.status == SshSessionStatus::Active)
            })
            .map(|s| ProtoSshSession {
                session_id: s.session_id.clone(),
                executor_id: s.executor_id.clone(),
                validator_hotkey: s.validator_hotkey.clone(),
                created_at: s.created_at.timestamp(),
                expires_at: s.expires_at.timestamp(),
                status: s.status as i32,
            })
            .collect();

        Ok(ListSshSessionsResponse {
            sessions: validator_sessions,
        })
    }

    /// Validate session request
    fn validate_session_request(&self, request: &InitiateSshSessionRequest) -> Result<()> {
        // Validate public key format
        if request.validator_public_key.is_empty() {
            return Err(anyhow::anyhow!("Validator public key is required"));
        }

        if !request.validator_public_key.starts_with("ssh-") {
            return Err(anyhow::anyhow!("Invalid SSH public key format"));
        }

        // Validate session duration
        let duration = Duration::from_secs(request.session_duration_secs as u64);
        if duration > self.config.max_session_duration {
            return Err(anyhow::anyhow!(
                "Session duration exceeds maximum allowed: {} > {}",
                duration.as_secs(),
                self.config.max_session_duration.as_secs()
            ));
        }

        if duration.as_secs() == 0 {
            return Err(anyhow::anyhow!("Session duration must be greater than 0"));
        }

        Ok(())
    }

    /// Check rate limits for validator
    async fn check_rate_limits(&self, validator_hotkey: &str) -> Result<()> {
        let mut rate_limits = self.rate_limits.write().await;
        let now = Utc::now();
        let window = chrono::Duration::hours(1);

        let limit_info = rate_limits
            .entry(validator_hotkey.to_string())
            .or_insert_with(|| RateLimitInfo {
                session_count: 0,
                window_start: now,
            });

        // Reset window if expired
        if now > limit_info.window_start + window {
            limit_info.session_count = 0;
            limit_info.window_start = now;
        }

        // Check rate limit
        if limit_info.session_count >= self.config.session_rate_limit {
            return Err(anyhow::anyhow!(
                "Rate limit exceeded: {} sessions per hour",
                self.config.session_rate_limit
            ));
        }

        limit_info.session_count += 1;
        Ok(())
    }

    /// Check concurrent session limits
    async fn check_concurrent_limits(&self, validator_hotkey: &str) -> Result<()> {
        let sessions = self.sessions.read().await;
        let active_count = sessions
            .values()
            .filter(|s| {
                s.validator_hotkey == validator_hotkey && s.status == SshSessionStatus::Active
            })
            .count();

        if active_count >= self.config.max_sessions_per_validator {
            return Err(anyhow::anyhow!(
                "Concurrent session limit exceeded: {} active sessions",
                self.config.max_sessions_per_validator
            ));
        }

        Ok(())
    }

    /// Add validator key to executor via gRPC
    async fn add_validator_key_to_executor(
        &self,
        executor_info: &ExecutorInfo,
        validator_hotkey: &str,
        public_key: &str,
        duration_secs: u64,
        permissions: &str,
        rental_mode: bool,
    ) -> Result<String> {
        // Get the executor's gRPC endpoint
        let grpc_endpoint = executor_info
            .grpc_endpoint
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Executor has no gRPC endpoint configured"))?;

        // Use gRPC to provision validator access on executor
        debug!(
            "Calling provision_validator_access for validator {} on executor via gRPC endpoint {}: public_key='{}', permissions='{}'",
            validator_hotkey, grpc_endpoint, public_key, permissions
        );

        // For rental mode, we need to pass additional metadata to the executor
        let metadata = if rental_mode {
            Some(
                serde_json::json!({
                    "permissions": permissions,
                    "rental_mode": true,
                    "docker_access": true
                })
                .to_string(),
            )
        } else {
            None
        };

        let response = self
            .executor_grpc_client
            .provision_validator_access(
                grpc_endpoint,
                validator_hotkey,
                public_key,
                duration_secs,
                metadata,
            )
            .await
            .context("Failed to provision validator access via gRPC")?;

        if !response.success {
            let error_msg = response
                .error
                .map(|e| e.message)
                .unwrap_or_else(|| "Unknown error".to_string());
            return Err(anyhow::anyhow!(
                "Failed to add validator key: {}",
                error_msg
            ));
        }

        // Parse SSH username from the credentials JSON response
        let actual_ssh_username = if let Ok(credentials_json) =
            serde_json::from_str::<serde_json::Value>(&response.credentials)
        {
            credentials_json["ssh_username"]
                .as_str()
                .map(|s| s.to_string())
                .unwrap_or_else(|| executor_info.ssh_username.clone())
        } else {
            // Fallback to config if JSON parsing fails
            executor_info.ssh_username.clone()
        };

        info!(
            "Added validator key for {} to executor {} via gRPC, SSH username: {}",
            validator_hotkey, executor_info.id, actual_ssh_username
        );
        Ok(actual_ssh_username)
    }

    /// Remove validator key from executor via gRPC
    async fn remove_validator_key_from_executor(&self, session: &SshSession) -> Result<()> {
        let executor_info = self
            .executor_manager
            .get_executor_info(&session.executor_id)
            .await
            .context("Failed to get executor information")?;

        // Get the executor's gRPC endpoint
        let grpc_endpoint = executor_info
            .grpc_endpoint
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Executor has no gRPC endpoint configured"))?;

        // Use gRPC to revoke validator access by setting duration to 0
        let response = self
            .executor_grpc_client
            .provision_validator_access(
                grpc_endpoint,
                &session.validator_hotkey,
                &session._validator_public_key,
                0,    // Duration of 0 means revoke access
                None, // No metadata needed for revocation
            )
            .await
            .context("Failed to revoke validator access via gRPC")?;

        if !response.success {
            let error_msg = response
                .error
                .map(|e| e.message)
                .unwrap_or_else(|| "Unknown error".to_string());
            return Err(anyhow::anyhow!(
                "Failed to remove validator key: {}",
                error_msg
            ));
        }

        info!(
            "Removed validator key for session {} from executor {} via gRPC",
            session.session_id, executor_info.id
        );
        Ok(())
    }

    /// Cleanup expired session
    async fn cleanup_expired_session(&self, session_id: &str) -> Result<()> {
        let session = {
            let sessions = self.sessions.read().await;
            sessions.get(session_id).cloned()
        };

        if let Some(session) = session {
            if session.status == SshSessionStatus::Active {
                info!("Cleaning up expired session: {}", session_id);

                if let Err(e) = self.remove_validator_key_from_executor(&session).await {
                    error!("Failed to remove key for session {}: {}", session_id, e);
                }

                let mut sessions = self.sessions.write().await;
                if let Some(s) = sessions.get_mut(session_id) {
                    s.status = SshSessionStatus::Expired;
                }
            }
        }

        Ok(())
    }

    /// Run periodic cleanup task
    pub async fn run_cleanup_task(&self) {
        let mut interval = tokio::time::interval(self.config.cleanup_interval);

        loop {
            interval.tick().await;

            let now = Utc::now();
            let expired_sessions: Vec<SshSession> = {
                let sessions = self.sessions.read().await;
                sessions
                    .values()
                    .filter(|s| s.expires_at < now && s.status == SshSessionStatus::Active)
                    .cloned()
                    .collect()
            };

            for session in expired_sessions {
                if let Err(e) = self.cleanup_expired_session(&session.session_id).await {
                    error!("Failed to cleanup session {}: {}", session.session_id, e);
                }
            }

            // Clean up old expired sessions from memory
            let cutoff = now - chrono::Duration::hours(24);
            let mut sessions = self.sessions.write().await;
            sessions.retain(|_, s| s.status == SshSessionStatus::Active || s.expires_at > cutoff);
        }
    }

    /// Log audit event
    async fn log_audit_event(
        &self,
        session_id: &str,
        validator_hotkey: &str,
        executor_id: &str,
        action: &str,
        success: bool,
        details: Option<&str>,
    ) {
        info!(
            target: "ssh_audit",
            session_id = %session_id,
            validator_hotkey = %validator_hotkey,
            executor_id = %executor_id,
            action = %action,
            success = %success,
            details = ?details,
            timestamp = %Utc::now().to_rfc3339(),
            "SSH session audit event"
        );
    }
}

// Clone implementation for spawning tasks
impl Clone for SshSessionOrchestrator {
    fn clone(&self) -> Self {
        Self {
            sessions: self.sessions.clone(),
            sessions_by_validator: self.sessions_by_validator.clone(),
            executor_manager: self.executor_manager.clone(),
            executor_grpc_client: self.executor_grpc_client.clone(),
            rate_limits: self.rate_limits.clone(),
            config: self.config.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_session_validation() {
        let config = SshSessionConfig::default();
        let executor_manager = Arc::new(ExecutorConnectionManager::new_test());
        let orchestrator = SshSessionOrchestrator::new(executor_manager, config);

        // Test invalid public key
        let request = InitiateSshSessionRequest {
            validator_hotkey: "test-validator".to_string(),
            executor_id: "test-executor".to_string(),
            purpose: "testing".to_string(),
            validator_public_key: "invalid-key".to_string(),
            session_duration_secs: 300,
            session_metadata: "{}".to_string(),
            rental_mode: false,
            rental_id: String::new(),
        };

        let result = orchestrator.validate_session_request(&request);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid SSH public key format"));

        // Test valid request
        let valid_request = InitiateSshSessionRequest {
            validator_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID...".to_string(),
            ..request
        };

        let result = orchestrator.validate_session_request(&valid_request);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let config = SshSessionConfig {
            session_rate_limit: 2,
            ..Default::default()
        };

        let executor_manager = Arc::new(ExecutorConnectionManager::new_test());
        let orchestrator = SshSessionOrchestrator::new(executor_manager, config);

        let validator = "test-validator";

        // First two should succeed
        for _ in 0..2 {
            let result = orchestrator.check_rate_limits(validator).await;
            assert!(result.is_ok());
        }

        // Third should fail
        let result = orchestrator.check_rate_limits(validator).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Rate limit exceeded"));
    }

    #[tokio::test]
    async fn test_concurrent_limits() {
        let config = SshSessionConfig {
            max_sessions_per_validator: 2,
            ..Default::default()
        };

        let executor_manager = Arc::new(ExecutorConnectionManager::new_test());
        let orchestrator = SshSessionOrchestrator::new(executor_manager, config);

        let validator = "test-validator";

        // Add two active sessions
        {
            let mut sessions = orchestrator.sessions.write().await;
            for i in 0..2 {
                let session = SshSession {
                    session_id: format!("session-{i}"),
                    validator_hotkey: validator.to_string(),
                    executor_id: format!("executor-{i}"),
                    _validator_public_key: "ssh-ed25519 TEST".to_string(),
                    created_at: Utc::now(),
                    expires_at: Utc::now() + chrono::Duration::hours(1),
                    status: SshSessionStatus::Active,
                    _purpose: "test".to_string(),
                    _metadata: None,
                };
                sessions.insert(session.session_id.clone(), session);
            }
        }

        // Check should fail
        let result = orchestrator.check_concurrent_limits(validator).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Concurrent session limit exceeded"));
    }
}
