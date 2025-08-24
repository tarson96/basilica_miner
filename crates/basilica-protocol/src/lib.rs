//! # Protocol
//!
//! gRPC protocol definitions and message types for Basilca communication.
//! This crate provides typed interfaces for all inter-service communication.
//!
//! ## Services
//!
//! ### ExecutorControl
//! Service for direct Validator ↔ Executor communication. Allows validators to:
//! - Provision validator access
//! - Execute system profiling
//! - Run computational challenges
//! - Manage containers
//! - Stream logs
//!
//! ### MinerDiscovery  
//! Service for Validator ↔ Miner coordination. Allows validators to:
//! - Authenticate with miners using Bittensor signatures
//! - Request executor leases with resource requirements
//! - Initiate executor sessions
//!
//! ### ValidatorExternalApi
//! Service for external → Validator communication. Allows external services to:
//! - List available capacity
//! - Rent GPU capacity with container specifications
//! - Manage rentals
//! - Stream logs
//!
//! ## Usage
//!
//! The protocol crate provides generated gRPC service definitions and message types.
//! See the generated code in `src/gen/` for the exact structure of all types.
//!
//! ### Client Example
//!
//! ```rust,ignore
//! use basilica_protocol::executor_control::executor_control_client::ExecutorControlClient;
//! use basilica_protocol::executor_control::HealthCheckRequest;
//! use tonic::Request;
//!
//! let mut client = ExecutorControlClient::connect("http://[::1]:50051").await?;
//! let request = Request::new(HealthCheckRequest {
//!     requester: "validator".to_string(),
//!     check_type: "full".to_string(),
//! });
//! let response = client.health_check(request).await?;
//! ```
//!
//! ### Server Example
//!
//! ```rust,ignore
//! use basilica_protocol::executor_control::executor_control_server::{ExecutorControl, ExecutorControlServer};
//! use tonic::{transport::Server, Request, Response, Status};
//!
//! #[tonic::async_trait]
//! impl ExecutorControl for MyService {
//!     // Implement required methods
//! }
//!
//! Server::builder()
//!     .add_service(ExecutorControlServer::new(MyService))
//!     .serve(addr)
//!     .await?;
//! ```

// Create proper module hierarchy for generated protobuf code
pub mod basilca {
    pub mod common {
        pub mod v1 {
            include!("gen/basilca.common.v1.rs");
        }
    }

    pub mod executor {
        pub mod v1 {
            include!("gen/basilca.executor.v1.rs");
        }
    }

    pub mod executor_registration {
        pub mod v1 {
            include!("gen/basilca.executor_registration.v1.rs");
        }
    }

    pub mod executor_management {
        pub mod v1 {
            include!("gen/basilca.executor_management.v1.rs");
        }
    }

    pub mod miner {
        pub mod v1 {
            include!("gen/basilca.miner.v1.rs");
        }
    }

    pub mod validator {
        pub mod v1 {
            include!("gen/basilca.validator.v1.rs");
        }
    }

    pub mod gpu_pow {
        pub mod v1 {
            include!("gen/basilca.gpu_pow.v1.rs");
        }
    }
}

// Structured re-exports for better organization
pub mod common {
    //! Common types and data structures used across all services
    pub use crate::basilca::common::v1::*;
}

pub mod executor_control {
    //! Executor control service for direct Validator ↔ Executor communication
    //!
    //! This service supports step 5 of the interaction flow (direct validation):
    //! - System profiling and hardware specification collection
    //! - Computational challenge execution and verification
    //! - Container lifecycle management
    //! - Real-time log streaming
    //! - Health monitoring and heartbeat
    pub use crate::basilca::executor::v1::*;
}

pub mod miner_discovery {
    //! Miner discovery service for Validator ↔ Miner coordination
    //!
    //! This service supports steps 3-4 of the interaction flow:
    //! - Bittensor signature-based validator authentication
    //! - Executor lease requests with resource requirements
    //! - Validator-executor session initialization
    pub use crate::basilca::miner::v1::*;
}

pub mod executor_registration {
    //! Executor registration service for Executor ↔ Miner registration
    //!
    //! This service allows executors to register with their managing miner:
    //! - Executor registration with GPU attestation
    //! - Status updates and heartbeats
    //! - Graceful unregistration
    pub use crate::basilca::executor_registration::v1::*;
}

pub mod executor_management {
    //! Executor management service for Miner ↔ Executor management
    //!
    //! This service allows miners to manage their executors:
    //! - Health checks and status monitoring
    //! - SSH key management for validator access
    //! - Resource usage tracking
    pub use crate::basilca::executor_management::v1::*;
}

pub mod validator_api {
    //! External API service for services like Celium to interact with validators
    //!
    //! Public interface for capacity rental:
    //! - Discover available GPU capacity across the network
    //! - Rent GPU capacity with container specifications
    //! - Manage rental lifecycle (terminate, status, logs)
    pub use crate::basilca::validator::v1::*;
}

// Re-export common types at crate root for convenience
pub use basilica_common::*;

// Utility functions for working with protocol types
pub mod utils {
    use super::common::*;

    /// Convert ExecutorId to string representation for protobuf
    pub fn executor_id_to_string(id: &str) -> String {
        id.to_string()
    }

    /// Convert string to ExecutorId (with validation)
    pub fn string_to_executor_id(s: &str) -> Result<String, String> {
        if s.is_empty() {
            Err("Executor ID cannot be empty".to_string())
        } else {
            Ok(s.to_string())
        }
    }

    /// Validate GPU specification
    pub fn validate_gpu_spec(gpu: &GpuSpec) -> Result<(), String> {
        if gpu.model.is_empty() {
            return Err("GPU model cannot be empty".to_string());
        }
        if gpu.memory_mb == 0 {
            return Err("GPU memory must be greater than 0".to_string());
        }
        Ok(())
    }

    /// Validate container specification
    pub fn validate_container_spec(spec: &ContainerSpec) -> Result<(), String> {
        if spec.image.is_empty() {
            return Err("Container image cannot be empty".to_string());
        }
        Ok(())
    }

    /// Create a timestamp from current time
    pub fn current_timestamp() -> Timestamp {
        Timestamp {
            value: Some(prost_types::Timestamp::from(std::time::SystemTime::now())),
        }
    }

    /// Convert ResourceUsageStats to human-readable format
    pub fn format_resource_usage(stats: &ResourceUsageStats) -> String {
        format!(
            "CPU: {:.1}%, Memory: {} MB, GPU: {:?}%",
            stats.cpu_percent, stats.memory_mb, stats.gpu_utilization
        )
    }
}

// Error handling for protocol operations
pub mod errors {
    use thiserror::Error;

    /// Protocol-specific errors
    #[derive(Error, Debug)]
    pub enum ProtocolError {
        #[error("gRPC communication failed: {0}")]
        GrpcError(#[from] tonic::Status),

        #[error("Invalid message format: {0}")]
        InvalidMessage(String),

        #[error("Authentication failed: {0}")]
        AuthenticationFailed(String),

        #[error("Protocol version mismatch: expected {expected}, got {actual}")]
        VersionMismatch { expected: String, actual: String },

        #[error("Validation error: {0}")]
        ValidationError(String),

        #[error("Resource not found: {0}")]
        ResourceNotFound(String),

        #[error("Resource conflict: {0}")]
        ResourceConflict(String),

        #[error("Timeout error: {0}")]
        Timeout(String),
    }

    impl From<ProtocolError> for tonic::Status {
        fn from(err: ProtocolError) -> Self {
            match err {
                ProtocolError::GrpcError(status) => status,
                ProtocolError::InvalidMessage(msg) => tonic::Status::invalid_argument(msg),
                ProtocolError::AuthenticationFailed(msg) => tonic::Status::unauthenticated(msg),
                ProtocolError::ValidationError(msg) => tonic::Status::invalid_argument(msg),
                ProtocolError::ResourceNotFound(msg) => tonic::Status::not_found(msg),
                ProtocolError::ResourceConflict(msg) => tonic::Status::already_exists(msg),
                ProtocolError::Timeout(msg) => tonic::Status::deadline_exceeded(msg),
                _ => tonic::Status::internal(err.to_string()),
            }
        }
    }
}

/// Version of the protocol definitions
pub const PROTOCOL_VERSION: &str = "1.0.0";

// Implementation notes for generated types:
// The protobuf-generated types may have different field names than expected.
// Always check the generated code in src/gen/ for the actual structure.
// Key differences from common expectations:
// - HealthCheckResponse uses 'status' as an i32 enum value, not a struct field
// - SystemProfileResponse uses encrypted_profile instead of direct machine_info
// - Some message types may be nested under different modules than expected

// Implementation notes for generated types:
// The protobuf-generated types may have different field names than expected.
// Always check the generated code in src/gen/ for the actual structure.
// Key differences from common expectations:
// - HealthCheckResponse uses 'status' as an i32 enum value, not a struct field
// - SystemProfileResponse uses encrypted_profile instead of direct machine_info
// - Some message types may be nested under different modules than expected

// Helper types for common gRPC patterns
pub mod helpers {
    use tonic::{Request, Status};
    use tracing::instrument;

    /// Extract metadata value from gRPC request
    #[allow(clippy::result_large_err)]
    pub fn extract_metadata(
        request: &Request<impl std::fmt::Debug>,
        key: &str,
    ) -> Result<String, Status> {
        request
            .metadata()
            .get(key)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .ok_or_else(|| Status::invalid_argument(format!("Missing required metadata: {key}")))
    }

    /// Verify protocol version compatibility
    #[allow(clippy::result_large_err)]
    pub fn verify_protocol_version(client_version: &str) -> Result<(), Status> {
        if client_version != crate::PROTOCOL_VERSION {
            return Err(Status::failed_precondition(format!(
                "Protocol version mismatch: client={}, server={}",
                client_version,
                crate::PROTOCOL_VERSION
            )));
        }
        Ok(())
    }

    /// Helper for creating authenticated requests
    #[instrument(skip(request))]
    pub fn add_auth_metadata<T>(
        mut request: Request<T>,
        hotkey: &str,
        signature: &str,
    ) -> Request<T> {
        request
            .metadata_mut()
            .insert("x-hotkey", hotkey.parse().expect("Invalid hotkey format"));
        request.metadata_mut().insert(
            "x-signature",
            signature.parse().expect("Invalid signature format"),
        );
        request
    }

    /// Create a gRPC interceptor for mTLS when implemented
    pub fn create_tls_config(
    ) -> Result<tonic::transport::ClientTlsConfig, Box<dyn std::error::Error>> {
        // TODO: Implement mTLS configuration when certificates are available
        // For now, return a placeholder that uses system roots
        Ok(tonic::transport::ClientTlsConfig::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utility_functions() {
        let id = "test-executor-123";
        let id_str = utils::executor_id_to_string(id);
        let parsed_id = utils::string_to_executor_id(&id_str).unwrap();

        assert_eq!(id, parsed_id);
    }

    #[test]
    fn test_gpu_spec_validation() {
        let mut gpu = common::GpuSpec {
            model: "RTX 4090".to_string(),
            memory_mb: 24000,
            uuid: "GPU-12345".to_string(),
            driver_version: "535.86.05".to_string(),
            cuda_version: "12.2".to_string(),
            utilization_percent: 0.0,
            memory_utilization_percent: 0.0,
            temperature_celsius: 45.0,
            power_watts: 350.0,
            core_clock_mhz: 2205,
            memory_clock_mhz: 10501,
            compute_capability: "8.9".to_string(),
        };

        assert!(utils::validate_gpu_spec(&gpu).is_ok());

        gpu.model = String::new();
        assert!(utils::validate_gpu_spec(&gpu).is_err());
    }

    #[test]
    fn test_container_spec_validation() {
        let mut spec = common::ContainerSpec {
            image: "nvidia/cuda:12.2-runtime-ubuntu20.04".to_string(),
            environment: std::collections::HashMap::new(),
            port_mappings: std::collections::HashMap::new(),
            volume_mounts: std::collections::HashMap::new(),
            resource_limits: None,
            command: vec![],
            working_directory: "/app".to_string(),
            user: "root".to_string(),
            gpu_requirements: vec!["nvidia".to_string()],
            network_mode: "bridge".to_string(),
        };

        assert!(utils::validate_container_spec(&spec).is_ok());

        spec.image = String::new();
        assert!(utils::validate_container_spec(&spec).is_err());
    }

    #[test]
    fn test_error_conversion() {
        let proto_err =
            errors::ProtocolError::AuthenticationFailed("Invalid signature".to_string());
        let status: tonic::Status = proto_err.into();

        assert_eq!(status.code(), tonic::Code::Unauthenticated);
        assert!(status.message().contains("Invalid signature"));
    }

    #[test]
    fn test_timestamp_creation() {
        let ts = utils::current_timestamp();
        assert!(ts.value.is_some());
    }

    #[test]
    fn test_helpers_extract_metadata() {
        use tonic::Request;
        let mut request = Request::new(());
        request
            .metadata_mut()
            .insert("test-key", "test-value".parse().unwrap());

        let result = helpers::extract_metadata(&request, "test-key");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test-value");

        let missing = helpers::extract_metadata(&request, "missing-key");
        assert!(missing.is_err());
    }

    #[test]
    fn test_helpers_verify_protocol_version() {
        let result = helpers::verify_protocol_version(PROTOCOL_VERSION);
        assert!(result.is_ok());

        let mismatch = helpers::verify_protocol_version("0.9.0");
        assert!(mismatch.is_err());
    }

    #[test]
    fn test_helpers_add_auth_metadata() {
        use tonic::Request;
        let request = Request::new(());
        let authed = helpers::add_auth_metadata(request, "test-hotkey", "test-signature");

        assert_eq!(
            authed.metadata().get("x-hotkey").unwrap().to_str().unwrap(),
            "test-hotkey"
        );
        assert_eq!(
            authed
                .metadata()
                .get("x-signature")
                .unwrap()
                .to_str()
                .unwrap(),
            "test-signature"
        );
    }
}
