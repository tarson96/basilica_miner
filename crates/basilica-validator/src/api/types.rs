//! API Types and Data Transfer Objects
//!
//! All request/response types, enums, and shared data structures for the validator API

use crate::rental::RentalState;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[cfg(feature = "openapi")]
use utoipa::ToSchema;

/// Request to rent GPU capacity
#[derive(Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct RentCapacityRequest {
    pub gpu_requirements: GpuRequirements,
    pub ssh_public_key: String,
    pub docker_image: String,
    pub env_vars: Option<HashMap<String, String>>,
    pub max_duration_hours: u32,
}

#[derive(Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct GpuRequirements {
    pub min_memory_gb: u32,
    pub gpu_type: Option<String>,
    pub gpu_count: u32,
}

/// Response for capacity rental request
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct RentCapacityResponse {
    pub rental_id: String,
    pub executor: ExecutorDetails,
    pub ssh_access: SshAccess,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct ExecutorDetails {
    pub id: String,
    pub gpu_specs: Vec<GpuSpec>,
    pub cpu_specs: CpuSpec,
    pub location: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct GpuSpec {
    pub name: String,
    pub memory_gb: u32,
    pub compute_capability: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct CpuSpec {
    pub cores: u32,
    pub model: String,
    pub memory_gb: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct SshAccess {
    pub host: String,
    pub port: u16,
    pub username: String,
}

/// Request to terminate a rental
#[derive(Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct TerminateRentalRequest {
    pub reason: Option<String>,
}

/// Rental status information
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct RentalStatusResponse {
    pub rental_id: String,
    pub status: RentalStatus,
    pub executor: ExecutorDetails,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum RentalStatus {
    Pending,
    Active,
    Terminated,
    Failed,
}

/// Available executors listing
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct ListAvailableExecutorsResponse {
    pub available_executors: Vec<AvailableExecutor>,
    pub total_count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct AvailableExecutor {
    pub executor: ExecutorDetails,
    pub availability: AvailabilityInfo,
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct AvailabilityInfo {
    pub available_until: Option<chrono::DateTime<chrono::Utc>>,
    pub verification_score: f64,
    pub uptime_percentage: f64,
}

/// Query parameters for listing available executors
#[derive(Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct ListAvailableExecutorsQuery {
    /// Filter for available executors only (default: true for /executors endpoint)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_gpu_memory: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_gpu_count: Option<u32>,
}

/// Log streaming query parameters
#[derive(Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct LogQuery {
    pub follow: Option<bool>,
    pub tail: Option<u32>,
}

/// Miner registration request
#[derive(Debug, Deserialize)]
pub struct RegisterMinerRequest {
    pub miner_id: String,
    pub hotkey: String,
    pub endpoint: String,
    pub signature: String,
    pub executors: Vec<ExecutorRegistration>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ExecutorRegistration {
    pub executor_id: String,
    pub grpc_address: String,
    pub gpu_count: u32,
    pub gpu_specs: Vec<GpuSpec>,
    pub cpu_specs: CpuSpec,
}

/// Miner registration response
#[derive(Debug, Serialize)]
pub struct RegisterMinerResponse {
    pub success: bool,
    pub miner_id: String,
    pub message: String,
}

/// Miner details for listing
#[derive(Debug, Serialize)]
pub struct MinerDetails {
    pub miner_id: String,
    pub hotkey: String,
    pub endpoint: String,
    pub status: MinerStatus,
    pub executor_count: u32,
    pub total_gpu_count: u32,
    pub verification_score: f64,
    pub uptime_percentage: f64,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub registered_at: chrono::DateTime<chrono::Utc>,
}

/// Miner status enumeration
#[derive(Debug, Serialize)]
pub enum MinerStatus {
    Active,
    Inactive,
    Offline,
    Verifying,
    Suspended,
}

/// List miners response
#[derive(Debug, Serialize)]
pub struct ListMinersResponse {
    pub miners: Vec<MinerDetails>,
    pub total_count: usize,
    pub page: u32,
    pub page_size: u32,
}

/// Query parameters for miner listing
#[derive(Debug, Deserialize)]
pub struct ListMinersQuery {
    pub status: Option<String>,
    pub min_gpu_count: Option<u32>,
    pub min_score: Option<f64>,
    pub page: Option<u32>,
    pub page_size: Option<u32>,
}

/// Miner update request
#[derive(Debug, Deserialize)]
pub struct UpdateMinerRequest {
    pub endpoint: Option<String>,
    pub signature: String,
    pub executors: Option<Vec<ExecutorRegistration>>,
}

/// Miner health status response
#[derive(Debug, Serialize)]
pub struct MinerHealthResponse {
    pub miner_id: String,
    pub overall_status: MinerStatus,
    pub last_health_check: chrono::DateTime<chrono::Utc>,
    pub executor_health: Vec<ExecutorHealthStatus>,
    pub response_time_ms: u64,
}

#[derive(Debug, Serialize)]
pub struct ExecutorHealthStatus {
    pub executor_id: String,
    pub status: String,
    pub last_seen: chrono::DateTime<chrono::Utc>,
}

/// Verification trigger request
#[derive(Debug, Deserialize)]
pub struct TriggerVerificationRequest {
    pub verification_type: String,
    pub executor_id: Option<String>,
}

/// Verification trigger response
#[derive(Debug, Serialize)]
pub struct TriggerVerificationResponse {
    pub verification_id: String,
    pub status: String,
    pub estimated_completion: chrono::DateTime<chrono::Utc>,
}

/// Emission metrics response
#[derive(Debug, Serialize)]
pub struct EmissionMetricsResponse {
    pub id: i64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub burn_amount: u64,
    pub burn_percentage: f64,
    pub category_distributions: HashMap<String, CategoryDistributionResponse>,
    pub total_miners: u32,
    pub weight_set_block: u64,
}

#[derive(Debug, Serialize)]
pub struct CategoryDistributionResponse {
    pub category: String,
    pub miner_count: u32,
    pub total_weight: u64,
    pub average_score: f64,
}

#[derive(Debug, Serialize)]
pub struct MinerWeightAllocation {
    pub miner_uid: u16,
    pub gpu_category: String,
    pub allocated_weight: u64,
    pub miner_score: f64,
    pub percentage_of_category: f64,
}

#[derive(Debug, Serialize)]
pub struct CategoryWeightSummary {
    pub category: String,
    pub total_weight: u64,
    pub miner_count: u32,
    pub average_score: f64,
}

/// Rental list item for API response
#[derive(Debug, Serialize, Deserialize)]
pub struct RentalListItem {
    pub rental_id: String,
    pub executor_id: String,
    pub container_id: String,
    pub state: RentalState,
    pub created_at: String,
    pub miner_id: String,
    pub container_image: String,
}

/// Response for listing rentals
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct ListRentalsResponse {
    pub rentals: Vec<RentalListItem>,
    pub total_count: usize,
}

/// API error type
#[derive(Debug)]
pub enum ApiError {
    NotFound(String),
    BadRequest(String),
    Unauthorized,
    InternalError(String),
}

impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;
        use axum::Json;

        let (status, message) = match self {
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()),
            ApiError::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        let body = Json(serde_json::json!({
            "error": message,
            "timestamp": chrono::Utc::now()
        }));

        (status, body).into_response()
    }
}
