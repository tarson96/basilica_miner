//! # Validator Discovery
//!
//! Discovers validators from the Bittensor metagraph and manages executor assignments
//! based on arbitrary miner-defined strategies.

use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::executor_manager::{AvailableExecutor, ExecutorManager};
use crate::persistence::AssignmentDb;
use sqlx::SqlitePool;

/// Information about a discovered validator
#[derive(Debug, Clone)]
pub struct ValidatorInfo {
    /// The validator's unique identifier
    pub uid: u16,
    /// The validator's hotkey (SS58 address)
    pub hotkey: String,
    /// The validator's stake amount
    pub stake: u64,
    /// The validator's axon endpoint
    pub axon_endpoint: Option<String>,
}

/// Manages validator discovery and executor assignments
pub struct ValidatorDiscovery {
    bittensor_service: Arc<bittensor::Service>,
    executor_manager: Arc<ExecutorManager>,
    assignment_strategy: Box<dyn AssignmentStrategy>,
    assignments: Arc<RwLock<HashMap<String, Vec<String>>>>, // validator_hotkey -> executor_ids
    netuid: u16,
    assignment_db: Option<AssignmentDb>,
}

/// Strategy for assigning executors to validators
#[async_trait]
pub trait AssignmentStrategy: Send + Sync {
    /// Assign executors to validators based on custom logic
    async fn assign_executors(
        &self,
        validators: Vec<ValidatorInfo>,
        executors: Vec<AvailableExecutor>,
        current_assignments: &HashMap<String, Vec<String>>,
    ) -> HashMap<String, Vec<String>>;
}

impl ValidatorDiscovery {
    /// Create a new validator discovery service
    pub fn new(
        bittensor_service: Arc<bittensor::Service>,
        executor_manager: Arc<ExecutorManager>,
        assignment_strategy: Box<dyn AssignmentStrategy>,
        netuid: u16,
    ) -> Self {
        Self {
            bittensor_service,
            executor_manager,
            assignment_strategy,
            assignments: Arc::new(RwLock::new(HashMap::new())),
            netuid,
            assignment_db: None,
        }
    }

    /// Set the assignment database for manual assignments
    pub fn with_assignment_db(mut self, db: AssignmentDb) -> Self {
        self.assignment_db = Some(db);
        self
    }

    /// Discover validators and update executor assignments
    pub async fn discover_and_assign(&self) -> Result<()> {
        info!("Starting validator discovery and executor assignment");

        // Fetch metagraph
        let metagraph = self
            .bittensor_service
            .get_metagraph(self.netuid)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get metagraph: {}", e))?;

        // Use discovery module to find validators
        let discovery = bittensor::NeuronDiscovery::new(&metagraph);
        let validators = discovery.get_validators()?;

        info!("Discovered {} validators from metagraph", validators.len());

        // Convert to ValidatorInfo
        let validator_infos: Vec<ValidatorInfo> = validators
            .into_iter()
            .map(|v| {
                let axon_endpoint = v.axon_info.map(|a| format!("{}:{}", a.ip, a.port));
                ValidatorInfo {
                    uid: v.uid,
                    hotkey: v.hotkey,
                    stake: v.stake,
                    axon_endpoint,
                }
            })
            .collect();

        // Log validators with axon endpoints
        let with_endpoints = validator_infos
            .iter()
            .filter(|v| v.axon_endpoint.is_some())
            .count();
        info!(
            "Found {} validators with axon endpoints out of {} total",
            with_endpoints,
            validator_infos.len()
        );

        // Get available executors
        let executors = self.executor_manager.list_available().await?;
        info!("Found {} available executors", executors.len());

        // Get current assignments
        let current_assignments = self.assignments.read().await.clone();

        // Apply assignment strategy
        let new_assignments = self
            .assignment_strategy
            .assign_executors(validator_infos, executors, &current_assignments)
            .await;

        // Log assignment changes
        for (validator_hotkey, executor_ids) in &new_assignments {
            if let Some(old_ids) = current_assignments.get(validator_hotkey) {
                if old_ids != executor_ids {
                    info!(
                        "Updated assignment for validator {}: {:?} -> {:?}",
                        validator_hotkey, old_ids, executor_ids
                    );
                }
            } else {
                info!(
                    "New assignment for validator {}: {:?}",
                    validator_hotkey, executor_ids
                );
            }
        }

        // Store new assignments
        *self.assignments.write().await = new_assignments;

        info!("Completed validator discovery and executor assignment");
        Ok(())
    }

    /// Get current assignments for a specific validator
    pub async fn get_validator_assignments(&self, validator_hotkey: &str) -> Option<Vec<String>> {
        // If we have an assignment DB, use manual assignments from it
        if let Some(ref db) = self.assignment_db {
            match db.get_assignments_for_validator(validator_hotkey).await {
                Ok(assignments) => {
                    if assignments.is_empty() {
                        None
                    } else {
                        Some(assignments.into_iter().map(|a| a.executor_id).collect())
                    }
                }
                Err(e) => {
                    warn!("Failed to get assignments from database: {}", e);
                    None
                }
            }
        } else {
            // Fall back to in-memory assignments (old behavior)
            self.assignments.read().await.get(validator_hotkey).cloned()
        }
    }

    /// Get all current assignments
    pub async fn get_all_assignments(&self) -> HashMap<String, Vec<String>> {
        self.assignments.read().await.clone()
    }

    /// Check if a validator has any assigned executors
    pub async fn has_assignments(&self, validator_hotkey: &str) -> bool {
        self.assignments
            .read()
            .await
            .get(validator_hotkey)
            .map(|ids| !ids.is_empty())
            .unwrap_or(false)
    }
}

/// Business logic based assignment strategy
#[allow(dead_code)]
pub struct BusinessLogicAssignment {
    /// Validators that should be prioritized
    pub preferred_validators: Vec<String>,
    /// Maximum executors to assign per validator
    pub max_executors_per_validator: usize,
}

#[async_trait]
impl AssignmentStrategy for BusinessLogicAssignment {
    async fn assign_executors(
        &self,
        validators: Vec<ValidatorInfo>,
        executors: Vec<AvailableExecutor>,
        _current_assignments: &HashMap<String, Vec<String>>,
    ) -> HashMap<String, Vec<String>> {
        let mut assignments = HashMap::new();
        let mut executor_iter = executors.into_iter();

        // First, assign to preferred validators
        for validator in validators.iter() {
            if self.preferred_validators.contains(&validator.hotkey) {
                let assigned: Vec<String> = executor_iter
                    .by_ref()
                    .take(self.max_executors_per_validator)
                    .map(|e| e.id)
                    .collect();

                if !assigned.is_empty() {
                    debug!(
                        "Assigned {} executors to preferred validator {}",
                        assigned.len(),
                        validator.hotkey
                    );
                    assignments.insert(validator.hotkey.clone(), assigned);
                }
            }
        }

        // Then, assign remaining executors to other validators
        for validator in validators.iter() {
            if !assignments.contains_key(&validator.hotkey) && validator.axon_endpoint.is_some() {
                if let Some(executor) = executor_iter.next() {
                    debug!(
                        "Assigned executor {} to validator {}",
                        executor.id, validator.hotkey
                    );
                    assignments.insert(validator.hotkey.clone(), vec![executor.id]);
                }
            }
        }

        assignments
    }
}

/// Random assignment strategy
#[allow(dead_code)]
pub struct RandomAssignment {
    /// Maximum executors to assign per validator
    pub max_executors_per_validator: usize,
}

#[async_trait]
impl AssignmentStrategy for RandomAssignment {
    async fn assign_executors(
        &self,
        validators: Vec<ValidatorInfo>,
        executors: Vec<AvailableExecutor>,
        _current_assignments: &HashMap<String, Vec<String>>,
    ) -> HashMap<String, Vec<String>> {
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();

        let mut assignments = HashMap::new();
        let mut available_executors = executors;
        available_executors.shuffle(&mut rng);

        let mut validators_with_endpoints: Vec<_> = validators
            .into_iter()
            .filter(|v| v.axon_endpoint.is_some())
            .collect();
        validators_with_endpoints.shuffle(&mut rng);

        let mut executor_iter = available_executors.into_iter();

        for validator in validators_with_endpoints {
            let assigned: Vec<String> = executor_iter
                .by_ref()
                .take(self.max_executors_per_validator)
                .map(|e| e.id)
                .collect();

            if !assigned.is_empty() {
                assignments.insert(validator.hotkey, assigned);
            }
        }

        assignments
    }
}

/// Stake-based assignment strategy
#[allow(dead_code)]
pub struct StakeBasedAssignment {
    /// Minimum stake required for any assignment
    pub min_stake_threshold: u64,
    /// Scaling factor for executors per TAO of stake
    pub executors_per_tao: f64,
}

#[async_trait]
impl AssignmentStrategy for StakeBasedAssignment {
    async fn assign_executors(
        &self,
        validators: Vec<ValidatorInfo>,
        executors: Vec<AvailableExecutor>,
        _current_assignments: &HashMap<String, Vec<String>>,
    ) -> HashMap<String, Vec<String>> {
        let mut assignments = HashMap::new();

        // Filter and sort validators by stake (descending)
        let mut eligible_validators: Vec<_> = validators
            .into_iter()
            .filter(|v| v.stake >= self.min_stake_threshold && v.axon_endpoint.is_some())
            .collect();
        eligible_validators.sort_by(|a, b| b.stake.cmp(&a.stake));

        let mut executor_iter = executors.into_iter();

        for validator in eligible_validators {
            // Calculate executors based on stake
            let tao_stake = validator.stake as f64 / 1e9; // Convert from RAO to TAO
            let executor_count = (tao_stake * self.executors_per_tao).round() as usize;
            let executor_count = executor_count.max(1); // At least 1 executor if eligible

            let assigned: Vec<String> = executor_iter
                .by_ref()
                .take(executor_count)
                .map(|e| e.id)
                .collect();

            if !assigned.is_empty() {
                debug!(
                    "Assigned {} executors to validator {} with {:.2} TAO stake",
                    assigned.len(),
                    validator.hotkey,
                    tao_stake
                );
                assignments.insert(validator.hotkey, assigned);
            }
        }

        assignments
    }
}

/// Round-robin assignment strategy
pub struct RoundRobinAssignment;

#[async_trait]
impl AssignmentStrategy for RoundRobinAssignment {
    async fn assign_executors(
        &self,
        validators: Vec<ValidatorInfo>,
        executors: Vec<AvailableExecutor>,
        _current_assignments: &HashMap<String, Vec<String>>,
    ) -> HashMap<String, Vec<String>> {
        let mut assignments: HashMap<String, Vec<String>> = HashMap::new();

        let eligible_validators: Vec<_> = validators
            .into_iter()
            .filter(|v| v.axon_endpoint.is_some())
            .collect();

        if eligible_validators.is_empty() {
            warn!("No validators with axon endpoints found for assignment");
            return assignments;
        }

        // Initialize empty vectors for each validator
        for validator in &eligible_validators {
            assignments.insert(validator.hotkey.clone(), Vec::new());
        }

        // Distribute executors round-robin
        for (idx, executor) in executors.into_iter().enumerate() {
            let validator_idx = idx % eligible_validators.len();
            let validator_hotkey = &eligible_validators[validator_idx].hotkey;

            assignments
                .get_mut(validator_hotkey)
                .unwrap()
                .push(executor.id);
        }

        // Remove validators with no executors
        assignments.retain(|_, v| !v.is_empty());

        assignments
    }
}

/// Highest stake assignment strategy
pub struct HighestStakeAssignment {
    pool: SqlitePool,
    min_stake_threshold: f64,
    validator_hotkey: Option<String>,
}

impl HighestStakeAssignment {
    pub fn new(
        pool: SqlitePool,
        min_stake_threshold: f64,
        validator_hotkey: Option<String>,
    ) -> Self {
        Self {
            pool,
            min_stake_threshold,
            validator_hotkey,
        }
    }
}

#[async_trait]
impl AssignmentStrategy for HighestStakeAssignment {
    async fn assign_executors(
        &self,
        validators: Vec<ValidatorInfo>,
        executors: Vec<AvailableExecutor>,
        _current_assignments: &HashMap<String, Vec<String>>,
    ) -> HashMap<String, Vec<String>> {
        let mut assignments = HashMap::new();
        let all_executor_ids: Vec<String> = executors.into_iter().map(|e| e.id).collect();
        let db = AssignmentDb::new(self.pool.clone());
        let validator_stakes = match db
            .get_validator_stakes_above(self.min_stake_threshold)
            .await
        {
            Ok(stakes) => stakes,
            Err(e) => {
                warn!("Failed to get validator stakes from database: {}", e);
                return assignments;
            }
        };

        let stake_map: HashMap<String, f64> = validator_stakes
            .into_iter()
            .map(|vs| (vs.validator_hotkey, vs.stake_amount))
            .collect();

        if all_executor_ids.is_empty() {
            warn!("No available executors found for assignment");
            return assignments;
        }

        // Filter validators to only those that are:
        // 1. Online
        // 2. Have sufficient stake in database
        let mut eligible_validators: Vec<_> = validators
            .into_iter()
            .filter(|v| {
                v.axon_endpoint.is_some()
                    && stake_map.get(&v.hotkey).copied().unwrap_or(0.0) >= self.min_stake_threshold
            })
            .collect();

        eligible_validators.sort_by(|a, b| {
            let stake_a = stake_map.get(&a.hotkey).copied().unwrap_or(0.0);
            let stake_b = stake_map.get(&b.hotkey).copied().unwrap_or(0.0);
            stake_b.partial_cmp(&stake_a).unwrap()
        });

        if eligible_validators.is_empty() {
            warn!("No validators with sufficient stake and online status found");
            return assignments;
        }

        info!(
            "Found {} eligible validators with stake >= {} TAO and online status",
            eligible_validators.len(),
            self.min_stake_threshold
        );

        let target_validator = if let Some(ref target_hotkey) = self.validator_hotkey {
            eligible_validators
                .iter()
                .find(|v| &v.hotkey == target_hotkey)
        } else {
            eligible_validators.first()
        };

        if let Some(validator) = target_validator {
            let stake = stake_map.get(&validator.hotkey).copied().unwrap_or(0.0);
            info!(
                "Assigning {} executors to validator {} with {:.2} TAO stake",
                all_executor_ids.len(),
                &validator.hotkey[..8.min(validator.hotkey.len())],
                stake
            );
            assignments.insert(validator.hotkey.clone(), all_executor_ids);
        } else {
            warn!(
                "Configured validator {} not found among eligible validators",
                self.validator_hotkey.as_ref().unwrap()
            );
        }

        assignments
    }
}

#[cfg(test)]
/// Manual assignment strategy that reads from the database
pub struct ManualAssignment {
    pool: SqlitePool,
}

#[cfg(test)]
impl ManualAssignment {
    /// Create a new manual assignment strategy
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[cfg(test)]
#[async_trait]
impl AssignmentStrategy for ManualAssignment {
    async fn assign_executors(
        &self,
        _validators: Vec<ValidatorInfo>,
        _executors: Vec<AvailableExecutor>,
        _current_assignments: &HashMap<String, Vec<String>>,
    ) -> HashMap<String, Vec<String>> {
        let db = AssignmentDb::new(self.pool.clone());

        // Get all assignments from the database
        match db.get_all_assignments().await {
            Ok(assignments) => {
                let mut result: HashMap<String, Vec<String>> = HashMap::new();

                // Group assignments by validator
                for assignment in assignments {
                    result
                        .entry(assignment.validator_hotkey)
                        .or_default()
                        .push(assignment.executor_id);
                }

                info!(
                    "Loaded {} validator assignments from database",
                    result.len()
                );
                for (validator, executors) in &result {
                    debug!(
                        "Validator {} has {} executors assigned",
                        validator,
                        executors.len()
                    );
                }

                result
            }
            Err(e) => {
                warn!("Failed to load assignments from database: {}", e);
                HashMap::new()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MinerConfig;
    use crate::executor_manager::ExecutorManager;
    use crate::persistence::RegistrationDb;
    use sqlx::SqlitePool;

    async fn setup_test_db() -> Result<SqlitePool> {
        let pool = SqlitePool::connect("sqlite::memory:").await?;
        let assignment_db = AssignmentDb::new(pool.clone());
        assignment_db.run_migrations().await?;
        Ok(pool)
    }

    fn create_test_config() -> MinerConfig {
        use crate::config::MinerBittensorConfig;
        use basilica_common::config::{BittensorConfig, DatabaseConfig};

        MinerConfig {
            bittensor: MinerBittensorConfig {
                common: BittensorConfig {
                    wallet_name: "test_wallet".to_string(),
                    hotkey_name: "test_hotkey".to_string(),
                    network: "local".to_string(),
                    netuid: 999,
                    chain_endpoint: Some("ws://127.0.0.1:9944".to_string()),
                    weight_interval_secs: 300,
                },
                coldkey_name: "test_coldkey".to_string(),
                skip_registration: true,
                ..Default::default()
            },
            database: DatabaseConfig {
                url: "sqlite::memory:".to_string(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_round_robin_assignment() {
        let validators = vec![
            ValidatorInfo {
                uid: 1,
                hotkey: "val1".to_string(),
                stake: 1000,
                axon_endpoint: Some("1.1.1.1:8080".to_string()),
            },
            ValidatorInfo {
                uid: 2,
                hotkey: "val2".to_string(),
                stake: 2000,
                axon_endpoint: Some("2.2.2.2:8080".to_string()),
            },
        ];

        let executors = vec![
            AvailableExecutor {
                id: "e1".to_string(),
                name: "E1".to_string(),
                grpc_address: "".to_string(),
                resources: None,
                gpu_count: 1,
            },
            AvailableExecutor {
                id: "e2".to_string(),
                name: "E2".to_string(),
                grpc_address: "".to_string(),
                resources: None,
                gpu_count: 1,
            },
            AvailableExecutor {
                id: "e3".to_string(),
                name: "E3".to_string(),
                grpc_address: "".to_string(),
                resources: None,
                gpu_count: 1,
            },
        ];

        let strategy = RoundRobinAssignment;
        let assignments = strategy
            .assign_executors(validators, executors, &HashMap::new())
            .await;

        // Round-robin: e1->val1, e2->val2, e3->val1
        assert_eq!(assignments.len(), 2);
        assert_eq!(assignments["val1"], vec!["e1", "e3"]);
        assert_eq!(assignments["val2"], vec!["e2"]);
    }

    #[tokio::test]
    async fn test_manual_assignment_empty_database() -> Result<()> {
        let pool = setup_test_db().await?;
        let strategy = ManualAssignment::new(pool);

        let assignments = strategy
            .assign_executors(vec![], vec![], &HashMap::new())
            .await;

        assert_eq!(assignments.len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn test_manual_assignment_with_data() -> Result<()> {
        let pool = setup_test_db().await?;
        let db = AssignmentDb::new(pool.clone());

        db.create_assignment("e1", "v1", "test", None).await?;
        db.create_assignment("e2", "v1", "test", None).await?;
        db.create_assignment("e3", "v2", "test", None).await?;

        let strategy = ManualAssignment::new(pool);
        let assignments = strategy
            .assign_executors(vec![], vec![], &HashMap::new())
            .await;

        assert_eq!(assignments.len(), 2);
        let v1_execs = &assignments["v1"];
        assert_eq!(v1_execs.len(), 2);
        assert!(v1_execs.contains(&"e1".to_string()));
        assert!(v1_execs.contains(&"e2".to_string()));
        assert_eq!(assignments["v2"], vec!["e3"]);

        Ok(())
    }

    #[tokio::test]
    async fn test_manual_assignment_reassignment() -> Result<()> {
        let pool = setup_test_db().await?;
        let db = AssignmentDb::new(pool.clone());
        let strategy = ManualAssignment::new(pool.clone());

        db.create_assignment("exec-1", "val-1", "test", None)
            .await?;

        let assignments1 = strategy
            .assign_executors(vec![], vec![], &HashMap::new())
            .await;
        assert_eq!(assignments1["val-1"], vec!["exec-1"]);

        db.delete_assignment("exec-1", "test").await?;
        db.create_assignment("exec-1", "val-2", "test", None)
            .await?;

        let assignments2 = strategy
            .assign_executors(vec![], vec![], &HashMap::new())
            .await;
        assert!(!assignments2.contains_key("val-1"));
        assert_eq!(assignments2["val-2"], vec!["exec-1"]);

        Ok(())
    }

    #[tokio::test]
    async fn test_highest_stake_assignment() -> Result<()> {
        let pool = setup_test_db().await?;
        let db = AssignmentDb::new(pool.clone());

        db.update_validator_stake("val1", 5000.0, 50.0).await?;
        db.update_validator_stake("val2", 200.0, 20.0).await?;
        db.update_validator_stake("val3", 50.0, 5.0).await?;

        let validators = vec![
            ValidatorInfo {
                uid: 1,
                hotkey: "val1".to_string(),
                stake: 1,
                axon_endpoint: Some("1.1.1.1:8080".to_string()),
            },
            ValidatorInfo {
                uid: 2,
                hotkey: "val2".to_string(),
                stake: 1,
                axon_endpoint: Some("2.2.2.2:8080".to_string()),
            },
            ValidatorInfo {
                uid: 3,
                hotkey: "val3".to_string(),
                stake: 1,
                axon_endpoint: Some("3.3.3.3:8080".to_string()),
            },
            ValidatorInfo {
                uid: 4,
                hotkey: "offline".to_string(),
                stake: 1,
                axon_endpoint: None, // Offline
            },
        ];

        let executors = vec![
            AvailableExecutor {
                id: "exec1".to_string(),
                name: "E1".to_string(),
                grpc_address: "".to_string(),
                resources: None,
                gpu_count: 1,
            },
            AvailableExecutor {
                id: "exec2".to_string(),
                name: "E2".to_string(),
                grpc_address: "".to_string(),
                resources: None,
                gpu_count: 1,
            },
        ];

        let strategy = HighestStakeAssignment::new(pool, 100.0, None);
        let assignments = strategy
            .assign_executors(validators, executors, &HashMap::new())
            .await;

        assert_eq!(assignments.len(), 1);
        assert_eq!(assignments["val1"], vec!["exec1", "exec2"]); // val1 has highest stake
        assert!(!assignments.contains_key("val2"));
        assert!(!assignments.contains_key("val3")); // Below threshold
        assert!(!assignments.contains_key("offline")); // No endpoint

        Ok(())
    }

    #[tokio::test]
    async fn test_highest_stake_assignment_no_stake_data() -> Result<()> {
        let pool = setup_test_db().await?;

        let validators = vec![ValidatorInfo {
            uid: 1,
            hotkey: "val1".to_string(),
            stake: 1,
            axon_endpoint: Some("1.1.1.1:8080".to_string()),
        }];

        let executors = vec![AvailableExecutor {
            id: "exec1".to_string(),
            name: "E1".to_string(),
            grpc_address: "".to_string(),
            resources: None,
            gpu_count: 1,
        }];

        let strategy = HighestStakeAssignment::new(pool, 100.0, None);
        let assignments = strategy
            .assign_executors(validators, executors, &HashMap::new())
            .await;

        assert_eq!(assignments.len(), 0);

        Ok(())
    }

    #[tokio::test]
    #[ignore] // Ignore by default as it requires network access and is just a config test
    async fn test_validator_discovery_with_manual_assignments() -> Result<()> {
        let pool = setup_test_db().await?;
        let assignment_db = AssignmentDb::new(pool.clone());

        // Create assignments
        assignment_db
            .create_assignment("exec-1", "validator-hotkey-1", "test", None)
            .await?;
        assignment_db
            .create_assignment("exec-2", "validator-hotkey-1", "test", None)
            .await?;
        assignment_db
            .create_assignment("exec-3", "validator-hotkey-2", "test", None)
            .await?;

        // Create test config with executors and skip_registration
        let mut config = create_test_config();
        config.executor_management.executors = vec![crate::config::ExecutorConfig {
            grpc_address: "127.0.0.1:50051".to_string(),
            host: "127.0.0.1".to_string(),
            port: 50051,
            ssh_port: 22,
            ssh_username: "testuser".to_string(),
            enabled: true,
            metadata: None,
        }];

        // Mock discovery with assignment database
        let discovery = ValidatorDiscovery {
            bittensor_service: Arc::new(
                bittensor::Service::new(config.bittensor.common.clone()).await?,
            ),
            executor_manager: Arc::new(
                ExecutorManager::new(&config, RegistrationDb::new(&Default::default()).await?)
                    .await?,
            ),
            assignment_strategy: Box::new(ManualAssignment::new(pool.clone())),
            assignments: Arc::new(RwLock::new(HashMap::new())),
            netuid: 12,
            assignment_db: Some(assignment_db),
        };

        // Test getting assignments for specific validator
        let assignments = discovery
            .get_validator_assignments("validator-hotkey-1")
            .await;

        assert!(assignments.is_some());
        let exec_ids = assignments.unwrap();
        assert_eq!(exec_ids.len(), 2);
        assert!(exec_ids.contains(&"exec-1".to_string()));
        assert!(exec_ids.contains(&"exec-2".to_string()));

        // Test validator with one assignment
        let assignments = discovery
            .get_validator_assignments("validator-hotkey-2")
            .await;

        assert!(assignments.is_some());
        let exec_ids = assignments.unwrap();
        assert_eq!(exec_ids.len(), 1);
        assert_eq!(exec_ids[0], "exec-3");

        // Test validator with no assignments
        let assignments = discovery
            .get_validator_assignments("validator-hotkey-3")
            .await;

        assert!(assignments.is_none());

        Ok(())
    }
}
