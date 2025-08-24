//! # Basilica CLI
//!
//! Unified command-line interface for Basilica GPU rental and network management.
//!
//! This crate provides a comprehensive CLI that combines:
//! - GPU rental operations (ls, up, down, exec, ssh, etc.)
//! - Network component management (validator, miner, executor)
//! - Configuration and wallet management
//!
//! ## Architecture
//!
//! The CLI follows the same patterns as other Basilica components:
//! - Clap-based argument parsing with derive macros
//! - Handler-based command processing
//! - Shared configuration and error handling
//! - Integration with existing basilica-common utilities

pub mod auth;
pub mod cache;
pub mod cli;
pub mod client;
pub mod config;
pub mod error;
// pub mod interactive; // Temporarily disabled - will re-enable with proper interactive selection
pub mod output;
pub mod progress;
pub mod ssh;
pub mod wallet;

pub use cli::*;
pub use error::*;
