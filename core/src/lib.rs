//! Core traits and types for `mcp-warden`.
//!
//! This crate exposes the trait surfaces that pluggable implementations
//! (open-source or commercial) hook into. The `mcp-warden` binary crate
//! ships one implementation per trait; additional implementations attach
//! here without modifying or weakening the existing ones.
//!
//! See the project's `BUSINESS.md` for the open-core commitment.

pub mod approval;
pub mod audit;
pub mod config;
pub mod error;
pub mod keychain;
pub mod presets;
pub mod secret;
