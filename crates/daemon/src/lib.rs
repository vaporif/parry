//! Async daemon for persistent ML model loading.
//!
//! The daemon keeps the ML model loaded in memory and serves scan requests
//! via IPC, avoiding repeated model loading overhead.

pub mod client;
pub mod protocol;
pub mod server;
pub mod transport;

pub use client::{is_daemon_running, spawn_daemon, try_scan_fast, try_scan_full};
pub use protocol::{ScanRequest, ScanResponse, ScanType};
pub use server::{run, DaemonConfig};
