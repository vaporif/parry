//! Daemon client for IPC communication.

use std::time::Duration;

use parry_core::{Config, ScanError, ScanResult};
use tracing::{debug, info, trace};

use crate::protocol::{self, ScanRequest, ScanResponse, ScanType};
use crate::transport::Stream;

/// Connection timeout for daemon IPC.
const CONNECT_TIMEOUT: Duration = Duration::from_millis(50);

/// Run a full scan (with ML) via the daemon.
///
/// # Errors
///
/// Returns `ScanError::DaemonIo` if the daemon is unreachable.
pub fn scan_full(text: &str, config: &Config) -> Result<ScanResult, ScanError> {
    debug!(text_len = text.len(), "attempting full scan via daemon");
    let req = ScanRequest {
        scan_type: ScanType::Full,
        threshold: config.threshold,
        text: text.to_string(),
    };
    send_request(&req)
}

/// Check if a daemon is running by sending a ping.
#[must_use]
pub fn is_daemon_running() -> bool {
    trace!("checking if daemon is running");
    let Ok(mut stream) = Stream::connect(CONNECT_TIMEOUT) else {
        trace!("daemon not running (connection failed)");
        return false;
    };

    let req = ScanRequest {
        scan_type: ScanType::Ping,
        threshold: 0.0,
        text: String::new(),
    };

    if protocol::write_request(&mut stream, &req).is_err() {
        trace!("daemon not running (write failed)");
        return false;
    }

    let running = matches!(protocol::read_response(&mut stream), Ok(ScanResponse::Pong));
    trace!(running, "daemon running check complete");
    running
}

/// Spawn the daemon as a detached background process. Fire-and-forget.
pub fn spawn_daemon(config: &Config) {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };

    let mut cmd = std::process::Command::new(exe);
    cmd.arg("serve");

    // Forward config
    cmd.arg("--threshold").arg(config.threshold.to_string());

    if let Some(ref token) = config.hf_token {
        cmd.arg("--hf-token").arg(token);
    }

    // Detach: null stdio, don't wait
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    // On unix, use process group detach
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    let _ = cmd.spawn();
}

/// Ensure the daemon is running. Spawns it if needed and waits for readiness.
///
/// # Errors
///
/// Returns `ScanError::DaemonStart` if the daemon fails to start within the timeout.
pub fn ensure_running(config: &Config) -> Result<(), ScanError> {
    if is_daemon_running() {
        return Ok(());
    }
    info!("daemon not running, starting...");
    spawn_daemon(config);
    for delay_ms in [100, 200, 500, 1000, 2000] {
        std::thread::sleep(Duration::from_millis(delay_ms));
        if is_daemon_running() {
            info!("daemon ready");
            return Ok(());
        }
    }
    Err(ScanError::DaemonStart(
        "timed out waiting for daemon".into(),
    ))
}

fn send_request(req: &ScanRequest) -> Result<ScanResult, ScanError> {
    let mut stream = Stream::connect(CONNECT_TIMEOUT)?;
    protocol::write_request(&mut stream, req)?;
    let resp = protocol::read_response(&mut stream)?;
    Ok(response_to_scan_result(resp))
}

const fn response_to_scan_result(resp: ScanResponse) -> ScanResult {
    match resp {
        ScanResponse::Clean | ScanResponse::Pong => ScanResult::Clean,
        ScanResponse::Injection => ScanResult::Injection,
        ScanResponse::Secret => ScanResult::Secret,
    }
}
