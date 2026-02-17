use std::time::Duration;

use crate::config::Config;
use crate::daemon::protocol::{self, ScanRequest, ScanResponse, ScanType};
use crate::daemon::transport::Stream;
use crate::scan::ScanResult;

/// Connection timeout for daemon IPC.
const CONNECT_TIMEOUT: Duration = Duration::from_millis(50);

/// Try a full scan (with ML) via the daemon. Returns `None` if daemon unavailable.
#[must_use]
pub fn try_scan_full(text: &str, config: &Config) -> Option<ScanResult> {
    let req = ScanRequest {
        scan_type: ScanType::Full,
        threshold: config.threshold,
        text: text.to_string(),
    };
    send_request(&req)
}

/// Try a fast scan (no ML) via the daemon. Returns `None` if daemon unavailable.
#[must_use]
pub fn try_scan_fast(text: &str) -> Option<ScanResult> {
    let req = ScanRequest {
        scan_type: ScanType::Fast,
        threshold: 0.0,
        text: text.to_string(),
    };
    send_request(&req)
}

/// Check if a daemon is running by sending a ping.
#[must_use]
pub fn is_daemon_running() -> bool {
    let Ok(mut stream) = Stream::connect(CONNECT_TIMEOUT) else {
        return false;
    };

    let req = ScanRequest {
        scan_type: ScanType::Ping,
        threshold: 0.0,
        text: String::new(),
    };

    if protocol::write_request(&mut stream, &req).is_err() {
        return false;
    }

    matches!(protocol::read_response(&mut stream), Ok(ScanResponse::Pong))
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

    if config.hf_token_path.exists() {
        cmd.arg("--hf-token-path").arg(&config.hf_token_path);
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

fn send_request(req: &ScanRequest) -> Option<ScanResult> {
    let mut stream = Stream::connect(CONNECT_TIMEOUT).ok()?;
    protocol::write_request(&mut stream, req).ok()?;
    let resp = protocol::read_response(&mut stream).ok()?;
    Some(response_to_scan_result(resp))
}

const fn response_to_scan_result(resp: ScanResponse) -> ScanResult {
    match resp {
        ScanResponse::Clean | ScanResponse::Pong => ScanResult::Clean,
        ScanResponse::Injection => ScanResult::Injection,
        ScanResponse::Secret => ScanResult::Secret,
    }
}
