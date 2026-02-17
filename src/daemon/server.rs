use std::time::{Duration, Instant};

use crate::config::Config;
use crate::daemon::protocol::{self, ScanRequest, ScanResponse, ScanType};
use crate::daemon::transport::{self, Listener, Stream};
use crate::scan;

const POLL_INTERVAL: Duration = Duration::from_millis(100);

pub struct DaemonConfig {
    pub idle_timeout: Duration,
}

/// Run the daemon server. Loads the ML model once and serves scan requests.
///
/// # Errors
///
/// Returns an error if another daemon is running or the socket cannot be bound.
pub fn run(config: &Config, daemon_config: &DaemonConfig) -> eyre::Result<()> {
    // Check for existing daemon
    if crate::daemon::client::is_daemon_running() {
        return Err(eyre::eyre!("another daemon is already running"));
    }

    let listener = Listener::bind()?;

    // Write PID file
    let pid_path = transport::pid_file_path()?;
    std::fs::write(&pid_path, std::process::id().to_string())?;

    // Load ML model (fail-open: None if unavailable)
    let mut ml_scanner = load_ml_scanner(config);

    eprintln!(
        "parry daemon started (pid={}, ml={})",
        std::process::id(),
        if ml_scanner.is_some() {
            "loaded"
        } else {
            "unavailable"
        }
    );

    let mut last_activity = Instant::now();

    loop {
        if last_activity.elapsed() >= daemon_config.idle_timeout {
            eprintln!("parry daemon idle timeout, shutting down");
            break;
        }

        match listener.try_accept() {
            Ok(Some(stream)) => {
                last_activity = Instant::now();
                handle_connection(stream, config, ml_scanner.as_mut());
            }
            Ok(None) => {
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(e) => {
                eprintln!("accept error: {e}");
                std::thread::sleep(POLL_INTERVAL);
            }
        }
    }

    // Cleanup (socket is auto-reclaimed on listener drop)
    drop(listener);
    let _ = std::fs::remove_file(&pid_path);

    Ok(())
}

fn load_ml_scanner(config: &Config) -> Option<scan::ml::MlScanner> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let paths = crate::model::ensure_model(config).ok()?;
        scan::ml::MlScanner::new(&paths.model, &paths.tokenizer, config.threshold).ok()
    }));
    result.unwrap_or(None)
}

fn handle_connection(
    mut stream: Stream,
    config: &Config,
    ml_scanner: Option<&mut scan::ml::MlScanner>,
) {
    let Ok(req) = protocol::read_request(&mut stream) else {
        return;
    };

    let resp = handle_request(&req, config, ml_scanner);

    let _ = protocol::write_response(&mut stream, resp);
}

fn handle_request(
    req: &ScanRequest,
    _config: &Config,
    ml_scanner: Option<&mut scan::ml::MlScanner>,
) -> ScanResponse {
    match req.scan_type {
        ScanType::Ping => ScanResponse::Pong,
        ScanType::Fast => scan_result_to_response(&scan::scan_text_fast(&req.text)),
        ScanType::Full => {
            // Fast scan first
            let fast = scan::scan_text_fast(&req.text);
            if !fast.is_clean() {
                return scan_result_to_response(&fast);
            }

            // ML scan if available
            if let Some(scanner) = ml_scanner {
                let stripped = scan::unicode::strip_invisible(&req.text);
                if matches!(scanner.scan_chunked(&stripped), Ok(true)) {
                    return ScanResponse::Injection;
                }
            }

            ScanResponse::Clean
        }
    }
}

const fn scan_result_to_response(result: &scan::ScanResult) -> ScanResponse {
    match result {
        scan::ScanResult::Injection => ScanResponse::Injection,
        scan::ScanResult::Secret => ScanResponse::Secret,
        scan::ScanResult::Clean => ScanResponse::Clean,
    }
}
