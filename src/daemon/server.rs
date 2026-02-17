use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use interprocess::local_socket::traits::tokio::Listener as _;
use tokio::time::Instant;
use tokio_util::codec::Framed;

use crate::config::Config;
use crate::daemon::protocol::{DaemonCodec, ScanRequest, ScanResponse, ScanType};
use crate::daemon::transport;
use crate::scan;

pub struct DaemonConfig {
    pub idle_timeout: Duration,
}

/// Run the daemon server. Loads the ML model once and serves scan requests.
///
/// # Errors
///
/// Returns an error if another daemon is running or the socket cannot be bound.
pub async fn run(config: &Config, daemon_config: &DaemonConfig) -> eyre::Result<()> {
    if crate::daemon::client::is_daemon_running() {
        return Err(eyre::eyre!("another daemon is already running"));
    }

    let listener = transport::bind_async()?;

    let pid_path = transport::pid_file_path()?;
    std::fs::write(&pid_path, std::process::id().to_string())?;

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

    let idle_timeout = daemon_config.idle_timeout;
    let mut deadline = Instant::now() + idle_timeout;

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok(stream) => {
                        handle_connection(stream, &mut ml_scanner).await;
                        deadline = Instant::now() + idle_timeout;
                    }
                    Err(e) => eprintln!("accept error: {e}"),
                }
            }
            () = tokio::time::sleep_until(deadline) => {
                eprintln!("parry daemon idle timeout, shutting down");
                break;
            }
        }
    }

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

async fn handle_connection(
    stream: interprocess::local_socket::tokio::Stream,
    ml_scanner: &mut Option<scan::ml::MlScanner>,
) {
    let mut framed = Framed::new(stream, DaemonCodec);

    let Some(Ok(req)) = framed.next().await else {
        return;
    };

    let resp = handle_request(&req, ml_scanner);
    let _ = framed.send(resp).await;
}

fn handle_request(
    req: &ScanRequest,
    ml_scanner: &mut Option<scan::ml::MlScanner>,
) -> ScanResponse {
    match req.scan_type {
        ScanType::Ping => ScanResponse::Pong,
        ScanType::Fast => scan_result_to_response(&scan::scan_text_fast(&req.text)),
        ScanType::Full => {
            let fast = scan::scan_text_fast(&req.text);
            if !fast.is_clean() {
                return scan_result_to_response(&fast);
            }

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
