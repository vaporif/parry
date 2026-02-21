//! Async daemon server.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use interprocess::local_socket::traits::tokio::Listener as _;
use tokio::time::Instant;
use tokio_util::codec::Framed;
use tracing::{debug, info, instrument, warn};

use parry_core::{Config, ScanResult};
use parry_ml::MlScanner;

use crate::protocol::{DaemonCodec, ScanRequest, ScanResponse, ScanType};
use crate::scan_cache::{self, ScanCache};
use crate::transport;

pub struct DaemonConfig {
    pub idle_timeout: Duration,
}

/// Run the daemon server. Loads the ML model once and serves scan requests.
///
/// # Errors
///
/// Returns an error if another daemon is running or the socket cannot be bound.
#[instrument(skip(config, daemon_config), fields(idle_timeout = ?daemon_config.idle_timeout))]
pub async fn run(config: &Config, daemon_config: &DaemonConfig) -> eyre::Result<()> {
    if crate::client::is_daemon_running() {
        warn!("another daemon is already running");
        return Err(eyre::eyre!("another daemon is already running"));
    }

    let listener = transport::bind_async()?;

    let pid_path = transport::pid_file_path()?;
    std::fs::write(&pid_path, std::process::id().to_string())?;

    let mut ml_scanner = load_ml_scanner(config);
    let cache = ScanCache::open().map(Arc::new);

    let ml_status = if ml_scanner.is_some() {
        "loaded"
    } else {
        "unavailable"
    };
    let cache_status = if cache.is_some() { "loaded" } else { "off" };
    info!(pid = std::process::id(), ml = ml_status, cache = cache_status, "daemon started");

    if let Some(ref c) = cache {
        let c = Arc::clone(c);
        tokio::spawn(async move { scan_cache::prune_task(&c).await });
    }

    let idle_timeout = daemon_config.idle_timeout;
    let mut deadline = Instant::now() + idle_timeout;

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok(stream) => {
                        debug!("accepted connection");
                        handle_connection(stream, &mut ml_scanner, cache.as_deref()).await;
                        deadline = Instant::now() + idle_timeout;
                    }
                    Err(e) => {
                        warn!(%e, "accept error");
                    }
                }
            }
            () = tokio::time::sleep_until(deadline) => {
                info!("idle timeout, shutting down");
                break;
            }
        }
    }

    drop(listener);
    let _ = std::fs::remove_file(&pid_path);

    Ok(())
}

fn load_ml_scanner(config: &Config) -> Option<MlScanner> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| MlScanner::load(config))) {
        Ok(Ok(scanner)) => Some(scanner),
        Ok(Err(e)) => {
            warn!(%e, "ML scanner failed to load");
            None
        }
        Err(_) => {
            warn!("ML scanner panicked during load");
            None
        }
    }
}

async fn handle_connection(
    stream: interprocess::local_socket::tokio::Stream,
    ml_scanner: &mut Option<MlScanner>,
    cache: Option<&ScanCache>,
) {
    let mut framed = Framed::new(stream, DaemonCodec);

    let Some(Ok(req)) = framed.next().await else {
        return;
    };

    let resp = handle_request(&req, ml_scanner, cache);
    let _ = framed.send(resp).await;
}

fn handle_request(
    req: &ScanRequest,
    ml_scanner: &mut Option<MlScanner>,
    cache: Option<&ScanCache>,
) -> ScanResponse {
    debug!(scan_type = ?req.scan_type, text_len = req.text.len(), "handling request");
    match req.scan_type {
        ScanType::Ping => ScanResponse::Pong,
        ScanType::Fast => {
            let result = parry_core::scan_text_fast(&req.text);
            debug!(?result, "fast scan complete");
            scan_result_to_response(result)
        }
        ScanType::Full => {
            if let Some(c) = cache {
                let hash = scan_cache::hash_content(&req.text);

                if let Some(cached) = c.get(hash) {
                    debug!(?cached, "cache hit");
                    return scan_result_to_response(cached);
                }

                let result = run_full_scan(&req.text, ml_scanner);
                c.put(hash, response_to_result(result));
                result
            } else {
                run_full_scan(&req.text, ml_scanner)
            }
        }
    }
}

fn run_full_scan(text: &str, ml_scanner: &mut Option<MlScanner>) -> ScanResponse {
    let fast = parry_core::scan_text_fast(text);
    if !fast.is_clean() {
        debug!(?fast, "fast scan detected issue");
        return scan_result_to_response(fast);
    }

    if let Some(scanner) = ml_scanner {
        let stripped = parry_core::unicode::strip_invisible(text);
        match scanner.scan_chunked(&stripped) {
            Ok(false) => {
                debug!("ML scan clean");
            }
            Ok(true) => {
                debug!("ML scan detected injection");
                return ScanResponse::Injection;
            }
            Err(e) => {
                warn!(%e, "ML scan error, treating as injection (fail-closed)");
                return ScanResponse::Injection;
            }
        }
    }

    ScanResponse::Clean
}

const fn response_to_result(resp: ScanResponse) -> ScanResult {
    match resp {
        ScanResponse::Injection => ScanResult::Injection,
        ScanResponse::Secret => ScanResult::Secret,
        ScanResponse::Clean | ScanResponse::Pong => ScanResult::Clean,
    }
}

const fn scan_result_to_response(result: ScanResult) -> ScanResponse {
    match result {
        ScanResult::Injection => ScanResponse::Injection,
        ScanResult::Secret => ScanResponse::Secret,
        ScanResult::Clean => ScanResponse::Clean,
    }
}
