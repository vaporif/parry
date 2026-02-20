//! Parry CLI - prompt injection scanner.

mod cli;

use clap::Parser;
use parry_core::Config;
use std::io::Read;
use std::process::ExitCode;
use std::time::Duration;
use tracing::{debug, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

fn init_tracing() {
    let filter = EnvFilter::try_from_env("PARRY_LOG").unwrap_or_else(|_| EnvFilter::new("warn"));
    fmt().with_env_filter(filter).init();
}

fn main() -> ExitCode {
    init_tracing();
    // Fail-closed: any panic exits with failure
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_hook(info);
        std::process::exit(1);
    }));

    let cli = cli::Cli::parse();

    let config = Config {
        hf_token_path: cli.hf_token_path,
        threshold: cli.threshold,
        no_daemon: cli.no_daemon,
        ml_backend: cli.ml_backend,
    };

    match cli.command {
        Some(cli::Command::Hook) => run_hook(&config),
        Some(cli::Command::Serve { idle_timeout }) => run_serve(&config, idle_timeout),
        Some(cli::Command::Scan) | None => run_scan(&config),
    }
}

fn run_scan(config: &Config) -> ExitCode {
    debug!("starting scan mode");
    let mut text = String::new();
    if std::io::stdin().read_to_string(&mut text).is_err() {
        warn!("failed to read stdin (fail-closed)");
        eprintln!("parry: failed to read stdin (fail-closed)");
        return ExitCode::FAILURE;
    }

    let text = text.trim();
    if text.is_empty() {
        debug!("empty input, skipping scan");
        return ExitCode::SUCCESS;
    }

    info!(text_len = text.len(), "scanning text");
    let result = parry_hook::scan_text(text, config);
    info!(?result, "scan complete");

    if result.is_clean() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn run_hook(config: &Config) -> ExitCode {
    debug!("starting hook mode");
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        warn!("failed to read stdin (fail-closed)");
        eprintln!("parry: failed to read stdin (fail-closed)");
        return ExitCode::FAILURE;
    }

    let input = input.trim();
    if input.is_empty() {
        debug!("empty hook input, skipping");
        return ExitCode::SUCCESS;
    }

    let hook_input: parry_hook::HookInput = match serde_json::from_str(input) {
        Ok(v) => v,
        Err(e) => {
            warn!(%e, "invalid hook JSON (fail-closed)");
            eprintln!("parry: invalid hook JSON: {e} (fail-closed)");
            return ExitCode::FAILURE;
        }
    };

    debug!(tool = %hook_input.tool_name, "processing hook");

    // Auto-detect: tool_response present → PostToolUse, absent → PreToolUse
    if hook_input.tool_response.is_some() {
        debug!("detected PostToolUse hook");
        if let Some(output) = parry_hook::post_tool_use::process(&hook_input, config) {
            info!(tool = %hook_input.tool_name, "threat detected in tool output");
            match serde_json::to_string(&output) {
                Ok(json) => println!("{json}"),
                Err(e) => eprintln!("parry: failed to serialize hook output: {e}"),
            }
        }
    } else {
        debug!("detected PreToolUse hook");
        if let Some(output) = parry_hook::pre_tool_use::process(&hook_input) {
            info!(tool = %hook_input.tool_name, "tool blocked by PreToolUse");
            match serde_json::to_string(&output) {
                Ok(json) => println!("{json}"),
                Err(e) => eprintln!("parry: failed to serialize hook output: {e}"),
            }
        }
    }

    ExitCode::SUCCESS // hooks always exit clean
}

fn run_serve(config: &Config, idle_timeout: u64) -> ExitCode {
    info!(idle_timeout, "starting daemon server");
    let daemon_config = parry_daemon::DaemonConfig {
        idle_timeout: Duration::from_secs(idle_timeout),
    };

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            warn!(%e, "failed to build tokio runtime");
            eprintln!("runtime error: {e}");
            return ExitCode::FAILURE;
        }
    };

    match rt.block_on(parry_daemon::run(config, &daemon_config)) {
        Ok(()) => {
            info!("daemon shutdown cleanly");
            ExitCode::SUCCESS
        }
        Err(e) => {
            warn!(%e, "daemon error");
            eprintln!("daemon error: {e}");
            ExitCode::FAILURE
        }
    }
}
