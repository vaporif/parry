mod cli;

use clap::Parser;
use parry_cli::config::Config;
use parry_cli::daemon;
use parry_cli::hook;
use parry_cli::scan;
use std::io::Read;
use std::process::ExitCode;
use std::time::Duration;

fn main() -> ExitCode {
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
    let mut text = String::new();
    if std::io::stdin().read_to_string(&mut text).is_err() {
        eprintln!("parry: failed to read stdin (fail-closed)");
        return ExitCode::FAILURE;
    }

    let text = text.trim();
    if text.is_empty() {
        return ExitCode::SUCCESS;
    }

    if scan::scan_text(text, config).is_clean() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn run_hook(config: &Config) -> ExitCode {
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        eprintln!("parry: failed to read stdin (fail-closed)");
        return ExitCode::FAILURE;
    }

    let input = input.trim();
    if input.is_empty() {
        return ExitCode::SUCCESS;
    }

    let hook_input: hook::HookInput = match serde_json::from_str(input) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("parry: invalid hook JSON: {e} (fail-closed)");
            return ExitCode::FAILURE;
        }
    };

    // Auto-detect: tool_response present → PostToolUse, absent → PreToolUse
    if hook_input.tool_response.is_some() {
        if let Some(output) = hook::post_tool_use::process(&hook_input, config) {
            match serde_json::to_string(&output) {
                Ok(json) => println!("{json}"),
                Err(e) => eprintln!("parry: failed to serialize hook output: {e}"),
            }
        }
    } else if let Some(output) = hook::pre_tool_use::process(&hook_input) {
        match serde_json::to_string(&output) {
            Ok(json) => println!("{json}"),
            Err(e) => eprintln!("parry: failed to serialize hook output: {e}"),
        }
    }

    ExitCode::SUCCESS // hooks always exit clean
}

fn run_serve(config: &Config, idle_timeout: u64) -> ExitCode {
    let daemon_config = daemon::server::DaemonConfig {
        idle_timeout: Duration::from_secs(idle_timeout),
    };

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("runtime error: {e}");
            return ExitCode::FAILURE;
        }
    };

    match rt.block_on(daemon::server::run(config, &daemon_config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("daemon error: {e}");
            ExitCode::FAILURE
        }
    }
}
