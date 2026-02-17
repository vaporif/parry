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
    // Fail-open: any panic exits clean
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_hook(info);
        std::process::exit(0);
    }));

    let cli = cli::Cli::parse();

    let config = Config {
        hf_token_path: cli.hf_token_path,
        threshold: cli.threshold,
        no_daemon: cli.no_daemon,
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
        return ExitCode::SUCCESS; // fail-open
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
        return ExitCode::SUCCESS; // fail-open
    }

    let input = input.trim();
    if input.is_empty() {
        return ExitCode::SUCCESS;
    }

    let hook_input: hook::HookInput = match serde_json::from_str(input) {
        Ok(v) => v,
        Err(_) => return ExitCode::SUCCESS, // fail-open on bad JSON
    };

    if let Some(output) = hook::post_tool_use::process(&hook_input, config) {
        if let Ok(json) = serde_json::to_string(&output) {
            println!("{json}");
        }
    }

    ExitCode::SUCCESS // hooks always exit clean
}

fn run_serve(config: &Config, idle_timeout: u64) -> ExitCode {
    let daemon_config = daemon::server::DaemonConfig {
        idle_timeout: Duration::from_secs(idle_timeout),
    };

    let rt = match tokio::runtime::Builder::new_current_thread()
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
