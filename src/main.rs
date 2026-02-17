mod cli;

use clap::Parser;
use parry_cli::config::Config;
use parry_cli::hook;
use parry_cli::scan;
use std::io::Read;
use std::process;

fn main() {
    // Fail-open: any panic exits 0 (clean)
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_hook(info);
        process::exit(0);
    }));

    let cli = cli::Cli::parse();

    let config = Config {
        hf_token_path: cli.hf_token_path,
        threshold: cli.threshold,
        no_ml: cli.no_ml || cfg!(not(feature = "ml")),
    };

    let exit_code = match cli.command {
        Some(cli::Command::Hook) => run_hook(&config),
        Some(cli::Command::Scan) | None => run_scan(&config),
    };

    process::exit(exit_code);
}

fn run_scan(config: &Config) -> i32 {
    let mut text = String::new();
    if std::io::stdin().read_to_string(&mut text).is_err() {
        return 0; // fail-open
    }

    let text = text.trim();
    if text.is_empty() {
        return 0;
    }

    if scan::scan_text(text, config).is_injection() {
        1
    } else {
        0
    }
}

fn run_hook(config: &Config) -> i32 {
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        return 0; // fail-open
    }

    let input = input.trim();
    if input.is_empty() {
        return 0;
    }

    let hook_input: hook::HookInput = match serde_json::from_str(input) {
        Ok(v) => v,
        Err(_) => return 0, // fail-open on bad JSON
    };

    if let Some(output) = hook::post_tool_use::process(&hook_input, config) {
        if let Ok(json) = serde_json::to_string(&output) {
            println!("{json}");
        }
    }

    0 // hooks always exit 0
}
