//! CLI argument parsing.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

fn threshold_in_range(s: &str) -> Result<f32, String> {
    let val: f32 = s.parse().map_err(|e| format!("{e}"))?;
    if (0.0..=1.0).contains(&val) {
        Ok(val)
    } else {
        Err(format!("threshold must be between 0.0 and 1.0, got {val}"))
    }
}

#[derive(Parser)]
#[command(name = "parry", about = "Prompt injection scanner")]
pub struct Cli {
    /// `HuggingFace` token (direct value)
    #[arg(long, env = "HF_TOKEN")]
    pub hf_token: Option<String>,

    /// Path to `HuggingFace` token file
    #[arg(long, env = "HF_TOKEN_PATH")]
    pub hf_token_path: Option<PathBuf>,

    /// ML detection threshold (0.0–1.0)
    #[arg(long, env = "PARRY_THRESHOLD", default_value = "0.5",
          value_parser = threshold_in_range)]
    pub threshold: f32,

    #[command(subcommand)]
    pub command: Option<Command>,
}

impl Cli {
    /// Resolve the HF token from `--hf-token`, `--hf-token-path`, or default paths.
    #[must_use]
    pub fn resolve_hf_token(&self) -> Option<String> {
        // 1. Direct token value (--hf-token or HF_TOKEN env)
        if let Some(ref token) = self.hf_token {
            let trimmed = token.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }

        // 2. Token file (--hf-token-path or HF_TOKEN_PATH env)
        if let Some(ref path) = self.hf_token_path {
            if let Some(token) = read_token_file(path) {
                return Some(token);
            }
        }

        // 3. Default file path
        read_token_file("/run/secrets/hf-token-scan-injection".as_ref())
    }
}

fn read_token_file(path: &std::path::Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[derive(Subcommand)]
pub enum Command {
    /// Read stdin text, exit 1 if injection detected, 0 if clean
    Scan,
    /// `PostToolUse` hook mode (JSON stdin → JSON stdout)
    Hook,
    /// Run as a daemon with the ML model loaded in memory
    Serve {
        /// Idle timeout in seconds before the daemon shuts down
        #[arg(long, default_value = "1800")]
        idle_timeout: u64,
    },
    /// Scan only files changed since a git ref (commit, branch, tag)
    Diff {
        /// Git ref to compare against (e.g., main, HEAD~5, abc123)
        #[arg(name = "REF")]
        git_ref: String,
        /// Only scan specific file extensions (comma-separated, e.g., "md,txt,py")
        #[arg(long, short = 'e')]
        extensions: Option<String>,
        /// Run full ML scan (slow). Default is fast scan only (patterns + unicode + secrets)
        #[arg(long)]
        full: bool,
    },
}
