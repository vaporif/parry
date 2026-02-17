use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "parry", about = "Prompt injection scanner")]
pub struct Cli {
    /// Path to HuggingFace token file
    #[arg(
        long,
        env = "CLAUDE_GUARD_HF_TOKEN_PATH",
        default_value = "/run/secrets/hf-token-scan-injection"
    )]
    pub hf_token_path: PathBuf,

    /// ML detection threshold (0.0–1.0)
    #[arg(long, env = "CLAUDE_GUARD_THRESHOLD", default_value = "0.5")]
    pub threshold: f32,

    /// Disable ML scanning (regex + unicode only)
    #[arg(long, env = "CLAUDE_GUARD_NO_ML")]
    pub no_ml: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Read stdin text, exit 1 if injection detected, 0 if clean
    Scan,
    /// PostToolUse hook mode (JSON stdin → JSON stdout)
    Hook,
}
