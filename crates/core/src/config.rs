use std::path::PathBuf;

/// Runtime configuration for parry scanning.
#[derive(Debug, Clone)]
pub struct Config {
    pub hf_token_path: PathBuf,
    pub threshold: f32,
}

impl Config {
    /// Read the `HuggingFace` token from the configured path.
    #[must_use]
    pub fn hf_token(&self) -> Option<String> {
        std::fs::read_to_string(&self.hf_token_path)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            hf_token_path: PathBuf::from("/run/secrets/hf-token-scan-injection"),
            threshold: 0.5,
        }
    }
}
