/// Runtime configuration for parry scanning.
#[derive(Debug, Clone)]
pub struct Config {
    pub hf_token: Option<String>,
    pub threshold: f32,
    pub ignore_paths: Vec<String>,
}

impl Config {
    /// Check if the given path should be ignored (prefix match against `ignore_paths`).
    #[must_use]
    pub fn is_ignored(&self, path: &str) -> bool {
        self.ignore_paths
            .iter()
            .any(|ignored| path.starts_with(ignored))
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            hf_token: None,
            threshold: 0.5,
            ignore_paths: Vec::new(),
        }
    }
}
