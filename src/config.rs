use std::path::PathBuf;

pub struct Config {
    pub hf_token_path: PathBuf,
    pub threshold: f32,
}

impl Config {
    #[must_use]
    pub fn hf_token(&self) -> Option<String> {
        std::fs::read_to_string(&self.hf_token_path)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }
}
