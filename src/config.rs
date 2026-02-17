use std::path::PathBuf;

pub struct Config {
    pub hf_token_path: PathBuf,
    pub threshold: f32,
    pub no_ml: bool,
}

impl Config {
    pub fn hf_token(&self) -> Option<String> {
        std::fs::read_to_string(&self.hf_token_path)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }
}
