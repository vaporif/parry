use std::path::PathBuf;

#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum MlBackendKind {
    #[default]
    Auto,
    Onnx,
    Candle,
}

pub struct Config {
    pub hf_token_path: PathBuf,
    pub threshold: f32,
    pub no_daemon: bool,
    pub ml_backend: MlBackendKind,
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
