#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[cfg(feature = "ml")]
    #[error("ONNX runtime error: {0}")]
    Ort(#[from] ort::Error),

    #[cfg(feature = "ml")]
    #[error("Tokenizer error: {0}")]
    Tokenizer(Box<dyn std::error::Error + Send + Sync>),

    #[error("Model not available: {0}")]
    ModelNotAvailable(String),
}

#[cfg(feature = "ml")]
impl From<Box<dyn std::error::Error + Send + Sync>> for Error {
    fn from(e: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Error::Tokenizer(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
