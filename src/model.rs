use crate::config::Config;
use crate::error::{Error, Result};

const MODEL_REPO: &str = "ProtectAI/deberta-v3-small-prompt-injection-v2";
const MODEL_FILE: &str = "onnx/model.onnx";
const TOKENIZER_FILE: &str = "tokenizer.json";

pub struct ModelPaths {
    pub model: String,
    pub tokenizer: String,
}

/// Download or locate the ONNX model and tokenizer files.
///
/// # Errors
///
/// Returns an error if the `HuggingFace` API client cannot be built or
/// model/tokenizer files cannot be downloaded.
pub fn ensure_model(config: &Config) -> Result<ModelPaths> {
    use hf_hub::api::sync::ApiBuilder;

    let mut builder = ApiBuilder::new();
    if let Some(token) = config.hf_token() {
        builder = builder.with_token(Some(token));
    }
    let api = builder
        .build()
        .map_err(|e| Error::ModelNotAvailable(e.to_string()))?;

    let repo = api.model(MODEL_REPO.to_string());

    let model_path = repo
        .get(MODEL_FILE)
        .map_err(|e| Error::ModelNotAvailable(format!("model download failed: {e}")))?;

    let tokenizer_path = repo
        .get(TOKENIZER_FILE)
        .map_err(|e| Error::ModelNotAvailable(format!("tokenizer download failed: {e}")))?;

    Ok(ModelPaths {
        model: model_path.to_string_lossy().into_owned(),
        tokenizer: tokenizer_path.to_string_lossy().into_owned(),
    })
}
