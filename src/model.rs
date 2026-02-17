use crate::config::Config;
use crate::error::Result;
use eyre::WrapErr;

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
        .wrap_err("failed to build HuggingFace API client")?;

    let repo = api.model(MODEL_REPO.to_string());

    let model_path = repo.get(MODEL_FILE).wrap_err("model download failed")?;

    let tokenizer_path = repo
        .get(TOKENIZER_FILE)
        .wrap_err("tokenizer download failed")?;

    Ok(ModelPaths {
        model: model_path.to_string_lossy().into_owned(),
        tokenizer: tokenizer_path.to_string_lossy().into_owned(),
    })
}
