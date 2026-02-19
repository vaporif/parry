//! `HuggingFace` model download/caching.

use eyre::WrapErr;
use parry_core::config::Config;
use parry_core::Result;

pub const MODEL_REPO: &str = "ProtectAI/deberta-v3-small-prompt-injection-v2";

/// Get a `HuggingFace` Hub repo handle for the injection detection model.
///
/// # Errors
///
/// Returns an error if the `HuggingFace` API client cannot be built.
pub fn hf_repo(config: &Config) -> Result<hf_hub::api::sync::ApiRepo> {
    use hf_hub::api::sync::ApiBuilder;

    let mut builder = ApiBuilder::new();
    if let Some(token) = config.hf_token() {
        builder = builder.with_token(Some(token));
    }
    let api = builder
        .build()
        .wrap_err("failed to build HuggingFace API client")?;

    Ok(api.model(MODEL_REPO.to_string()))
}
