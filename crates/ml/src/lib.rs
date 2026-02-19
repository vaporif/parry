//! ML-based injection detection using `DeBERTa` v3.

// Ensure at least one ML backend is enabled
#[cfg(not(any(feature = "onnx", feature = "onnx-fetch", feature = "candle")))]
compile_error!(
    "At least one ML backend must be enabled: 'onnx', 'onnx-fetch' (default), or 'candle'"
);

pub mod backend;
pub mod chunker;
pub mod model;

#[cfg(feature = "candle")]
pub mod candle;
#[cfg(any(feature = "onnx", feature = "onnx-fetch"))]
pub mod onnx;

use backend::MlBackend;
use parry_core::config::{Config, MlBackendKind};
use parry_core::Result;
use tokenizers::Tokenizer;

pub struct MlScanner {
    backend: Box<dyn MlBackend>,
    tokenizer: Tokenizer,
    threshold: f32,
}

impl MlScanner {
    /// Load the ML scanner with the configured backend.
    ///
    /// # Errors
    ///
    /// Returns an error if the model cannot be downloaded or loaded.
    pub fn load(config: &Config) -> Result<Self> {
        let repo = model::hf_repo(config)?;

        let tokenizer_path = repo
            .get("tokenizer.json")
            .map_err(|e| eyre::eyre!("tokenizer download failed: {e}"))?;
        let tokenizer = Tokenizer::from_file(&tokenizer_path).map_err(|e| eyre::eyre!(e))?;

        let backend: Box<dyn MlBackend> = match config.ml_backend {
            MlBackendKind::Auto => load_auto_backend(&repo)?,
            MlBackendKind::Onnx => load_onnx_backend(&repo)?,
            MlBackendKind::Candle => load_candle_backend(&repo)?,
        };

        Ok(Self {
            backend,
            tokenizer,
            threshold: config.threshold,
        })
    }

    fn score(&mut self, text: &str) -> Result<f32> {
        let encoding = self
            .tokenizer
            .encode(text, true)
            .map_err(|e| eyre::eyre!(e))?;

        self.backend
            .score(encoding.get_ids(), encoding.get_attention_mask())
    }

    /// Scan text using chunked strategy. Returns true if injection detected.
    ///
    /// # Errors
    ///
    /// Returns an error if scoring any chunk fails.
    pub fn scan_chunked(&mut self, text: &str) -> Result<bool> {
        for chunk in chunker::chunks(text) {
            if self.score(chunk)? >= self.threshold {
                return Ok(true);
            }
        }

        if let Some((head_tail, _)) = chunker::head_tail(text) {
            if self.score(&head_tail)? >= self.threshold {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

#[allow(clippy::needless_return, unused_variables)]
fn load_auto_backend(repo: &hf_hub::api::sync::ApiRepo) -> Result<Box<dyn MlBackend>> {
    #[cfg(feature = "candle")]
    return load_candle_backend(repo);

    #[cfg(all(any(feature = "onnx", feature = "onnx-fetch"), not(feature = "candle")))]
    return load_onnx_backend(repo);

    #[cfg(not(any(feature = "onnx", feature = "onnx-fetch", feature = "candle")))]
    return Err(eyre::eyre!("no ML backend compiled in"));
}

#[cfg(any(feature = "onnx", feature = "onnx-fetch"))]
fn load_onnx_backend(repo: &hf_hub::api::sync::ApiRepo) -> Result<Box<dyn MlBackend>> {
    let model_path = repo
        .get("onnx/model.onnx")
        .map_err(|e| eyre::eyre!("model download failed: {e}"))?;
    Ok(Box::new(onnx::OnnxBackend::load(
        &model_path.to_string_lossy(),
    )?))
}

#[cfg(not(any(feature = "onnx", feature = "onnx-fetch")))]
fn load_onnx_backend(_repo: &hf_hub::api::sync::ApiRepo) -> Result<Box<dyn MlBackend>> {
    Err(eyre::eyre!(
        "onnx backend not compiled in (enable 'onnx' or 'onnx-fetch' feature)"
    ))
}

#[cfg(feature = "candle")]
fn load_candle_backend(repo: &hf_hub::api::sync::ApiRepo) -> Result<Box<dyn MlBackend>> {
    let safetensors_path = repo
        .get("model.safetensors")
        .map_err(|e| eyre::eyre!("safetensors download failed: {e}"))?;
    let config_path = repo
        .get("config.json")
        .map_err(|e| eyre::eyre!("config download failed: {e}"))?;
    Ok(Box::new(candle::CandleBackend::load(
        &safetensors_path.to_string_lossy(),
        &config_path.to_string_lossy(),
    )?))
}

#[cfg(not(feature = "candle"))]
fn load_candle_backend(_repo: &hf_hub::api::sync::ApiRepo) -> Result<Box<dyn MlBackend>> {
    Err(eyre::eyre!(
        "candle backend not compiled in (enable 'candle' feature)"
    ))
}

#[cfg(any(feature = "onnx", feature = "onnx-fetch", feature = "candle", test))]
pub(crate) fn softmax_injection_prob(logits: &[f32]) -> f32 {
    if logits.len() < 2 {
        return 0.0;
    }
    let max = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let exps: Vec<f32> = logits.iter().map(|&l| (l - max).exp()).collect();
    let sum: f32 = exps.iter().sum();
    exps[1] / sum // label 1 = INJECTION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn softmax_basic() {
        let logits = [2.0, 1.0];
        let prob = softmax_injection_prob(&logits);
        assert!(prob > 0.0 && prob < 1.0);
        assert!(prob < 0.5); // logit[0] > logit[1] means injection prob < 0.5
    }

    #[test]
    fn softmax_injection_dominant() {
        let logits = [0.0, 5.0];
        let prob = softmax_injection_prob(&logits);
        assert!(prob > 0.9);
    }
}
