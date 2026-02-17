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
use parry_core::config::Config;
use parry_core::Result;
use tokenizers::Tokenizer;
use tracing::{debug, info, instrument};

/// Concrete backend type selected at compile time.
#[cfg(feature = "candle")]
type Backend = candle::CandleBackend;
#[cfg(all(any(feature = "onnx", feature = "onnx-fetch"), not(feature = "candle")))]
type Backend = onnx::OnnxBackend;

/// ML scanner parameterized by backend.
pub type MlScanner = Scanner<Backend>;

pub struct Scanner<B: MlBackend> {
    backend: B,
    tokenizer: Tokenizer,
    threshold: f32,
}

impl MlScanner {
    /// Load the ML scanner with the compile-time selected backend.
    ///
    /// # Errors
    ///
    /// Returns an error if the model cannot be downloaded or loaded.
    #[instrument(skip(config))]
    pub fn load(config: &Config) -> Result<Self> {
        debug!("loading ML scanner");
        let repo = model::hf_repo(config)?;

        let tokenizer_path = repo
            .get("tokenizer.json")
            .map_err(|e| eyre::eyre!("tokenizer download failed: {e}"))?;
        let tokenizer = Tokenizer::from_file(&tokenizer_path).map_err(|e| eyre::eyre!(e))?;
        debug!("tokenizer loaded");

        let backend = load_backend(&repo)?;
        info!("ML backend initialized");

        Ok(Self {
            backend,
            tokenizer,
            threshold: config.threshold,
        })
    }
}

impl<B: MlBackend> Scanner<B> {
    fn score(&mut self, text: &str) -> Result<f32> {
        let encoding = self
            .tokenizer
            .encode(text, true)
            .map_err(|e| eyre::eyre!(e))?;

        let score = self
            .backend
            .score(encoding.get_ids(), encoding.get_attention_mask())?;
        debug!(score, text_len = text.len(), "chunk scored");
        Ok(score)
    }

    /// Update the detection threshold.
    pub const fn set_threshold(&mut self, threshold: f32) {
        self.threshold = threshold;
    }

    /// Scan text using chunked strategy. Returns true if injection detected.
    ///
    /// # Errors
    ///
    /// Returns an error if scoring any chunk fails.
    #[instrument(skip(self, text), fields(text_len = text.len(), threshold = self.threshold))]
    pub fn scan_chunked(&mut self, text: &str) -> Result<bool> {
        for chunk in chunker::chunks(text) {
            let score = self.score(chunk)?;
            if score >= self.threshold {
                debug!(score, "injection detected in chunk");
                return Ok(true);
            }
        }

        if let Some((head_tail, _)) = chunker::head_tail(text) {
            let score = self.score(&head_tail)?;
            if score >= self.threshold {
                debug!(score, "injection detected in head+tail");
                return Ok(true);
            }
        }

        debug!("ML scan clean");
        Ok(false)
    }
}

#[cfg(feature = "candle")]
fn load_backend(repo: &hf_hub::api::sync::ApiRepo) -> Result<Backend> {
    let safetensors_path = repo
        .get("model.safetensors")
        .map_err(|e| eyre::eyre!("safetensors download failed: {e}"))?;
    let config_path = repo
        .get("config.json")
        .map_err(|e| eyre::eyre!("config download failed: {e}"))?;
    candle::CandleBackend::load(
        &safetensors_path.to_string_lossy(),
        &config_path.to_string_lossy(),
    )
}

#[cfg(all(any(feature = "onnx", feature = "onnx-fetch"), not(feature = "candle")))]
fn load_backend(repo: &hf_hub::api::sync::ApiRepo) -> Result<Backend> {
    let model_path = repo
        .get("onnx/model.onnx")
        .map_err(|e| eyre::eyre!("model download failed: {e}"))?;
    onnx::OnnxBackend::load(&model_path.to_string_lossy())
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
