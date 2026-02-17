use crate::error::Result;

use ort::session::Session;
use ort::value::Tensor;
use tokenizers::Tokenizer;

pub struct MlScanner {
    session: Session,
    tokenizer: Tokenizer,
    threshold: f32,
}

impl MlScanner {
    /// # Errors
    ///
    /// Returns an error if the ONNX session or tokenizer cannot be loaded.
    pub fn new(model_path: &str, tokenizer_path: &str, threshold: f32) -> Result<Self> {
        let session = Session::builder()?.commit_from_file(model_path)?;
        let tokenizer = Tokenizer::from_file(tokenizer_path)?;

        Ok(Self {
            session,
            tokenizer,
            threshold,
        })
    }

    /// Score a single text chunk. Returns probability of injection (label 1).
    fn score(&mut self, text: &str) -> Result<f32> {
        let encoding = self.tokenizer.encode(text, true)?;

        let ids: Vec<i64> = encoding.get_ids().iter().map(|&id| i64::from(id)).collect();
        let mask: Vec<i64> = encoding
            .get_attention_mask()
            .iter()
            .map(|&m| i64::from(m))
            .collect();
        let len = ids.len();

        #[allow(clippy::cast_possible_wrap)]
        let shape = vec![1i64, len as i64];
        let input_ids = Tensor::from_array((shape.clone(), ids))?;
        let attention_mask = Tensor::from_array((shape, mask))?;

        let outputs = self.session.run(ort::inputs![input_ids, attention_mask])?;

        let logits_view = outputs[0].try_extract_array::<f32>()?;
        let logits = logits_view.as_slice().expect("contiguous logits tensor");

        Ok(softmax_injection_prob(logits))
    }

    /// Scan text using chunked strategy. Returns true if injection detected.
    ///
    /// # Errors
    ///
    /// Returns an error if scoring any chunk fails.
    pub fn scan_chunked(&mut self, text: &str) -> Result<bool> {
        use crate::scan::chunker;

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

fn softmax_injection_prob(logits: &[f32]) -> f32 {
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
