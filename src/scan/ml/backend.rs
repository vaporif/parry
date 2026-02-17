use crate::error::Result;

pub trait MlBackend {
    fn score(&mut self, input_ids: &[u32], attention_mask: &[u32]) -> Result<f32>;
}
