/// Runtime configuration for parry scanning.
#[derive(Debug, Clone)]
pub struct Config {
    pub hf_token: Option<String>,
    pub threshold: f32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            hf_token: None,
            threshold: 0.5,
        }
    }
}
