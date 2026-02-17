pub mod post_tool_use;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct HookInput {
    pub tool_name: String,
    pub tool_input: serde_json::Value,
    pub tool_response: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HookOutput {
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: HookSpecificOutput,
}

#[derive(Debug, Serialize)]
pub struct HookSpecificOutput {
    #[serde(rename = "hookEventName")]
    pub hook_event_name: String,
    #[serde(rename = "additionalContext")]
    pub additional_context: String,
}

impl HookOutput {
    pub fn warning(message: &str) -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PostToolUse".to_string(),
                additional_context: message.to_string(),
            },
        }
    }
}
