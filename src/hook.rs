pub mod post_tool_use;
pub mod pre_tool_use;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct HookInput {
    pub tool_name: String,
    pub tool_input: serde_json::Value,
    pub tool_response: Option<String>,
    pub session_id: Option<String>,
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
    #[must_use]
    pub fn warning(message: &str) -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PostToolUse".to_string(),
                additional_context: message.to_string(),
            },
        }
    }
}

#[derive(Debug, Serialize)]
pub struct PreToolUseOutput {
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: PreToolUseSpecificOutput,
}

#[derive(Debug, Serialize)]
pub struct PreToolUseSpecificOutput {
    #[serde(rename = "hookEventName")]
    pub hook_event_name: String,
    #[serde(rename = "permissionDecision")]
    pub permission_decision: String,
    #[serde(rename = "permissionDecisionReason")]
    pub permission_decision_reason: String,
}

impl PreToolUseOutput {
    #[must_use]
    pub fn deny(reason: &str) -> Self {
        Self {
            hook_specific_output: PreToolUseSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "deny".to_string(),
                permission_decision_reason: reason.to_string(),
            },
        }
    }
}
