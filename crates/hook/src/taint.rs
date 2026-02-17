//! Project taint tracking.

use std::path::PathBuf;

const TAINT_FILE: &str = ".parry-tainted";

fn taint_file() -> Option<PathBuf> {
    parry_core::runtime_path(TAINT_FILE)
}

/// Mark the current project as tainted with context about what triggered it. Fail-silent.
pub fn mark(tool_name: &str, session_id: Option<&str>) {
    use std::fmt::Write;
    let Some(path) = taint_file() else { return };
    let mut context = format!("tool: {tool_name}");
    if let Some(sid) = session_id {
        let _ = write!(context, "\nsession: {sid}");
    }
    if let Err(e) = std::fs::write(&path, context) {
        tracing::warn!(path = %path.display(), %e, "failed to write taint file");
    }
}

/// Check if the current project is tainted.
#[must_use]
pub fn is_tainted() -> bool {
    taint_file().is_some_and(|p| p.exists())
}

/// Read the taint context (tool, session) if the project is tainted.
#[must_use]
pub fn read_context() -> Option<String> {
    let path = taint_file()?;
    std::fs::read_to_string(&path)
        .ok()
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::EnvGuard;

    #[test]
    fn mark_and_check() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::new(dir.path());
        mark("TestTool", Some("test-session"));
        assert!(is_tainted());
    }

    #[test]
    fn clean_project() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::new(dir.path());
        assert!(!is_tainted());
    }

    #[test]
    fn manual_removal_clears_taint() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::new(dir.path());
        mark("TestTool", Some("test-session"));
        assert!(is_tainted());
        let path = taint_file().unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(!is_tainted());
    }

    #[test]
    fn context_includes_tool_and_session() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::new(dir.path());
        mark("WebFetch", Some("sess-abc"));
        let ctx = read_context().unwrap();
        assert!(ctx.contains("WebFetch"), "context should include tool name");
        assert!(
            ctx.contains("sess-abc"),
            "context should include session id"
        );
    }

    #[test]
    fn context_without_session() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::new(dir.path());
        mark("Read", None);
        let ctx = read_context().unwrap();
        assert!(ctx.contains("Read"));
        assert!(!ctx.contains("session:"));
    }
}
