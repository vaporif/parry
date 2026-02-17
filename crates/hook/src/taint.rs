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

    fn setup_test_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("PARRY_RUNTIME_DIR", dir.path()) };
        dir
    }

    fn teardown() {
        unsafe { std::env::remove_var("PARRY_RUNTIME_DIR") };
    }

    #[test]
    fn mark_and_check() {
        let _dir = setup_test_dir();
        mark("TestTool", Some("test-session"));
        assert!(is_tainted());
        teardown();
    }

    #[test]
    fn clean_project() {
        let _dir = setup_test_dir();
        assert!(!is_tainted());
        teardown();
    }

    #[test]
    fn manual_removal_clears_taint() {
        let _dir = setup_test_dir();
        mark("TestTool", Some("test-session"));
        assert!(is_tainted());
        let path = taint_file().unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(!is_tainted());
        teardown();
    }

    #[test]
    fn context_includes_tool_and_session() {
        let _dir = setup_test_dir();
        mark("WebFetch", Some("sess-abc"));
        let ctx = read_context().unwrap();
        assert!(ctx.contains("WebFetch"), "context should include tool name");
        assert!(
            ctx.contains("sess-abc"),
            "context should include session id"
        );
        teardown();
    }

    #[test]
    fn context_without_session() {
        let _dir = setup_test_dir();
        mark("Read", None);
        let ctx = read_context().unwrap();
        assert!(ctx.contains("Read"));
        assert!(!ctx.contains("session:"));
        teardown();
    }
}
