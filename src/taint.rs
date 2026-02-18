use std::path::PathBuf;
use std::time::{Duration, SystemTime};

const TAINT_TTL: Duration = Duration::from_secs(3600);

fn taint_dir() -> Option<PathBuf> {
    crate::daemon::transport::parry_dir()
        .ok()
        .map(|d| d.join("taint"))
}

/// Mark a session as tainted. Fail-silent.
pub fn mark(session_id: &str) {
    let Some(dir) = taint_dir() else { return };
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(hash_id(session_id));
    let _ = std::fs::write(&path, b"");
    cleanup_expired(&dir);
}

/// Remove expired taint files. Runs on ~1 in 16 calls to avoid overhead.
fn cleanup_expired(dir: &std::path::Path) {
    // Use low bits of current time as cheap randomness
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    if now.as_nanos() & 0xF != 0 {
        return;
    }

    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let age = meta
            .modified()
            .ok()
            .and_then(|m| SystemTime::now().duration_since(m).ok())
            .unwrap_or(Duration::ZERO);
        if age > TAINT_TTL {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Check if a session is tainted (and not expired).
#[must_use]
pub fn is_tainted(session_id: &str) -> bool {
    let Some(dir) = taint_dir() else {
        return false;
    };
    let path = dir.join(hash_id(session_id));
    std::fs::metadata(&path).is_ok_and(|meta| {
        let age = meta
            .modified()
            .ok()
            .and_then(|m| SystemTime::now().duration_since(m).ok())
            .unwrap_or(Duration::MAX);
        if age > TAINT_TTL {
            let _ = std::fs::remove_file(&path);
            false
        } else {
            true
        }
    })
}

fn hash_id(session_id: &str) -> String {
    format!("{:016x}", hash_bytes(session_id.as_bytes()))
}

/// FNV-1a 64-bit hash.
fn hash_bytes(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &byte in data {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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
        mark("session-abc");
        assert!(is_tainted("session-abc"));
        teardown();
    }

    #[test]
    fn unknown_session_clean() {
        let _dir = setup_test_dir();
        assert!(!is_tainted("never-marked"));
        teardown();
    }

    #[test]
    fn expired_taint_cleaned() {
        let _dir = setup_test_dir();
        let dir = taint_dir().unwrap();
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(hash_id("old-session"));
        fs::write(&path, b"").unwrap();

        // Backdate file mtime to 2 hours ago
        let two_hours_ago =
            filetime::FileTime::from_system_time(SystemTime::now() - Duration::from_secs(7200));
        filetime::set_file_mtime(&path, two_hours_ago).unwrap();

        assert!(!is_tainted("old-session"));
        assert!(!path.exists(), "expired taint file should be removed");
        teardown();
    }

    #[test]
    fn hash_is_deterministic() {
        assert_eq!(hash_id("test"), hash_id("test"));
        assert_ne!(hash_id("a"), hash_id("b"));
    }
}
