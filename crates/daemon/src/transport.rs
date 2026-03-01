//! IPC transport layer for daemon communication.

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::time::Duration;

use interprocess::local_socket::{prelude::*, GenericFilePath, ListenerOptions};

/// Returns the parry runtime directory (`~/.parry/`).
/// Respects `PARRY_RUNTIME_DIR` env override for testing.
///
/// # Errors
///
/// Returns an error if the home directory cannot be determined.
pub fn parry_dir() -> io::Result<PathBuf> {
    if let Ok(dir) = std::env::var("PARRY_RUNTIME_DIR") {
        return Ok(PathBuf::from(dir));
    }

    home_dir()
        .map(|h| h.join(".parry"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "cannot determine home directory"))
}

fn home_dir() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    }
}

fn socket_path() -> io::Result<PathBuf> {
    Ok(parry_dir()?.join("parry.sock"))
}

/// Check if the daemon socket file exists on disk.
#[must_use]
pub fn socket_exists() -> bool {
    socket_path().is_ok_and(|p| p.exists())
}

fn socket_name() -> io::Result<interprocess::local_socket::Name<'static>> {
    // Always use filesystem path for reliable cleanup across all platforms.
    // Namespaced sockets (Linux abstract, Windows named pipes) can leave stale
    // references that are difficult to clean up, causing "Address already in use".
    socket_path()?
        .to_fs_name::<GenericFilePath>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

/// # Errors
///
/// Returns an error if the parry runtime directory cannot be determined.
pub fn pid_file_path() -> io::Result<PathBuf> {
    Ok(parry_dir()?.join("daemon.pid"))
}

// ─── Stale state cleanup ─────────────────────────────────────────────────────

/// Check if a process with the given PID is alive.
#[cfg(unix)]
fn is_process_alive(pid: u32) -> bool {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    if pid == 0 {
        return false;
    }
    // SAFETY: kill with signal 0 checks process existence without sending a signal.
    unsafe { kill(pid, 0) == 0 }
}

#[cfg(not(unix))]
fn is_process_alive(_pid: u32) -> bool {
    // Cannot verify on non-Unix; assume alive to avoid accidental cleanup.
    true
}

/// Remove stale daemon state (PID file and socket) if the recorded process is no longer alive.
pub fn cleanup_stale_state() {
    let Ok(pid_path) = pid_file_path() else {
        return;
    };

    // If PID file exists, check if that process is alive
    if let Ok(pid_str) = std::fs::read_to_string(&pid_path) {
        match pid_str.trim().parse::<u32>() {
            Ok(pid) if is_process_alive(pid) => return,
            Ok(pid) => {
                tracing::info!(pid, "removing stale daemon state (process not alive)");
            }
            Err(_) => {
                tracing::info!("removing corrupt daemon PID file");
            }
        }
        let _ = std::fs::remove_file(&pid_path);
    }

    // Clean up orphaned socket even if PID file was missing
    if let Ok(sock) = socket_path() {
        if sock.exists() {
            tracing::info!("removing stale socket");
            let _ = std::fs::remove_file(&sock);
        }
    }
}

// ─── Async listener (for daemon server) ──────────────────────────────────────

/// Create an async tokio listener for the daemon.
///
/// # Errors
///
/// Returns an error if the socket cannot be created.
pub fn bind_async() -> io::Result<interprocess::local_socket::tokio::Listener> {
    let dir = parry_dir()?;
    std::fs::create_dir_all(&dir)?;

    // Remove stale socket file before binding
    let sock_path = socket_path()?;
    if sock_path.exists() {
        let _ = std::fs::remove_file(&sock_path);
    }

    let name = socket_name()?;
    ListenerOptions::new().name(name).create_tokio()
}

// ─── Sync stream (for daemon client) ────────────────────────────────────────

pub struct Stream {
    inner: interprocess::local_socket::Stream,
}

impl Stream {
    /// Connect to the daemon with a timeout.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection cannot be established.
    pub fn connect(timeout: Duration) -> io::Result<Self> {
        let name = socket_name()?;
        let inner = interprocess::local_socket::Stream::connect(name)?;
        let _ = inner.set_recv_timeout(Some(timeout));
        let _ = inner.set_send_timeout(Some(timeout));
        Ok(Self { inner })
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
pub(crate) mod test_util {
    use std::sync::MutexGuard;

    /// Serializes tests that mutate `PARRY_RUNTIME_DIR`.
    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// RAII guard: sets `PARRY_RUNTIME_DIR`, restores on drop.
    pub struct EnvGuard<'a> {
        _lock: MutexGuard<'a, ()>,
    }

    impl EnvGuard<'_> {
        pub fn new(dir: &std::path::Path) -> Self {
            let lock = ENV_MUTEX
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            unsafe { std::env::set_var("PARRY_RUNTIME_DIR", dir) };
            Self { _lock: lock }
        }
    }

    impl Drop for EnvGuard<'_> {
        fn drop(&mut self) {
            unsafe { std::env::remove_var("PARRY_RUNTIME_DIR") };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::test_util::EnvGuard;

    #[test]
    fn parry_dir_respects_env_override() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::new(dir.path());
        let result = parry_dir().unwrap();
        assert_eq!(result, dir.path().to_path_buf());
    }

    #[test]
    fn connect_fails_without_listener() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::new(dir.path());
        let result = Stream::connect(Duration::from_millis(50));
        assert!(result.is_err());
    }
}
