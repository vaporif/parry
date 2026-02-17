use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::time::Duration;

use interprocess::local_socket::{
    prelude::*, GenericFilePath, GenericNamespaced, ListenerNonblockingMode, ListenerOptions,
};

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

fn socket_name() -> io::Result<interprocess::local_socket::Name<'static>> {
    // Prefer namespaced names (Linux abstract sockets, Windows named pipes)
    // Fall back to filesystem path (macOS, other Unix)
    if GenericNamespaced::is_supported() {
        "parry-daemon.sock"
            .to_ns_name::<GenericNamespaced>()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
    } else {
        let path = parry_dir()?.join("parry.sock");
        path.to_fs_name::<GenericFilePath>()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
    }
}

/// # Errors
///
/// Returns an error if the parry runtime directory cannot be determined.
pub fn pid_file_path() -> io::Result<PathBuf> {
    Ok(parry_dir()?.join("daemon.pid"))
}

pub struct Listener {
    inner: interprocess::local_socket::Listener,
}

pub struct Stream {
    inner: interprocess::local_socket::Stream,
}

impl Listener {
    /// Bind to the local socket for incoming daemon connections.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot be created.
    pub fn bind() -> io::Result<Self> {
        let dir = parry_dir()?;
        std::fs::create_dir_all(&dir)?;

        // Remove stale socket file (filesystem path sockets only)
        if !GenericNamespaced::is_supported() {
            let sock_path = dir.join("parry.sock");
            if sock_path.exists() {
                let _ = std::fs::remove_file(&sock_path);
            }
        }

        let name = socket_name()?;
        let inner = ListenerOptions::new()
            .name(name)
            .nonblocking(ListenerNonblockingMode::Accept)
            .create_sync()?;

        Ok(Self { inner })
    }

    /// Non-blocking accept.
    ///
    /// # Errors
    ///
    /// Returns an error on accept failure (other than `WouldBlock`).
    pub fn try_accept(&self) -> io::Result<Option<Stream>> {
        match self.inner.accept() {
            Ok(stream) => {
                stream.set_nonblocking(false)?;
                Ok(Some(Stream { inner: stream }))
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }
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
        // Set timeouts so we don't hang if daemon is unresponsive
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
mod tests {
    use super::*;

    #[test]
    fn parry_dir_respects_env_override() {
        let dir = "/tmp/parry-test-dir";
        unsafe { std::env::set_var("PARRY_RUNTIME_DIR", dir) };
        let result = parry_dir().unwrap();
        assert_eq!(result, PathBuf::from(dir));
        unsafe { std::env::remove_var("PARRY_RUNTIME_DIR") };
    }

    #[test]
    fn connect_fails_without_listener() {
        let result = Stream::connect(Duration::from_millis(50));
        assert!(result.is_err());
    }
}
