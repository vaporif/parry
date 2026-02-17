pub type Result<T> = eyre::Result<T>;

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("daemon failed to start: {0}")]
    DaemonStart(String),
    #[error("daemon IO: {0}")]
    DaemonIo(#[from] std::io::Error),
}
