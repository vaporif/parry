pub mod config;
pub mod daemon;
pub mod error;
pub mod guard;
pub mod hook;
pub mod model;
pub mod scan;
pub mod taint;

use std::path::PathBuf;

pub(crate) fn runtime_path(filename: &str) -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("PARRY_RUNTIME_DIR") {
        return Some(PathBuf::from(dir).join(filename));
    }
    std::env::current_dir().ok().map(|d| d.join(filename))
}
