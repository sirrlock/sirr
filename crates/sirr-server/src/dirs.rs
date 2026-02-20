use std::path::PathBuf;

use anyhow::{Context, Result};
use directories::ProjectDirs;

/// Resolve the data directory for Sirr files (`sirr.db`, `sirr.salt`).
///
/// Priority:
/// 1. `SIRR_DATA_DIR` environment variable
/// 2. Platform-specific app data dir (`~/.local/share/sirr/`, etc.)
pub fn data_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("SIRR_DATA_DIR") {
        let path = PathBuf::from(dir);
        std::fs::create_dir_all(&path).context("create SIRR_DATA_DIR")?;
        return Ok(path);
    }

    let dirs =
        ProjectDirs::from("", "", "sirr").context("could not determine platform data directory")?;

    let path = dirs.data_dir().to_owned();
    std::fs::create_dir_all(&path).context("create platform data dir")?;
    Ok(path)
}
