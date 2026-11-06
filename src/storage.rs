use crate::{Error, Index, Result};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug)]
pub struct Budget {
    /// Strict upper bound: equal to the ceiling is already too large.
    pub ceiling_bytes: u64,
    /// All other installed files, dependencies, caches, logs and reserved growth.
    /// The caller must obtain this from a complete installation inventory.
    pub other_bytes: u64,
}

impl Index {
    pub fn load(path: &Path, max_bytes: usize) -> Result<Self> {
        let file = File::open(path)?;
        if file.metadata()?.len() > max_bytes as u64 {
            return Err(Error::new("index file exceeds byte limit"));
        }
        let mut bytes = Vec::new();
        // Recheck after a bounded read in case the file grew after metadata().
        file.take((max_bytes as u64).saturating_add(1))
            .read_to_end(&mut bytes)?;
        Self::from_bytes(bytes, max_bytes)
    }

    /// Stage and sync in the same directory before atomic replacement. A fixed
    /// create_new staging file serializes cooperating publishers. A stale file
    /// is never deleted automatically. Callers must serialize other storage use.
    pub fn publish(&self, path: &Path, budget: Budget) -> Result<()> {
        let name = path
            .file_name()
            .ok_or_else(|| Error::new("output must be a filename"))?;
        let mut staged_name = name.to_os_string();
        staged_name.push(".staging");
        let staging = path.with_file_name(staged_name);
        if staging.try_exists()? {
            return Err(Error::new(
                "staging file already exists; inspect interrupted update",
            ));
        }
        // Acquire the publisher lock before reading the old size. Reading it
        // first would race another publisher and undercount update overlap.
        // Declare cleanup before file so error returns close the file first
        // (Windows cannot remove a staging file while it is still open).
        let mut cleanup = Staging(None);
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&staging)?;
        cleanup.0 = Some(staging.clone());
        let old_bytes = match fs::symlink_metadata(path) {
            Ok(meta) if meta.is_file() => meta.len(),
            Ok(_) => {
                return Err(Error::new(
                    "output must be a regular file, not a symlink or directory",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => return Err(error.into()),
        };
        let peak = budget
            .other_bytes
            .checked_add(old_bytes)
            .and_then(|n| n.checked_add(self.as_bytes().len() as u64))
            .ok_or_else(|| Error::new("storage budget overflow"))?;
        if peak >= budget.ceiling_bytes {
            return Err(Error::new(format!(
                "update needs {peak} bytes; must remain below {}",
                budget.ceiling_bytes
            )));
        }
        file.write_all(self.as_bytes())?;
        file.sync_all()?;
        drop(file);
        fs::rename(&staging, path)?;
        cleanup.0 = None;
        // Unix directory sync makes the rename durable. On other platforms
        // replacement uses std::fs::rename; power-loss durability is unverified.
        #[cfg(unix)]
        File::open(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?
        .sync_all()
        .map_err(|e| {
            Error::new(format!(
                "index was replaced, but directory sync failed: {e}"
            ))
        })?;
        Ok(())
    }
}

struct Staging(Option<PathBuf>);
impl Drop for Staging {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = fs::remove_file(path);
        }
    }
}
