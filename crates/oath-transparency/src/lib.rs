//! Transparency log for oath installs.
//!
//! Appends a JSONL record to ~/.oath/transparency.log on every install.
//! The log is append-only and never truncated.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// A single entry in the transparency log (JSONL format)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransparencyEntry {
    /// Unix timestamp (seconds)
    pub ts: u64,
    /// Absolute path to the project
    pub project: String,
    /// Total number of packages installed
    pub pkg_count: usize,
    /// Individual package entries
    pub packages: Vec<PackageEntry>,
    /// Time taken for the full install (ms)
    pub duration_ms: u64,
}

/// A single package in a transparency entry
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PackageEntry {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity: Option<String>,
}

/// Appends a transparency log entry to ~/.oath/transparency.log.
pub struct TransparencyLogger {
    log_path: PathBuf,
}

impl TransparencyLogger {
    /// Create a logger that writes to ~/.oath/transparency.log
    pub fn default_logger() -> Result<Self> {
        let home = std::env::var("HOME").map_err(|_| anyhow::anyhow!("HOME not set"))?;
        let dir = PathBuf::from(home).join(".oath");
        std::fs::create_dir_all(&dir)?;
        Ok(Self {
            log_path: dir.join("transparency.log"),
        })
    }

    /// Create a logger that writes to a custom path (for testing)
    pub fn new(log_path: PathBuf) -> Self {
        Self { log_path }
    }

    /// Append a new entry. `packages` is a list of (name, version, integrity).
    pub fn log(
        &self,
        project: &str,
        packages: &[(String, String, Option<String>)],
        duration_ms: u64,
    ) -> Result<()> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let pkg_entries: Vec<PackageEntry> = packages
            .iter()
            .map(|(name, version, integrity)| PackageEntry {
                name: name.clone(),
                version: version.clone(),
                integrity: integrity.clone(),
            })
            .collect();

        let entry = TransparencyEntry {
            ts,
            project: project.to_string(),
            pkg_count: pkg_entries.len(),
            packages: pkg_entries,
            duration_ms,
        };

        let line = serde_json::to_string(&entry)?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;
        writeln!(file, "{}", line)?;
        Ok(())
    }

    /// Read recent entries from the log. Returns up to `tail` most recent entries.
    pub fn read_recent(&self, tail: usize) -> Result<Vec<TransparencyEntry>> {
        if !self.log_path.exists() {
            return Ok(Vec::new());
        }
        let content = std::fs::read_to_string(&self.log_path)?;
        let entries: Vec<TransparencyEntry> = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();

        // Return last `tail` entries
        let len = entries.len();
        if len <= tail {
            Ok(entries)
        } else {
            Ok(entries[len - tail..].to_vec())
        }
    }

    /// Return the log file path
    pub fn log_path(&self) -> &PathBuf {
        &self.log_path
    }
}
