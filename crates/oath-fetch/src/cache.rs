//! Disk cache for packuments and tarballs
//!
//! Caches packuments as JSON files and tarballs as .tgz files.
//! Uses content-addressable storage for tarballs (keyed by integrity hash).

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Root cache directory
    pub root: PathBuf,
}

impl Default for CacheConfig {
    fn default() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        Self {
            root: PathBuf::from(home).join(".oath").join("cache"),
        }
    }
}

/// Disk cache for registry data
pub struct DiskCache {
    config: CacheConfig,
}

impl DiskCache {
    pub fn new(config: CacheConfig) -> Self {
        std::fs::create_dir_all(&config.root).ok();
        Self { config }
    }

    /// Get cached tarball by integrity hash
    pub fn get_tarball(&self, integrity: &str) -> Option<Vec<u8>> {
        let path = self.tarball_path(integrity);
        std::fs::read(&path).ok()
    }

    /// Store tarball by integrity hash
    pub fn put_tarball(&self, integrity: &str, data: &[u8]) -> Result<PathBuf> {
        let path = self.tarball_path(integrity);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create cache dir: {}", parent.display()))?;
        }
        std::fs::write(&path, data)
            .with_context(|| format!("failed to write cache: {}", path.display()))?;
        Ok(path)
    }

    /// Check if a tarball is cached
    pub fn has_tarball(&self, integrity: &str) -> bool {
        self.tarball_path(integrity).exists()
    }

    /// Get cached packument JSON
    pub fn get_packument(&self, name: &str) -> Option<Vec<u8>> {
        let path = self.packument_path(name);
        std::fs::read(&path).ok()
    }

    /// Store packument JSON
    pub fn put_packument(&self, name: &str, data: &[u8]) -> Result<()> {
        let path = self.packument_path(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&path, data)
            .with_context(|| format!("failed to cache packument: {}", path.display()))?;
        Ok(())
    }

    /// Total cache size on disk (bytes)
    pub fn total_size(&self) -> u64 {
        dir_size(&self.config.root)
    }

    /// Clear the entire cache
    pub fn clear(&self) -> Result<()> {
        if self.config.root.exists() {
            std::fs::remove_dir_all(&self.config.root)
                .context("failed to clear cache")?;
            std::fs::create_dir_all(&self.config.root).ok();
        }
        Ok(())
    }

    // -- private --

    fn tarball_path(&self, integrity: &str) -> PathBuf {
        // sha512-abc123... -> tarballs/sha512/ab/c123...
        let safe = integrity.replace(['/', '+', '='], "_");
        let (algo, hash) = safe.split_once('-').unwrap_or(("unknown", &safe));
        let prefix = &hash[..2.min(hash.len())];
        self.config.root
            .join("tarballs")
            .join(algo)
            .join(prefix)
            .join(format!("{hash}.tgz"))
    }

    fn packument_path(&self, name: &str) -> PathBuf {
        let safe = name.replace('/', "__");
        self.config.root.join("packuments").join(format!("{safe}.json"))
    }
}

fn dir_size(path: &Path) -> u64 {
    let mut size = 0;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let meta = entry.metadata();
            if let Ok(meta) = meta {
                if meta.is_dir() {
                    size += dir_size(&entry.path());
                } else {
                    size += meta.len();
                }
            }
        }
    }
    size
}
