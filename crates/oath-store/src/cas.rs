//! Content-Addressable Store (CAS)
//!
//! Global store at ~/.oath/store/ where each file is stored by its BLAKE3 hash.
//! A package tarball is extracted once into the store, then hardlinked everywhere.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// The global content-addressable store
#[derive(Clone)]
pub struct ContentStore {
    /// Root directory of the store
    root: PathBuf,
}

impl ContentStore {
    /// Create or open a store at the given path
    pub fn new(root: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&root)
            .with_context(|| format!("failed to create store at {}", root.display()))?;
        Ok(Self { root })
    }

    /// Default store location: ~/.oath/store
    pub fn default_store() -> Result<Self> {
        let home = std::env::var("HOME").context("HOME not set")?;
        Self::new(PathBuf::from(home).join(".oath").join("store"))
    }

    /// Store a package's extracted files. Returns the package directory in the store.
    ///
    /// Layout: store/{name}/{version}/node_modules/{name}/{files...}
    /// This mirrors what node expects when resolving.
    pub fn store_package(
        &self,
        name: &str,
        version: &str,
        extracted_dir: &Path,
    ) -> Result<PathBuf> {
        let pkg_store_dir = self.package_dir(name, version);

        // If already stored, validate layout before skipping
        if pkg_store_dir.exists() {
            // Validate: if the store dir contains ONLY a single subdirectory and no files,
            // the extraction was done with the old wrong logic (subdir not stripped).
            // Delete and re-extract.
            let entries: Vec<_> = std::fs::read_dir(&pkg_store_dir)?.collect();
            let has_files = entries.iter().any(|e| {
                e.as_ref()
                    .map(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
                    .unwrap_or(false)
            });
            let has_only_subdirs = !entries.is_empty() && !has_files;
            if has_only_subdirs {
                // Bad extraction -- only subdirs, no files at root. Re-extract.
                tracing::debug!("stale store entry detected for {name}@{version}, re-extracting");
                std::fs::remove_dir_all(&pkg_store_dir)?;
            } else {
                tracing::debug!("already in store: {name}@{version}");
                return Ok(pkg_store_dir);
            }
        }

        // Create the store directory
        std::fs::create_dir_all(&pkg_store_dir)
            .with_context(|| format!("failed to create store dir: {}", pkg_store_dir.display()))?;

        // Copy all files from extracted dir to store
        copy_dir_recursive(extracted_dir, &pkg_store_dir)?;

        tracing::debug!("stored {name}@{version} at {}", pkg_store_dir.display());
        Ok(pkg_store_dir)
    }

    /// Check if a package is already in the store (and valid)
    pub fn has_package(&self, name: &str, version: &str) -> bool {
        let dir = self.package_dir(name, version);
        if !dir.exists() {
            return false;
        }
        // Validate layout: if the dir contains ONLY subdirectories and no files at root,
        // it was extracted with the old wrong logic (subdir not stripped). Treat as missing.
        if let Ok(entries) = std::fs::read_dir(&dir) {
            let entries: Vec<_> = entries.collect();
            let has_files = entries.iter().any(|e| {
                e.as_ref()
                    .map(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
                    .unwrap_or(false)
            });
            let has_only_subdirs = !entries.is_empty() && !has_files;
            if has_only_subdirs {
                return false;
            }
        }
        true
    }

    /// Root path of the store (for scanning)
    pub fn store_path(&self) -> PathBuf {
        self.root.clone()
    }

    /// Get the store path for a package
    pub fn package_dir(&self, name: &str, version: &str) -> PathBuf {
        // Scoped packages: @scope/name -> @scope+name
        let safe_name = name.replace('/', "+");
        self.root.join(&safe_name).join(version)
    }

    /// Total size of the store (bytes)
    pub fn total_size(&self) -> u64 {
        dir_size(&self.root)
    }

    /// List all packages in the store
    pub fn list_packages(&self) -> Vec<(String, String)> {
        let mut packages = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&self.root) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().replace('+', "/");
                if let Ok(versions) = std::fs::read_dir(entry.path()) {
                    for ver in versions.flatten() {
                        let version = ver.file_name().to_string_lossy().to_string();
                        packages.push((name.clone(), version));
                    }
                }
            }
        }
        packages
    }

    /// Remove a specific package version from the store
    pub fn remove_package(&self, name: &str, version: &str) -> Result<()> {
        let dir = self.package_dir(name, version);
        if dir.exists() {
            std::fs::remove_dir_all(&dir)
                .with_context(|| format!("failed to remove {name}@{version}"))?;
        }
        Ok(())
    }

    /// Garbage collect: remove packages not referenced by any project
    /// (For now just returns the list; actual GC needs project tracking)
    pub fn gc_candidates(&self) -> Vec<(String, String)> {
        // TODO: Track which projects reference which packages
        // For now, return all packages (conservative -- don't delete anything)
        self.list_packages()
    }
}

/// Recursively copy a directory
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if file_type.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else if file_type.is_file() {
            std::fs::copy(&src_path, &dst_path)?;
        }
        // Skip symlinks (security)
    }
    Ok(())
}

fn dir_size(path: &Path) -> u64 {
    let mut size = 0;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
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
