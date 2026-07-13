//! Content-Addressable Store (CAS)
//!
//! Global store at ~/.oath/store/ where each file is stored by its BLAKE3 hash.
//! A package tarball is extracted once into the store, then hardlinked everywhere.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

pub const STORE_MANIFEST_FILE: &str = ".oath-store-manifest.json";
pub const STORE_MANIFEST_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StoreManifest {
    pub schema_version: u32,
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock_integrity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_url: Option<String>,
    pub package_json_name: String,
    pub package_json_version: String,
    pub file_count: u64,
    pub byte_count: u64,
    pub blake3_tree: Vec<StoreManifestFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StoreManifestFile {
    pub path: String,
    pub bytes: u64,
    pub blake3: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageVerification {
    Verified(StoreManifest),
    Missing,
    Corrupt(String),
}

impl PackageVerification {
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified(_))
    }
}

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
        let home = oath_core::home_dir().context("HOME or USERPROFILE not set")?;
        Self::new(home.join(".oath").join("store"))
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
        self.store_package_with_manifest(name, version, None, None, extracted_dir)
    }

    /// Store a package and write a verification manifest atomically.
    pub fn store_package_with_manifest(
        &self,
        name: &str,
        version: &str,
        resolved_url: Option<&str>,
        lock_integrity: Option<&str>,
        extracted_dir: &Path,
    ) -> Result<PathBuf> {
        let pkg_store_dir = self.package_dir(name, version);

        match self.verify_package(name, version, lock_integrity) {
            PackageVerification::Verified(_) => {
                tracing::debug!("already verified in store: {name}@{version}");
                return Ok(pkg_store_dir);
            }
            PackageVerification::Missing => {}
            PackageVerification::Corrupt(reason) => {
                tracing::debug!("rebuilding corrupt store entry for {name}@{version}: {reason}");
                if pkg_store_dir.exists() {
                    std::fs::remove_dir_all(&pkg_store_dir).with_context(|| {
                        format!(
                            "failed to remove corrupt store dir: {}",
                            pkg_store_dir.display()
                        )
                    })?;
                }
            }
        }

        let parent = pkg_store_dir
            .parent()
            .with_context(|| format!("store path has no parent: {}", pkg_store_dir.display()))?;
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create store parent: {}", parent.display()))?;

        let temp_root = self.root.join(".tmp");
        std::fs::create_dir_all(&temp_root)
            .with_context(|| format!("failed to create store temp dir: {}", temp_root.display()))?;
        let temp_dir = temp_root.join(format!(
            "{}-{}-{}-{}",
            safe_path_component(&name.replace('/', "+")),
            safe_path_component(version),
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        if temp_dir.exists() {
            std::fs::remove_dir_all(&temp_dir).with_context(|| {
                format!("failed to clean stale temp dir: {}", temp_dir.display())
            })?;
        }
        std::fs::create_dir_all(&temp_dir)
            .with_context(|| format!("failed to create store temp dir: {}", temp_dir.display()))?;

        let result = (|| -> Result<()> {
            copy_dir_recursive(extracted_dir, &temp_dir)?;
            let manifest = build_manifest(
                name,
                version,
                resolved_url.map(str::to_string),
                lock_integrity.map(str::to_string),
                &temp_dir,
            )?;
            let manifest_json = serde_json::to_vec_pretty(&manifest)
                .context("failed to serialize store manifest")?;
            std::fs::write(temp_dir.join(STORE_MANIFEST_FILE), manifest_json)
                .context("failed to write store manifest")?;
            match validate_manifest(name, version, lock_integrity, &temp_dir) {
                Ok(_) => {}
                Err(StoreValidationError::Missing) => {
                    bail!("newly written store entry is missing")
                }
                Err(StoreValidationError::Corrupt(reason)) => {
                    bail!("newly written store entry is corrupt: {reason}")
                }
            }
            Ok(())
        })();

        if let Err(err) = result {
            let _ = std::fs::remove_dir_all(&temp_dir);
            return Err(err);
        }

        if pkg_store_dir.exists() {
            std::fs::remove_dir_all(&pkg_store_dir).with_context(|| {
                format!(
                    "failed to remove old store dir: {}",
                    pkg_store_dir.display()
                )
            })?;
        }
        std::fs::rename(&temp_dir, &pkg_store_dir).with_context(|| {
            format!(
                "failed to atomically install store dir {} -> {}",
                temp_dir.display(),
                pkg_store_dir.display()
            )
        })?;

        tracing::debug!("stored {name}@{version} at {}", pkg_store_dir.display());
        Ok(pkg_store_dir)
    }

    /// Check if a package is already in the store (and valid)
    pub fn has_package(&self, name: &str, version: &str) -> bool {
        self.verify_package(name, version, None).is_verified()
    }

    /// Verify a package store entry against its manifest and expected integrity.
    pub fn verify_package(
        &self,
        name: &str,
        version: &str,
        lock_integrity: Option<&str>,
    ) -> PackageVerification {
        match validate_manifest(
            name,
            version,
            lock_integrity,
            &self.package_dir(name, version),
        ) {
            Ok(manifest) => PackageVerification::Verified(manifest),
            Err(StoreValidationError::Missing) => PackageVerification::Missing,
            Err(StoreValidationError::Corrupt(reason)) => PackageVerification::Corrupt(reason),
        }
    }

    /// Root path of the store (for scanning)
    pub fn store_path(&self) -> PathBuf {
        self.root.clone()
    }

    /// Get the store path for a package
    pub fn package_dir(&self, name: &str, version: &str) -> PathBuf {
        // Scoped packages: @scope/name -> @scope+name
        self.package_name_dir(name)
            .join(safe_path_component(version))
    }

    /// Get the store path for all versions of a package.
    pub fn package_name_dir(&self, name: &str) -> PathBuf {
        self.root.join(safe_path_component(&name.replace('/', "+")))
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
                if name.starts_with('.') {
                    continue;
                }
                if let Ok(versions) = std::fs::read_dir(entry.path()) {
                    for ver in versions.flatten() {
                        let version = ver.file_name().to_string_lossy().to_string();
                        if version.starts_with('.') {
                            continue;
                        }
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
        } else {
            bail!(
                "refusing to store non-regular package entry: {}",
                src_path.display()
            );
        }
    }
    Ok(())
}

enum StoreValidationError {
    Missing,
    Corrupt(String),
}

fn validate_manifest(
    name: &str,
    version: &str,
    lock_integrity: Option<&str>,
    dir: &Path,
) -> std::result::Result<StoreManifest, StoreValidationError> {
    if !dir.exists() {
        return Err(StoreValidationError::Missing);
    }
    let manifest_path = dir.join(STORE_MANIFEST_FILE);
    if !manifest_path.exists() {
        return Err(StoreValidationError::Corrupt(
            "missing store manifest".to_string(),
        ));
    }

    let manifest: StoreManifest = std::fs::read(&manifest_path)
        .map_err(|err| StoreValidationError::Corrupt(format!("could not read manifest: {err}")))
        .and_then(|data| {
            serde_json::from_slice(&data).map_err(|err| {
                StoreValidationError::Corrupt(format!("malformed store manifest: {err}"))
            })
        })?;

    if manifest.schema_version != STORE_MANIFEST_SCHEMA_VERSION {
        return Err(StoreValidationError::Corrupt(format!(
            "unsupported store manifest schema {}",
            manifest.schema_version
        )));
    }
    if manifest.name != name || manifest.version != version {
        return Err(StoreValidationError::Corrupt(format!(
            "manifest package mismatch: expected {name}@{version}, got {}@{}",
            manifest.name, manifest.version
        )));
    }
    if let Some(expected) = lock_integrity
        && manifest.lock_integrity.as_deref() != Some(expected)
    {
        return Err(StoreValidationError::Corrupt(
            "manifest lock integrity mismatch".to_string(),
        ));
    }

    let rebuilt = build_manifest(
        name,
        version,
        manifest.resolved_url.clone(),
        manifest.lock_integrity.clone(),
        dir,
    )
    .map_err(|err| StoreValidationError::Corrupt(err.to_string()))?;

    if rebuilt.package_json_name != manifest.package_json_name
        || rebuilt.package_json_version != manifest.package_json_version
    {
        return Err(StoreValidationError::Corrupt(
            "package.json name/version changed".to_string(),
        ));
    }
    if rebuilt.file_count != manifest.file_count
        || rebuilt.byte_count != manifest.byte_count
        || rebuilt.blake3_tree != manifest.blake3_tree
    {
        return Err(StoreValidationError::Corrupt(
            "BLAKE3 file tree mismatch".to_string(),
        ));
    }

    Ok(manifest)
}

fn build_manifest(
    name: &str,
    version: &str,
    resolved_url: Option<String>,
    lock_integrity: Option<String>,
    dir: &Path,
) -> Result<StoreManifest> {
    let package_json_path = dir.join("package.json");
    let package_json = std::fs::read_to_string(&package_json_path).with_context(|| {
        format!(
            "package store entry missing package.json: {}",
            package_json_path.display()
        )
    })?;
    let package_json: serde_json::Value =
        serde_json::from_str(&package_json).context("package.json in store is not valid JSON")?;
    let package_json_name = package_json
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let package_json_version = package_json
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if package_json_name != name || package_json_version != version {
        bail!(
            "package.json mismatch: expected {name}@{version}, got {package_json_name}@{package_json_version}"
        );
    }

    let blake3_tree = build_file_tree(dir)?;
    let byte_count = blake3_tree.iter().map(|file| file.bytes).sum();
    let file_count = blake3_tree.len() as u64;

    Ok(StoreManifest {
        schema_version: STORE_MANIFEST_SCHEMA_VERSION,
        name: name.to_string(),
        version: version.to_string(),
        lock_integrity,
        resolved_url,
        package_json_name,
        package_json_version,
        file_count,
        byte_count,
        blake3_tree,
    })
}

fn build_file_tree(root: &Path) -> Result<Vec<StoreManifestFile>> {
    let mut files = Vec::new();
    collect_file_tree(root, root, &mut files)?;
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(files)
}

fn collect_file_tree(root: &Path, dir: &Path, files: &mut Vec<StoreManifestFile>) -> Result<()> {
    let mut entries = std::fs::read_dir(dir)
        .with_context(|| format!("failed to read store dir: {}", dir.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to read store dir entry: {}", dir.display()))?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)
            .with_context(|| format!("failed to stat store path: {}", path.display()))?;
        if metadata.is_dir() {
            collect_file_tree(root, &path, files)?;
        } else if metadata.is_file() {
            if path.file_name().and_then(|name| name.to_str()) == Some(STORE_MANIFEST_FILE) {
                continue;
            }
            let relative = manifest_relative_path(root, &path)?;
            let data = std::fs::read(&path)
                .with_context(|| format!("failed to read store file: {}", path.display()))?;
            files.push(StoreManifestFile {
                path: relative,
                bytes: data.len() as u64,
                blake3: blake3::hash(&data).to_hex().to_string(),
            });
        } else {
            bail!("refusing special file in store: {}", path.display());
        }
    }

    Ok(())
}

fn manifest_relative_path(root: &Path, path: &Path) -> Result<String> {
    let relative = path.strip_prefix(root).with_context(|| {
        format!(
            "store file {} is outside store entry {}",
            path.display(),
            root.display()
        )
    })?;
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => {
                let part = part
                    .to_str()
                    .with_context(|| format!("non-UTF-8 store path: {}", path.display()))?;
                parts.push(part.to_string());
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!("unsafe store path: {}", path.display());
            }
        }
    }
    Ok(parts.join("/"))
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

fn safe_path_component(input: &str) -> String {
    if input.is_empty() {
        return "_".to_string();
    }

    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-' | b'@' | b'+' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }

    match out.as_str() {
        "." => "%2E".to_string(),
        ".." => "%2E%2E".to_string(),
        _ => out,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_dir_does_not_escape_store_root() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::new(tmp.path().join("store")).unwrap();

        let path = store.package_dir("../evil", "../../outside");
        let relative = path.strip_prefix(store.store_path()).unwrap();

        assert!(!relative.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        }));
        assert_eq!(
            path,
            store.store_path().join("..+evil").join("..%2F..%2Foutside")
        );
    }

    #[test]
    fn package_name_dir_preserves_scoped_package_layout() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::new(tmp.path().join("store")).unwrap();

        assert_eq!(
            store.package_name_dir("@scope/name"),
            store.store_path().join("@scope+name")
        );
    }

    #[test]
    fn store_manifest_round_trips_and_detects_tampering() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        std::fs::create_dir_all(source.join("lib")).unwrap();
        std::fs::write(
            source.join("package.json"),
            r#"{"name":"pkg","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(source.join("lib/index.js"), "module.exports = 1;\n").unwrap();

        let store = ContentStore::new(tmp.path().join("store")).unwrap();
        store
            .store_package_with_manifest(
                "pkg",
                "1.0.0",
                Some("https://registry.example/pkg.tgz"),
                Some("sha512-example"),
                &source,
            )
            .unwrap();

        let verified = store.verify_package("pkg", "1.0.0", Some("sha512-example"));
        let PackageVerification::Verified(manifest) = verified else {
            panic!("expected verified package, got {verified:?}");
        };
        assert_eq!(manifest.file_count, 2);
        assert_eq!(
            manifest
                .blake3_tree
                .iter()
                .map(|f| f.path.as_str())
                .collect::<Vec<_>>(),
            vec!["lib/index.js", "package.json"]
        );

        std::fs::write(
            store.package_dir("pkg", "1.0.0").join("lib/index.js"),
            "tampered",
        )
        .unwrap();
        assert!(matches!(
            store.verify_package("pkg", "1.0.0", Some("sha512-example")),
            PackageVerification::Corrupt(_)
        ));
    }

    #[test]
    fn legacy_store_entry_without_manifest_is_unverified() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::new(tmp.path().join("store")).unwrap();
        let dir = store.package_dir("pkg", "1.0.0");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("package.json"),
            r#"{"name":"pkg","version":"1.0.0"}"#,
        )
        .unwrap();

        assert!(matches!(
            store.verify_package("pkg", "1.0.0", None),
            PackageVerification::Corrupt(reason) if reason.contains("missing store manifest")
        ));
        assert!(!store.has_package("pkg", "1.0.0"));
    }
}
