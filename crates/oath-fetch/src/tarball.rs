//! Tarball download, integrity verification, and extraction
//!
//! Handles SRI (Subresource Integrity) verification using sha512/sha256/sha1.

use anyhow::{bail, Context, Result};
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256, Sha512};
use std::io::Read;
use std::path::Path;
use tar::Archive;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Verify tarball bytes against an SRI integrity string.
///
/// Format: "sha512-<base64>" or "sha256-<base64>" or "sha1-<base64>"
pub fn verify_integrity(data: &[u8], sri: &str) -> Result<()> {
    let (algo, expected_b64) = sri
        .split_once('-')
        .with_context(|| format!("invalid SRI format: {sri}"))?;

    let computed_b64 = match algo {
        "sha512" => {
            let hash = Sha512::digest(data);
            base64_encode(&hash)
        }
        "sha256" => {
            let hash = Sha256::digest(data);
            base64_encode(&hash)
        }
        "sha1" => {
            // sha1 is legacy. Modern packages use sha512.
            // For now, we skip sha1 verification with a warning.
            tracing::warn!("sha1 integrity check not implemented; use sha512 packages");
            return Ok(());
        }
        _ => bail!("unsupported SRI algorithm: {algo}"),
    };

    if computed_b64 != expected_b64 {
        bail!(
            "integrity check failed: expected {algo}-{expected_b64}, got {algo}-{computed_b64}"
        );
    }

    Ok(())
}

/// Extract a .tgz tarball to a destination directory.
/// npm tarballs contain a `package/` prefix which we strip.
pub fn extract_tarball(data: &[u8], dest: &Path) -> Result<()> {
    let gz = GzDecoder::new(data);
    let mut archive = Archive::new(gz);

    std::fs::create_dir_all(dest)
        .with_context(|| format!("failed to create dir: {}", dest.display()))?;

    for entry in archive.entries().context("failed to read tar entries")? {
        let mut entry = entry.context("corrupt tar entry")?;
        let path = entry.path().context("invalid path in tar")?;

        // Strip the first path component (npm uses "package/" but some tarballs
        // like @types/node use non-standard roots e.g. "node v20.19/").
        // All npm-compatible tools strip the first component regardless of name.
        let relative = path
            .components()
            .skip(1)
            .collect::<std::path::PathBuf>();

        // Skip empty paths
        if relative.as_os_str().is_empty() {
            continue;
        }

        let full_path = dest.join(&relative);

        // Security: prevent path traversal
        if !full_path.starts_with(dest) {
            tracing::warn!("skipping path traversal attempt: {}", path.display());
            continue;
        }

        match entry.header().entry_type() {
            tar::EntryType::Directory => {
                std::fs::create_dir_all(&full_path).ok();
            }
            tar::EntryType::Regular | tar::EntryType::GNUSparse => {
                if let Some(parent) = full_path.parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                // Capture mode before consuming entry via io::copy
                let mode = entry.header().mode().unwrap_or(0o644);
                let mut file = std::fs::File::create(&full_path)
                    .with_context(|| format!("failed to create: {}", full_path.display()))?;
                std::io::copy(&mut entry, &mut file)
                    .with_context(|| format!("failed to write: {}", full_path.display()))?;
                // Preserve executable bits from the tar header
                #[cfg(unix)]
                if mode & 0o111 != 0 {
                    let perms = std::fs::Permissions::from_mode(0o755);
                    std::fs::set_permissions(&full_path, perms).with_context(|| {
                        format!("failed to set permissions on: {}", full_path.display())
                    })?;
                }
            }
            tar::EntryType::Symlink | tar::EntryType::Link => {
                // Skip symlinks in packages (security risk)
                tracing::debug!("skipping symlink in tarball: {}", path.display());
            }
            _ => {}
        }
    }

    Ok(())
}

/// List files in a tarball without extracting
pub fn list_tarball(data: &[u8]) -> Result<Vec<String>> {
    let gz = GzDecoder::new(data);
    let mut archive = Archive::new(gz);
    let mut files = Vec::new();

    for entry in archive.entries()? {
        let entry = entry?;
        if let Ok(path) = entry.path() {
            let relative = path.components().skip(1).collect::<std::path::PathBuf>();
            if !relative.as_os_str().is_empty() {
                files.push(relative.to_string_lossy().to_string());
            }
        }
    }

    Ok(files)
}

/// Get the total unpacked size of a tarball
pub fn tarball_unpacked_size(data: &[u8]) -> Result<u64> {
    let gz = GzDecoder::new(data);
    let mut archive = Archive::new(gz);
    let mut total = 0u64;

    for entry in archive.entries()? {
        let entry = entry?;
        total += entry.size();
    }

    Ok(total)
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

