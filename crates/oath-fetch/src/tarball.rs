//! Tarball download, integrity verification, and extraction
//!
//! Handles SRI (Subresource Integrity) verification using sha512/sha256/sha1.

use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use tar::Archive;

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
            let hash = Sha1::digest(data);
            base64_encode(&hash)
        }
        _ => bail!("unsupported SRI algorithm: {algo}"),
    };

    if computed_b64 != expected_b64 {
        bail!("integrity check failed: expected {algo}-{expected_b64}, got {algo}-{computed_b64}");
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

        let Some(relative) = sanitize_tar_path(&path) else {
            tracing::warn!("skipping unsafe path in tarball: {}", path.display());
            continue;
        };

        let full_path = dest.join(&relative);

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
        if let Ok(path) = entry.path()
            && let Some(relative) = sanitize_tar_path(&path)
        {
            files.push(relative.to_string_lossy().to_string());
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

fn sanitize_tar_path(path: &Path) -> Option<PathBuf> {
    if path
        .components()
        .any(|component| matches!(component, Component::Prefix(_) | Component::RootDir))
    {
        return None;
    }

    let mut relative = PathBuf::new();
    for component in path.components().skip(1) {
        match component {
            Component::Normal(part) => relative.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) | Component::RootDir => return None,
        }
    }

    (!relative.as_os_str().is_empty()).then_some(relative)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use tar::{Builder, Header};

    fn tar_gz_with_file(path: &str, content: &[u8]) -> Vec<u8> {
        let gz = GzEncoder::new(Vec::new(), Compression::default());
        let mut tar = Builder::new(gz);
        let mut header = Header::new_gnu();
        header.as_mut_bytes()[..path.len()].copy_from_slice(path.as_bytes());
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append(&header, content).unwrap();
        tar.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn extract_tarball_rejects_parent_dir_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("extract");
        let outside = tmp.path().join("escape.txt");
        let data = tar_gz_with_file("package/../escape.txt", b"owned");

        extract_tarball(&data, &dest).unwrap();

        assert!(
            !outside.exists(),
            "tarball extraction wrote outside destination"
        );
    }

    #[test]
    fn list_tarball_filters_parent_dir_entries() {
        let data = tar_gz_with_file("package/../escape.txt", b"owned");

        let files = list_tarball(&data).unwrap();

        assert!(files.is_empty(), "unsafe tar path was listed: {files:?}");
    }

    #[test]
    fn sha1_integrity_is_verified() {
        let data = b"package bytes";
        let hash = Sha1::digest(data);
        let integrity = format!("sha1-{}", base64_encode(&hash));

        verify_integrity(data, &integrity).unwrap();
        assert!(verify_integrity(b"tampered package bytes", &integrity).is_err());
    }
}
