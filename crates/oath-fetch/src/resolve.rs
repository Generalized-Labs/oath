//! Version resolution
//!
//! Resolves semver ranges against available versions in a packument.
//! Handles dist-tags, exact versions, ranges, and pre-release ordering.

use anyhow::{Context, Result};
use node_semver::{Range, Version};

use crate::packument::{Packument, VersionInfo};

/// Result of version resolution
#[derive(Debug, Clone)]
pub struct ResolvedVersion<'a> {
    /// The exact version string
    pub version: &'a str,
    /// The version info from the packument
    pub info: &'a VersionInfo,
}

/// Resolve a version specifier against a packument.
///
/// Specifier can be:
/// - A dist-tag: "latest", "next", "beta"
/// - An exact version: "1.0.0"
/// - A semver range: "^1.0.0", "~1.2.3", ">=1.0.0 <2.0.0", "1.x", "*"
pub fn resolve_version<'a>(packument: &'a Packument, specifier: &str) -> Result<ResolvedVersion<'a>> {
    // First, check if it's a dist-tag
    if let Some(version) = packument.dist_tags.get(specifier) {
        if let Some(info) = packument.versions.get(version) {
            return Ok(ResolvedVersion {
                version: version.as_str(),
                info,
            });
        }
    }

    // Try exact version match
    if let Some((ver_key, info)) = packument.versions.get_key_value(specifier) {
        return Ok(ResolvedVersion {
            version: ver_key.as_str(),
            info,
        });
    }

    // Parse as semver range
    let range: Range = specifier
        .parse()
        .with_context(|| format!("invalid semver range: {specifier}"))?;

    // Collect all versions that satisfy the range
    let mut candidates: Vec<(&str, &VersionInfo, Version)> = packument
        .versions
        .iter()
        .filter_map(|(ver_str, info)| {
            let ver: Version = ver_str.parse().ok()?;
            if range.satisfies(&ver) {
                Some((ver_str.as_str(), info, ver))
            } else {
                None
            }
        })
        .collect();

    // Sort by version (ascending), pick the highest
    candidates.sort_by(|a, b| a.2.cmp(&b.2));

    candidates
        .last()
        .map(|(ver_str, info, _)| ResolvedVersion {
            version: ver_str,
            info,
        })
        .with_context(|| {
            let available: Vec<&str> = packument.versions.keys().map(|s| s.as_str()).collect();
            format!(
                "no version of {} satisfies range {specifier} (available: {:?})",
                packument.name,
                &available[..available.len().min(10)]
            )
        })
}

/// Resolve multiple version ranges for the same package and pick the
/// intersection (highest version satisfying ALL ranges).
pub fn resolve_intersection<'a>(
    packument: &'a Packument,
    specifiers: &[&str],
) -> Result<ResolvedVersion<'a>> {
    let ranges: Vec<Range> = specifiers
        .iter()
        .map(|s| s.parse::<Range>().with_context(|| format!("invalid range: {s}")))
        .collect::<Result<Vec<_>>>()?;

    let mut candidates: Vec<(&str, &VersionInfo, Version)> = packument
        .versions
        .iter()
        .filter_map(|(ver_str, info)| {
            let ver: Version = ver_str.parse().ok()?;
            if ranges.iter().all(|r| r.satisfies(&ver)) {
                Some((ver_str.as_str(), info, ver))
            } else {
                None
            }
        })
        .collect();

    candidates.sort_by(|a, b| a.2.cmp(&b.2));

    candidates
        .last()
        .map(|(ver_str, info, _)| ResolvedVersion {
            version: ver_str,
            info,
        })
        .with_context(|| {
            format!(
                "no version of {} satisfies all constraints: {:?}",
                packument.name, specifiers
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packument::{DistInfo, Packument, VersionInfo};
    use std::collections::HashMap;

    fn make_packument(versions: &[&str], latest: &str) -> Packument {
        let mut version_map = HashMap::new();
        for &v in versions {
            version_map.insert(
                v.to_string(),
                VersionInfo {
                    name: "test-pkg".to_string(),
                    version: v.to_string(),
                    dependencies: HashMap::new(),
                    dev_dependencies: HashMap::new(),
                    optional_dependencies: HashMap::new(),
                    peer_dependencies: HashMap::new(),
                    peer_dependencies_meta: HashMap::new(),
                    bin: None,
                    engines: HashMap::new(),
                    os: vec![],
                    cpu: vec![],
                    dist: DistInfo {
                        tarball: format!("https://registry.npmjs.org/test-pkg/-/test-pkg-{v}.tgz"),
                        shasum: None,
                        integrity: None,
                        file_count: None,
                        unpacked_size: None,
                        signatures: vec![],
                    },
                    has_install_script: false,
                    has_shrinkwrap: false,
                    funding: None,
                },
            );
        }

        let mut dist_tags = HashMap::new();
        dist_tags.insert("latest".to_string(), latest.to_string());

        Packument {
            name: "test-pkg".to_string(),
            modified: None,
            dist_tags,
            versions: version_map,
        }
    }

    #[test]
    fn test_resolve_latest() {
        let p = make_packument(&["1.0.0", "1.1.0", "2.0.0"], "2.0.0");
        let r = resolve_version(&p, "latest").unwrap();
        assert_eq!(r.version, "2.0.0");
    }

    #[test]
    fn test_resolve_exact() {
        let p = make_packument(&["1.0.0", "1.1.0", "2.0.0"], "2.0.0");
        let r = resolve_version(&p, "1.1.0").unwrap();
        assert_eq!(r.version, "1.1.0");
    }

    #[test]
    fn test_resolve_caret() {
        let p = make_packument(&["1.0.0", "1.1.0", "1.2.3", "2.0.0"], "2.0.0");
        let r = resolve_version(&p, "^1.0.0").unwrap();
        assert_eq!(r.version, "1.2.3");
    }

    #[test]
    fn test_resolve_tilde() {
        let p = make_packument(&["1.0.0", "1.0.5", "1.1.0", "2.0.0"], "2.0.0");
        let r = resolve_version(&p, "~1.0.0").unwrap();
        assert_eq!(r.version, "1.0.5");
    }

    #[test]
    fn test_resolve_star() {
        let p = make_packument(&["1.0.0", "2.0.0", "3.0.0-beta.1"], "2.0.0");
        let r = resolve_version(&p, "*").unwrap();
        // * should not match pre-release
        assert_eq!(r.version, "2.0.0");
    }

    #[test]
    fn test_no_match() {
        let p = make_packument(&["1.0.0", "1.1.0"], "1.1.0");
        let r = resolve_version(&p, "^2.0.0");
        assert!(r.is_err());
    }
}
