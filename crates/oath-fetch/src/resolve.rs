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
/// - An npm alias specifier: "npm:some-pkg@^1.0.0" (the version part is extracted)
pub fn resolve_version<'a>(packument: &'a Packument, specifier: &str) -> Result<ResolvedVersion<'a>> {
    // Strip npm: alias prefix (e.g. "npm:real-pkg@^1.0.0" -> "^1.0.0")
    // This handles cases like aliased deps passed directly to resolve_version.
    let specifier = if specifier.starts_with("npm:") {
        let rest = &specifier[4..];
        // Scoped: npm:@scope/pkg@version -> extract version after second @
        if rest.starts_with('@') {
            if let Some(at_pos) = rest[1..].find('@').map(|p| p + 1) {
                &rest[at_pos + 1..]
            } else {
                "latest"
            }
        } else {
            // Non-scoped: npm:pkg@version -> extract version after @
            if let Some(at_pos) = rest.rfind('@') {
                if at_pos > 0 {
                    &rest[at_pos + 1..]
                } else {
                    "latest"
                }
            } else {
                "latest"
            }
        }
    } else {
        specifier
    };

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
    use crate::packument::{DistInfo, Engines, Packument, VersionInfo};
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
                    engines: Engines::Map(HashMap::new()),
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
            time: HashMap::new(),
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

    #[test]
    fn test_npm_prefix_stripped() {
        // npm:real-pkg@^1.0.0 should resolve using "^1.0.0" range only
        let p = make_packument(&["1.0.0", "1.2.3", "2.0.0"], "2.0.0");
        let r = resolve_version(&p, "npm:real-pkg@^1.0.0").unwrap();
        assert_eq!(r.version, "1.2.3");
    }

    #[test]
    fn test_caret_major_boundary() {
        // ^20.0.0 must NOT match v21+
        let p = make_packument(&["19.9.9", "20.0.0", "20.11.0", "21.0.0", "26.0.0"], "26.0.0");
        let r = resolve_version(&p, "^20.0.0").unwrap();
        assert_eq!(r.version, "20.11.0");
    }
}
