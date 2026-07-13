//! Git dependency support
//!
//! Parses and resolves git-style dependency specs like:
//!   github:user/repo
//!   github:user/repo#branch
//!   git+https://github.com/user/repo.git
//!   git+https://github.com/user/repo.git#abc123
//!   bitbucket:user/repo
//!   gitlab:user/repo

use anyhow::{Context, Result};
use std::collections::HashMap;

/// A parsed git dependency specification
#[derive(Debug, Clone)]
pub struct GitSpec {
    /// The resolved HTTPS URL (without git+ prefix)
    pub url: String,
    /// Optional ref: branch, tag, or commit hash
    pub git_ref: Option<String>,
    /// GitHub user/repo shorthand (if applicable), for API access
    pub github_repo: Option<(String, String)>,
}

/// Check if a dep spec is a git dependency
pub fn is_git_spec(spec: &str) -> bool {
    spec.starts_with("github:")
        || spec.starts_with("gitlab:")
        || spec.starts_with("bitbucket:")
        || spec.starts_with("git+https://")
        || spec.starts_with("git+ssh://")
        || spec.starts_with("git://")
}

/// Stable, path-safe filename for cached git dependency tarballs.
pub fn git_cache_file_name(name: &str, version: &str) -> String {
    format!(
        "{}-{}.tgz",
        safe_cache_component(&name.replace('/', "+")),
        safe_cache_component(version)
    )
}

/// Parse a git dependency spec into a GitSpec
pub fn parse_git_spec(spec: &str) -> Option<GitSpec> {
    if let Some(rest) = spec.strip_prefix("github:") {
        // after "github:"
        let (repo_path, git_ref) = split_ref(rest);
        // Skip semver: prefix refs for now -- treat as HEAD
        let git_ref = git_ref.and_then(|r| {
            if r.starts_with("semver:") {
                None // TODO: resolve tags for semver ranges
            } else {
                Some(r.to_string())
            }
        });
        let parts: Vec<&str> = repo_path.splitn(2, '/').collect();
        if parts.len() != 2 {
            return None;
        }
        let user = parts[0].to_string();
        let repo = parts[1].trim_end_matches(".git").to_string();
        let url = format!("https://github.com/{}/{}.git", user, repo);
        return Some(GitSpec {
            url,
            git_ref,
            github_repo: Some((user, repo)),
        });
    }

    if let Some(rest) = spec.strip_prefix("gitlab:") {
        let (repo_path, git_ref) = split_ref(rest);
        let git_ref = git_ref.map(|r| r.to_string());
        let parts: Vec<&str> = repo_path.splitn(2, '/').collect();
        if parts.len() != 2 {
            return None;
        }
        let user = parts[0].to_string();
        let repo = parts[1].trim_end_matches(".git").to_string();
        let url = format!("https://gitlab.com/{}/{}.git", user, repo);
        return Some(GitSpec {
            url,
            git_ref,
            github_repo: None,
        });
    }

    if let Some(rest) = spec.strip_prefix("bitbucket:") {
        let (repo_path, git_ref) = split_ref(rest);
        let git_ref = git_ref.map(|r| r.to_string());
        let parts: Vec<&str> = repo_path.splitn(2, '/').collect();
        if parts.len() != 2 {
            return None;
        }
        let user = parts[0].to_string();
        let repo = parts[1].trim_end_matches(".git").to_string();
        let url = format!("https://bitbucket.org/{}/{}.git", user, repo);
        return Some(GitSpec {
            url,
            git_ref,
            github_repo: None,
        });
    }

    if spec.starts_with("git+https://") {
        let url_part = &spec[4..]; // strip "git+" -> "https://..."
        let (url_no_ref, git_ref) = split_ref(url_part);
        let git_ref = git_ref.map(|r| r.to_string());
        // Check if it's a GitHub URL for API access
        let github_repo = parse_github_url(url_no_ref);
        return Some(GitSpec {
            url: url_no_ref.to_string(),
            git_ref,
            github_repo,
        });
    }

    if let Some(url_part) = spec.strip_prefix("git+ssh://") {
        // git+ssh://git@github.com/user/repo.git
        // strip "git+ssh://"
        let (url_no_ref, git_ref) = split_ref(url_part);
        let git_ref = git_ref.map(|r| r.to_string());
        // Convert ssh to https for downloading
        let https_url = if let Some(repo) = url_no_ref
            .strip_prefix("git@github.com:")
            .or_else(|| url_no_ref.strip_prefix("git@github.com/"))
        {
            format!("https://github.com/{repo}")
        } else {
            format!("https://{}", url_no_ref)
        };
        let github_repo = parse_github_url(&https_url);
        return Some(GitSpec {
            url: https_url,
            git_ref,
            github_repo,
        });
    }

    if let Some(url_part) = spec.strip_prefix("git://") {
        // strip "git://"
        let (url_no_ref, git_ref) = split_ref(url_part);
        let git_ref = git_ref.map(|r| r.to_string());
        let https_url = format!("https://{}", url_no_ref);
        let github_repo = parse_github_url(&https_url);
        return Some(GitSpec {
            url: https_url,
            git_ref,
            github_repo,
        });
    }

    None
}

/// Split a URL/path at '#' for the ref part
fn split_ref(s: &str) -> (&str, Option<&str>) {
    if let Some(pos) = s.find('#') {
        (&s[..pos], Some(&s[pos + 1..]))
    } else {
        (s, None)
    }
}

/// Try to extract (user, repo) from a GitHub HTTPS URL
fn parse_github_url(url: &str) -> Option<(String, String)> {
    // https://github.com/user/repo.git or https://github.com/user/repo
    let url = url.trim_end_matches(".git");
    if let Some(rest) = url.strip_prefix("https://github.com/") {
        let parts: Vec<&str> = rest.splitn(2, '/').collect();
        if parts.len() == 2 {
            return Some((parts[0].to_string(), parts[1].to_string()));
        }
    }
    None
}

/// Info resolved from a git dependency
#[derive(Debug, Clone)]
pub struct GitResolved {
    pub name: String,
    pub version: String,
    pub resolved_url: String,
    pub tarball_data: Vec<u8>,
    pub dependencies: HashMap<String, String>,
    pub optional_dependencies: HashMap<String, String>,
    pub has_install_script: bool,
}

/// Resolve a git spec: download the tarball and read package.json
pub async fn resolve_git_spec(spec: &GitSpec, http: &reqwest::Client) -> Result<GitResolved> {
    let git_ref = spec.git_ref.as_deref().unwrap_or("HEAD");

    // For GitHub repos, use the tarball API
    if let Some((user, repo)) = &spec.github_repo {
        return resolve_github_tarball(user, repo, git_ref, http).await;
    }

    // For other git repos, try the git CLI
    resolve_via_git_clone(&spec.url, git_ref).await
}

async fn resolve_github_tarball(
    user: &str,
    repo: &str,
    git_ref: &str,
    http: &reqwest::Client,
) -> Result<GitResolved> {
    // GitHub tarball API: GET /repos/{user}/{repo}/tarball/{ref}
    // This returns a 302 redirect to the actual tarball
    let api_url = if git_ref == "HEAD" {
        format!("https://api.github.com/repos/{}/{}/tarball", user, repo)
    } else {
        format!(
            "https://api.github.com/repos/{}/{}/tarball/{}",
            user, repo, git_ref
        )
    };

    tracing::debug!("fetching github tarball: {}", api_url);

    let resp = http
        .get(&api_url)
        .header("User-Agent", "oath-pm")
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .context("GitHub API request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "GitHub API returned {}: {} for {}/{}",
            status,
            body,
            user,
            repo
        );
    }

    let data = resp
        .bytes()
        .await
        .context("failed to read tarball")?
        .to_vec();

    parse_git_tarball(
        data,
        &format!("git+https://github.com/{}/{}.git", user, repo),
        git_ref,
    )
}

async fn resolve_via_git_clone(url: &str, git_ref: &str) -> Result<GitResolved> {
    use std::process::Command;

    let tmp = tempfile::tempdir().context("failed to create tempdir")?;
    let clone_dir = tmp.path().join("repo");

    // Try shallow clone with specific ref
    let clone_status = if git_ref == "HEAD" {
        Command::new("git")
            .args(["clone", "--depth", "1", url, clone_dir.to_str().unwrap()])
            .output()
    } else {
        Command::new("git")
            .args([
                "clone",
                "--depth",
                "1",
                "--branch",
                git_ref,
                url,
                clone_dir.to_str().unwrap(),
            ])
            .output()
    };

    let output = clone_status.context("failed to run git clone (is git installed?)")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git clone failed for {}: {}", url, stderr);
    }

    // Read package.json from clone dir
    let pkg_json_path = clone_dir.join("package.json");
    let pkg_json_data =
        std::fs::read(&pkg_json_path).with_context(|| format!("no package.json in {}", url))?;

    let packlist = crate::placement::npm_packlist(&clone_dir)?;
    prune_git_package_metadata(&clone_dir)?;
    let tar_data = repack_git_package(&clone_dir, &packlist)?;

    parse_git_tarball_from_json(tar_data, &pkg_json_data, url, git_ref)
}

fn parse_git_tarball(data: Vec<u8>, resolved_url: &str, _git_ref: &str) -> Result<GitResolved> {
    // Extract to tempdir and read package.json
    let tmp = tempfile::tempdir().context("failed to create tempdir for git tarball")?;
    oath_fetch::tarball::extract_tarball(&data, tmp.path())
        .context("failed to extract git tarball")?;

    // Find package.json - it's at the root of the extracted dir
    let pkg_json_path = tmp.path().join("package.json");
    let pkg_json_data = std::fs::read(&pkg_json_path)
        .with_context(|| format!("no package.json in tarball from {}", resolved_url))?;
    let packlist = crate::placement::npm_packlist(tmp.path())?;
    prune_git_package_metadata(tmp.path())?;
    let normalized = repack_git_package(tmp.path(), &packlist)?;

    parse_git_tarball_from_json(normalized, &pkg_json_data, resolved_url, _git_ref)
}

fn prune_git_package_metadata(root: &std::path::Path) -> Result<()> {
    for name in [
        ".git",
        ".gitignore",
        ".npmignore",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "pnpm-lock.yaml",
        "yarn.lock",
    ] {
        let path = root.join(name);
        if path.is_dir() {
            std::fs::remove_dir_all(&path)?;
        } else if path.exists() {
            std::fs::remove_file(&path)?;
        }
    }
    Ok(())
}

fn repack_git_package(root: &std::path::Path, files: &[std::path::PathBuf]) -> Result<Vec<u8>> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    let mut tar_data = Vec::new();
    {
        let enc = GzEncoder::new(&mut tar_data, Compression::default());
        let mut tar = tar::Builder::new(enc);
        for relative in files {
            let source = root.join(relative);
            // npm-packlist never includes its controlling ignore files, but
            // root package-manager metadata is pruned before this point as an
            // additional guard. A disappearing entry is therefore skipped.
            if !source.symlink_metadata().is_ok() {
                continue;
            }
            let archive_path = std::path::Path::new("package").join(relative);
            tar.append_path_with_name(&source, &archive_path)
                .with_context(|| format!("pack git dependency file {}", relative.display()))?;
        }
        tar.finish()
            .context("failed to finalize git package tarball")?;
    }
    Ok(tar_data)
}

fn parse_git_tarball_from_json(
    tarball_data: Vec<u8>,
    pkg_json_data: &[u8],
    resolved_url: &str,
    _git_ref: &str,
) -> Result<GitResolved> {
    let pkg_json: serde_json::Value = serde_json::from_slice(pkg_json_data)
        .context("failed to parse package.json from git repo")?;

    let name = pkg_json["name"]
        .as_str()
        .with_context(|| format!("no 'name' in package.json from {}", resolved_url))?
        .to_string();

    let version = pkg_json["version"].as_str().unwrap_or("0.0.0").to_string();

    let dependencies = extract_deps_from_json(&pkg_json, "dependencies");
    let optional_dependencies = extract_deps_from_json(&pkg_json, "optionalDependencies");

    let has_install_script = pkg_json
        .get("scripts")
        .and_then(|s| s.as_object())
        .is_some_and(|scripts| {
            scripts.contains_key("install")
                || scripts.contains_key("preinstall")
                || scripts.contains_key("postinstall")
        });

    Ok(GitResolved {
        name,
        version,
        resolved_url: resolved_url.to_string(),
        tarball_data,
        dependencies,
        optional_dependencies,
        has_install_script,
    })
}

fn extract_deps_from_json(pkg: &serde_json::Value, key: &str) -> HashMap<String, String> {
    pkg.get(key)
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

fn safe_cache_component(input: &str) -> String {
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
    use super::{git_cache_file_name, parse_git_spec, prune_git_package_metadata};

    #[test]
    fn git_cache_file_name_encodes_path_separators() {
        assert_eq!(
            git_cache_file_name("../evil", "../../outside"),
            "..+evil-..%2F..%2Foutside.tgz"
        );
    }

    #[test]
    fn parses_github_ssh_url_with_commit_for_tarball_api() {
        let spec = parse_git_spec(
            "git+ssh://git@github.com/webpack/tooling.git#978dc1c9680ef7d79f5f5c02c3439385d7937c39",
        )
        .unwrap();
        assert_eq!(spec.url, "https://github.com/webpack/tooling.git");
        assert_eq!(spec.github_repo, Some(("webpack".into(), "tooling".into())));
        assert_eq!(
            spec.git_ref.as_deref(),
            Some("978dc1c9680ef7d79f5f5c02c3439385d7937c39")
        );
    }

    #[test]
    fn prunes_root_package_manager_metadata_from_git_packages() {
        let root = tempfile::tempdir().unwrap();
        for name in ["yarn.lock", ".npmignore", "package-lock.json"] {
            std::fs::write(root.path().join(name), b"metadata").unwrap();
        }
        std::fs::write(root.path().join("index.js"), b"module.exports = 1").unwrap();
        prune_git_package_metadata(root.path()).unwrap();
        assert!(root.path().join("index.js").exists());
        assert!(!root.path().join("yarn.lock").exists());
        assert!(!root.path().join(".npmignore").exists());
        assert!(!root.path().join("package-lock.json").exists());
    }
}
