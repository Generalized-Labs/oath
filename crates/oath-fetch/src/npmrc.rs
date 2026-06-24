//! Minimal `.npmrc` parser: default registry, per-scope registries, and
//! per-host auth tokens. This is what lets oath work against private registries
//! (Verdaccio, GitHub Packages, Artifactory, corporate mirrors) instead of only
//! registry.npmjs.org.
//!
//! Supported directives (npm-compatible subset):
//!   registry=https://registry.npmjs.org/
//!   @myorg:registry=https://npm.pkg.github.com/
//!   //npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
//!   //registry.npmjs.org/:_authToken=npm_xxx
//!
//! Precedence (low -> high): $HOME/.npmrc, ./.npmrc, then the OATH_REGISTRY /
//! npm_config_registry env var (overrides the default registry only).
//! `${VAR}` references are expanded from the environment, like npm.

use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct NpmrcConfig {
    /// Default registry URL (no trailing slash), if configured.
    pub default_registry: Option<String>,
    /// "@scope" -> registry URL (no trailing slash).
    pub scoped_registries: HashMap<String, String>,
    /// host -> auth token.
    pub tokens: HashMap<String, String>,
}

impl NpmrcConfig {
    /// Load and merge `.npmrc` files plus the registry env override.
    pub fn load(project_dir: &Path) -> Self {
        let mut cfg = NpmrcConfig::default();
        if let Some(home) = std::env::var_os("HOME") {
            cfg.merge_file(&Path::new(&home).join(".npmrc"));
        }
        cfg.merge_file(&project_dir.join(".npmrc"));

        if let Ok(reg) = std::env::var("OATH_REGISTRY")
            .or_else(|_| std::env::var("npm_config_registry"))
        {
            if !reg.is_empty() {
                cfg.default_registry = Some(normalize_registry(&reg));
            }
        }
        cfg
    }

    fn merge_file(&mut self, path: &Path) {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return,
        };
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let Some((key, raw_val)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let val = expand_env(raw_val.trim());
            if val.is_empty() && !key.starts_with("//") {
                continue;
            }

            if key == "registry" {
                self.default_registry = Some(normalize_registry(&val));
            } else if let Some(scope) = key.strip_suffix(":registry") {
                // e.g. "@myorg:registry"
                if scope.starts_with('@') {
                    self.scoped_registries
                        .insert(scope.to_string(), normalize_registry(&val));
                }
            } else if let Some(host_path) = key.strip_suffix(":_authToken") {
                // e.g. "//npm.pkg.github.com/:_authToken" or "//host/path/:_authToken"
                if let Some(host) = host_from_npmrc_key(host_path) {
                    if !val.is_empty() {
                        self.tokens.insert(host, val);
                    }
                }
            }
        }
    }

    pub fn token_for_host(&self, host: &str) -> Option<&str> {
        self.tokens.get(host).map(String::as_str)
    }
}

/// Strip a trailing slash so `{registry}/{name}` joins cleanly.
fn normalize_registry(url: &str) -> String {
    url.trim_end_matches('/').to_string()
}

/// Extract the host from an npmrc auth key like `//host/path/`.
fn host_from_npmrc_key(key: &str) -> Option<String> {
    let trimmed = key.trim_start_matches('/');
    let host = trimmed.split('/').next().unwrap_or(trimmed);
    let host = host.split(':').next().unwrap_or(host); // drop any :port
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Expand `${VAR}` references from the environment (npm-compatible).
fn expand_env(s: &str) -> String {
    let mut out = s.to_string();
    while let Some(start) = out.find("${") {
        match out[start + 2..].find('}') {
            Some(rel_end) => {
                let end = start + 2 + rel_end;
                let var = out[start + 2..end].to_string();
                let val = std::env::var(&var).unwrap_or_default();
                out.replace_range(start..=end, &val);
            }
            None => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_registry_scope_and_token() {
        let dir = tempfile::tempdir().unwrap();
        let npmrc = dir.path().join(".npmrc");
        std::fs::write(
            &npmrc,
            "registry=https://mirror.example.com/\n\
             @myorg:registry=https://npm.pkg.github.com\n\
             //npm.pkg.github.com/:_authToken=secret123\n\
             # a comment\n",
        )
        .unwrap();

        let mut cfg = NpmrcConfig::default();
        cfg.merge_file(&npmrc);

        assert_eq!(cfg.default_registry.as_deref(), Some("https://mirror.example.com"));
        assert_eq!(
            cfg.scoped_registries.get("@myorg").map(String::as_str),
            Some("https://npm.pkg.github.com")
        );
        assert_eq!(cfg.token_for_host("npm.pkg.github.com"), Some("secret123"));
    }

    #[test]
    fn expands_env_token() {
        // SAFETY: single-threaded test process.
        unsafe { std::env::set_var("OATH_TEST_TOKEN", "tok-xyz") };
        let dir = tempfile::tempdir().unwrap();
        let npmrc = dir.path().join(".npmrc");
        std::fs::write(&npmrc, "//host.example/:_authToken=${OATH_TEST_TOKEN}\n").unwrap();
        let mut cfg = NpmrcConfig::default();
        cfg.merge_file(&npmrc);
        assert_eq!(cfg.token_for_host("host.example"), Some("tok-xyz"));
    }
}
