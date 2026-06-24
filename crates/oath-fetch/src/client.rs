//! Registry HTTP client
//!
//! Speaks the npm registry protocol. Supports abbreviated metadata,
//! etag caching, and multiple registry sources.

use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, ETAG, IF_NONE_MATCH};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::packument::Packument;

/// Abbreviated packument Accept header (much smaller than full application/json)
const ABBREVIATED_ACCEPT: &str = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8";

/// TTL for disk cache in seconds: if the cached file is younger than this,
/// return it directly without any HTTP request.
const CACHE_TTL_SECS: u64 = 300; // 5 minutes

/// Registry client configuration
#[derive(Debug, Clone)]
pub struct RegistryConfig {
    /// Default registry URL (default: https://registry.npmjs.org)
    pub registry_url: String,
    /// Per-scope registry overrides: "@scope" -> registry URL.
    pub scoped_registries: HashMap<String, String>,
    /// Per-host auth tokens: host -> token.
    pub tokens: HashMap<String, String>,
    /// Directory for cached packuments
    pub cache_dir: PathBuf,
    /// Legacy single auth token (applied to the default registry host).
    pub token: Option<String>,
    /// Request timeout in seconds
    pub timeout_secs: u64,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        let cache_dir = dirs_home()
            .join(".oath")
            .join("cache")
            .join("registry");
        Self {
            registry_url: "https://registry.npmjs.org".to_string(),
            scoped_registries: HashMap::new(),
            tokens: HashMap::new(),
            cache_dir,
            token: None,
            timeout_secs: 10,
        }
    }
}

impl RegistryConfig {
    /// Build config from the project's and user's `.npmrc` (+ OATH_REGISTRY env).
    /// This is what enables private/scoped/mirror registries.
    pub fn from_npmrc(project_dir: &Path) -> Self {
        let npmrc = crate::npmrc::NpmrcConfig::load(project_dir);
        let mut cfg = RegistryConfig::default();
        if let Some(reg) = npmrc.default_registry {
            cfg.registry_url = reg;
        }
        cfg.scoped_registries = npmrc.scoped_registries;
        cfg.tokens = npmrc.tokens;
        cfg
    }
}

fn dirs_home() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()))
}

/// Extract the host from a URL (for per-host auth lookup).
fn host_of(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
}

/// The main registry client. Thread-safe, cloneable.
#[derive(Clone)]
pub struct RegistryClient {
    config: RegistryConfig,
    http: reqwest::Client,
    /// In-memory etag cache: package_name -> etag
    etag_cache: Arc<RwLock<HashMap<String, String>>>,
}

impl RegistryClient {
    /// Create a new registry client
    pub fn new(mut config: RegistryConfig) -> Result<Self> {
        let mut headers = HeaderMap::new();

        // Use abbreviated packument format -- much smaller than full application/json
        // vnd.npm.install-v1+json is ~100x smaller for large packages like babel
        headers.insert(
            ACCEPT,
            HeaderValue::from_static(ABBREVIATED_ACCEPT),
        );

        // Fold a legacy single token into the per-host map (keyed by the default
        // registry's host). Auth is attached per-request by host, because a
        // scoped package may route to a different registry than the default.
        if let Some(token) = config.token.clone() {
            if let Some(host) = host_of(&config.registry_url) {
                config.tokens.entry(host).or_insert(token);
            }
        }

        let http = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .gzip(true)
            .tcp_nodelay(true)
            .pool_max_idle_per_host(32)
            .build()
            .context("failed to build HTTP client")?;

        // Ensure cache dir exists
        std::fs::create_dir_all(&config.cache_dir).ok();

        Ok(Self {
            config,
            http,
            etag_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Create a client, loading registry + auth config from `.npmrc` (project and
    /// home) plus the OATH_REGISTRY env var. Falls back to registry.npmjs.org.
    pub fn default_client() -> Result<Self> {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        Self::new(RegistryConfig::from_npmrc(&cwd))
    }

    /// Fetch a packument (package metadata) from the registry.
    /// Uses etag caching -- returns cached version if unchanged.
    pub async fn fetch_packument(&self, name: &str) -> Result<Packument> {
        let url = self.package_url(name);
        tracing::debug!("fetching packument: {url}");

        // Fast path: check disk cache first with TTL
        // If the cached file is fresh (< CACHE_TTL_SECS), use it directly without HTTP
        let cache_path = self.cache_path(name);
        if let Ok(meta) = std::fs::metadata(&cache_path) {
            if let Ok(modified) = meta.modified() {
                let age = std::time::SystemTime::now()
                    .duration_since(modified)
                    .unwrap_or_default();
                if age.as_secs() < CACHE_TTL_SECS {
                    if let Ok(data) = std::fs::read(&cache_path) {
                        if let Ok(packument) = serde_json::from_slice::<Packument>(&data) {
                            tracing::debug!("{name}: disk cache hit ({}s old)", age.as_secs());
                            return Ok(packument);
                        }
                    }
                }
            }
        }

        let mut req = self.http.get(&url);
        if let Some(tok) = self.token_for_url(&url) {
            req = req.bearer_auth(tok);
        }

        // Attach etag for conditional request
        let etag_cache = self.etag_cache.read().await;
        if let Some(etag) = etag_cache.get(name) {
            req = req.header(IF_NONE_MATCH, etag.as_str());
        } else {
            // Try to load persisted etag from disk sidecar file
            let etag_path = self.etag_path(name);
            if let Ok(etag_str) = std::fs::read_to_string(&etag_path) {
                let etag_str = etag_str.trim().to_string();
                req = req.header(IF_NONE_MATCH, etag_str.as_str());
            }
        }
        drop(etag_cache);

        let resp = req.send().await.context("registry request failed")?;

        // Check for 304 Not Modified
        if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
            tracing::debug!("{name}: not modified (etag cache hit)");
            return self.load_cached_packument(name).await;
        }

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            anyhow::bail!("package not found: {name}");
        }

        if !resp.status().is_success() {
            anyhow::bail!(
                "registry returned {}: {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            );
        }

        // Store new etag
        if let Some(etag) = resp.headers().get(ETAG) {
            if let Ok(etag_str) = etag.to_str() {
                let mut cache = self.etag_cache.write().await;
                cache.insert(name.to_string(), etag_str.to_string());
                // Persist etag to disk for use across process restarts
                let etag_path = self.etag_path(name);
                tokio::fs::write(&etag_path, etag_str).await.ok();
            }
        }

        let body = resp.bytes().await.context("failed to read response body")?;

        // Cache to disk
        self.write_cache(name, &body).await;

        // Parse
        let packument: Packument =
            serde_json::from_slice(&body).context("failed to parse packument")?;

        Ok(packument)
    }

    /// Fetch full (non-abbreviated) packument for detailed info
    pub async fn fetch_packument_full(&self, name: &str) -> Result<serde_json::Value> {
        let url = self.package_url(name);

        let mut req = self.http.get(&url).header(ACCEPT, "application/json");
        if let Some(tok) = self.token_for_url(&url) {
            req = req.bearer_auth(tok);
        }
        let resp = req.send().await.context("registry request failed")?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            anyhow::bail!("package not found: {name}");
        }

        if !resp.status().is_success() {
            anyhow::bail!("registry returned {}", resp.status());
        }

        resp.json().await.context("failed to parse full packument")
    }

    /// Download a tarball, verify integrity, return bytes
    pub async fn fetch_tarball(&self, url: &str, expected_integrity: Option<&str>) -> Result<Vec<u8>> {
        tracing::debug!("downloading tarball: {url}");

        let mut req = self.http.get(url).header(ACCEPT, "application/octet-stream");
        if let Some(tok) = self.token_for_url(url) {
            req = req.bearer_auth(tok);
        }
        let resp = req.send().await.context("tarball download failed")?;

        if !resp.status().is_success() {
            anyhow::bail!("tarball download returned {}", resp.status());
        }

        let bytes = resp.bytes().await.context("failed to read tarball")?.to_vec();

        // Verify integrity if provided
        if let Some(sri) = expected_integrity {
            crate::tarball::verify_integrity(&bytes, sri)?;
        }

        Ok(bytes)
    }

    /// Search packages
    pub async fn search(&self, query: &str, limit: usize) -> Result<serde_json::Value> {
        let url = format!(
            "{}/-/v1/search?text={}&size={}",
            self.config.registry_url,
            urlencoding::encode(query),
            limit
        );

        let mut req = self.http.get(&url).header(ACCEPT, "application/json");
        if let Some(tok) = self.token_for_url(&url) {
            req = req.bearer_auth(tok);
        }
        let resp = req.send().await?;

        resp.json().await.context("failed to parse search results")
    }

    // -- Private helpers --

    /// Pick the registry for a package (per-scope override or default) and build
    /// the packument URL. Scoped packages keep the `@scope/name` path -- npm
    /// registries accept it directly.
    fn package_url(&self, name: &str) -> String {
        format!("{}/{}", self.registry_for(name), name)
    }

    /// The registry a package should be fetched from: a `@scope:registry`
    /// override if one matches, otherwise the default registry.
    fn registry_for(&self, name: &str) -> &str {
        if name.starts_with('@') {
            if let Some(scope) = name.split('/').next() {
                if let Some(reg) = self.config.scoped_registries.get(scope) {
                    return reg;
                }
            }
        }
        &self.config.registry_url
    }

    /// The auth token for a request URL, matched by host.
    fn token_for_url(&self, url: &str) -> Option<String> {
        let host = host_of(url)?;
        self.config.tokens.get(&host).cloned()
    }

    async fn write_cache(&self, name: &str, data: &[u8]) {
        let path = self.cache_path(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        tokio::fs::write(&path, data).await.ok();
    }

    async fn load_cached_packument(&self, name: &str) -> Result<Packument> {
        let path = self.cache_path(name);
        let data = tokio::fs::read(&path)
            .await
            .context("cache miss after 304")?;
        serde_json::from_slice(&data).context("corrupt cache entry")
    }

    fn cache_path(&self, name: &str) -> PathBuf {
        // @scope/name -> @scope__name
        let safe_name = name.replace('/', "__");
        self.config.cache_dir.join(format!("{safe_name}.json"))
    }

    fn etag_path(&self, name: &str) -> PathBuf {
        let safe_name = name.replace('/', "__");
        self.config.cache_dir.join(format!("{safe_name}.etag"))
    }
}

/// URL encoding helper (minimal, just for search)
mod urlencoding {
    pub fn encode(s: &str) -> String {
        let mut result = String::with_capacity(s.len());
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    result.push(b as char);
                }
                _ => {
                    result.push_str(&format!("%{b:02X}"));
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_with(scoped: &[(&str, &str)], tokens: &[(&str, &str)]) -> RegistryClient {
        let mut cfg = RegistryConfig::default();
        for (k, v) in scoped {
            cfg.scoped_registries.insert(k.to_string(), v.to_string());
        }
        for (k, v) in tokens {
            cfg.tokens.insert(k.to_string(), v.to_string());
        }
        RegistryClient::new(cfg).unwrap()
    }

    #[test]
    fn routes_scoped_packages_to_their_registry() {
        let c = client_with(&[("@myorg", "https://private.example")], &[]);
        assert_eq!(c.registry_for("@myorg/pkg"), "https://private.example");
        assert_eq!(c.registry_for("lodash"), "https://registry.npmjs.org");
        assert_eq!(c.package_url("@myorg/pkg"), "https://private.example/@myorg/pkg");
        assert_eq!(c.package_url("lodash"), "https://registry.npmjs.org/lodash");
    }

    #[test]
    fn attaches_token_by_host() {
        let c = client_with(&[], &[("private.example", "tok-1")]);
        assert_eq!(
            c.token_for_url("https://private.example/@myorg/pkg"),
            Some("tok-1".to_string())
        );
        assert_eq!(c.token_for_url("https://registry.npmjs.org/lodash"), None);
    }

    #[test]
    fn legacy_token_maps_to_default_registry_host() {
        let mut cfg = RegistryConfig::default();
        cfg.token = Some("legacy".to_string());
        let c = RegistryClient::new(cfg).unwrap();
        assert_eq!(
            c.token_for_url("https://registry.npmjs.org/lodash"),
            Some("legacy".to_string())
        );
    }
}
