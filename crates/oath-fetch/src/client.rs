//! Registry HTTP client
//!
//! Speaks the npm registry protocol. Supports abbreviated metadata,
//! etag caching, and multiple registry sources.

use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, ETAG, IF_NONE_MATCH};
use std::collections::HashMap;
use std::path::PathBuf;
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
    /// Registry URL (default: https://registry.npmjs.org)
    pub registry_url: String,
    /// Directory for cached packuments
    pub cache_dir: PathBuf,
    /// Optional auth token
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
            cache_dir,
            token: None,
            timeout_secs: 10,
        }
    }
}

fn dirs_home() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()))
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
    pub fn new(config: RegistryConfig) -> Result<Self> {
        let mut headers = HeaderMap::new();

        // Use abbreviated packument format -- much smaller than full application/json
        // vnd.npm.install-v1+json is ~100x smaller for large packages like babel
        headers.insert(
            ACCEPT,
            HeaderValue::from_static(ABBREVIATED_ACCEPT),
        );

        if let Some(ref token) = config.token {
            headers.insert(
                "Authorization",
                HeaderValue::from_str(&format!("Bearer {token}"))
                    .context("invalid auth token")?,
            );
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

    /// Create a client with default config
    pub fn default_client() -> Result<Self> {
        Self::new(RegistryConfig::default())
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

        let resp = self
            .http
            .get(&url)
            .header(ACCEPT, "application/json")
            .send()
            .await
            .context("registry request failed")?;

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

        let resp = self
            .http
            .get(url)
            .header(ACCEPT, "application/octet-stream")
            .send()
            .await
            .context("tarball download failed")?;

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

        let resp = self
            .http
            .get(&url)
            .header(ACCEPT, "application/json")
            .send()
            .await?;

        resp.json().await.context("failed to parse search results")
    }

    // -- Private helpers --

    fn package_url(&self, name: &str) -> String {
        // Scoped packages: @scope/name -> @scope%2fname or just @scope/name
        // npm registry accepts both, so we use the path directly
        format!("{}/{}", self.config.registry_url, name)
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
