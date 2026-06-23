//! Package metadata fetching for npm registry.
//!
//! Fetches maintainer info, publish history, and download stats.

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::Value;

/// A package maintainer from the npm registry.
#[derive(Debug, Clone, Deserialize)]
pub struct Maintainer {
    pub name: String,
    pub email: Option<String>,
}

/// Metadata about an npm package including maintainers and publish info.
#[derive(Debug, Clone)]
pub struct PackageMetadata {
    pub name: String,
    pub latest_version: String,
    pub published_at: Option<String>,
    pub maintainers: Vec<Maintainer>,
    pub total_versions: usize,
    pub weekly_downloads: Option<u64>,
    pub has_readme: bool,
    pub license: Option<String>,
    pub repository: Option<String>,
    pub last_publish_age_days: Option<u64>,
}

/// Response from the npm downloads API.
#[derive(Debug, Deserialize)]
struct DownloadsResponse {
    downloads: Option<u64>,
}

/// Fetch full package metadata from the npm registry.
///
/// Makes two requests:
/// 1. Full packument from registry.npmjs.org
/// 2. Weekly download count from api.npmjs.org
pub async fn fetch_package_metadata(
    client: &reqwest::Client,
    package_name: &str,
) -> Result<PackageMetadata> {
    // Fetch full packument (not abbreviated)
    let registry_url = format!("https://registry.npmjs.org/{}", package_name);
    let packument: Value = client
        .get(&registry_url)
        .header("Accept", "application/json")
        .send()
        .await
        .context("Failed to fetch packument from registry")?
        .error_for_status()
        .context("Registry returned error status")?
        .json()
        .await
        .context("Failed to parse packument JSON")?;

    // Get dist-tags.latest
    let latest_version = packument
        .get("dist-tags")
        .and_then(|dt| dt.get("latest"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Parse maintainers array
    let maintainers: Vec<Maintainer> = packument
        .get("maintainers")
        .and_then(|m| serde_json::from_value(m.clone()).ok())
        .unwrap_or_default();

    // Get time object for publish dates
    let time_obj = packument.get("time");
    let published_at = time_obj
        .and_then(|t| t.get(&latest_version))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Calculate last_publish_age_days
    let last_publish_age_days = published_at.as_deref().and_then(parse_age_days);

    // Count total versions
    let total_versions = packument
        .get("versions")
        .and_then(|v| v.as_object())
        .map(|obj| obj.len())
        .unwrap_or(0);

    // Check readme presence
    let has_readme = packument
        .get("readme")
        .and_then(|r| r.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false);

    // Get license from latest version info
    let license = packument
        .get("versions")
        .and_then(|v| v.get(&latest_version))
        .and_then(|vi| vi.get("license"))
        .and_then(|l| l.as_str())
        .map(|s| s.to_string());

    // Get repository URL
    let repository = packument
        .get("repository")
        .and_then(|r| {
            if let Some(url) = r.get("url").and_then(|u| u.as_str()) {
                Some(url.to_string())
            } else if let Some(s) = r.as_str() {
                Some(s.to_string())
            } else {
                None
            }
        });

    // Fetch weekly downloads
    let weekly_downloads = fetch_weekly_downloads(client, package_name)
        .await
        .ok()
        .flatten();

    Ok(PackageMetadata {
        name: package_name.to_string(),
        latest_version,
        published_at,
        maintainers,
        total_versions,
        weekly_downloads,
        has_readme,
        license,
        repository,
        last_publish_age_days,
    })
}

/// Fetch weekly download count from the npm downloads API.
async fn fetch_weekly_downloads(client: &reqwest::Client, package_name: &str) -> Result<Option<u64>> {
    let url = format!(
        "https://api.npmjs.org/downloads/point/last-week/{}",
        package_name
    );
    let resp: DownloadsResponse = client
        .get(&url)
        .send()
        .await
        .context("Failed to fetch download stats")?
        .error_for_status()
        .context("Downloads API returned error status")?
        .json()
        .await
        .context("Failed to parse downloads JSON")?;

    Ok(resp.downloads)
}

/// Parse an ISO 8601 datetime string and return age in days from now.
/// Handles format like "2024-01-15T10:30:00.000Z"
fn parse_age_days(iso_date: &str) -> Option<u64> {
    // Extract year, month, day from ISO string
    let parts: Vec<&str> = iso_date.split('T').collect();
    let date_part = parts.first()?;
    let date_components: Vec<&str> = date_part.split('-').collect();
    if date_components.len() < 3 {
        return None;
    }

    let year: i64 = date_components[0].parse().ok()?;
    let month: i64 = date_components[1].parse().ok()?;
    let day: i64 = date_components[2].parse().ok()?;

    // Convert to days since epoch (approximate, good enough for age calculation)
    let publish_days = days_from_date(year, month, day);

    // Get current date
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    let now_days = (now.as_secs() / 86400) as i64;

    if now_days > publish_days {
        Some((now_days - publish_days) as u64)
    } else {
        Some(0)
    }
}

/// Convert a date to days since Unix epoch (approximate).
fn days_from_date(year: i64, month: i64, day: i64) -> i64 {
    // Using a simplified algorithm for days since epoch
    let mut y = year;
    let mut m = month;
    if m <= 2 {
        y -= 1;
        m += 12;
    }
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * (m - 3) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}
