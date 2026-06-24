//! Integration test: fetch real packages from npm registry
//!
//! These tests hit the real npm registry. They verify that our
//! protocol implementation actually works against production.

use oath_fetch::tarball;
use oath_fetch::{RegistryClient, resolve_version};

#[tokio::test]
async fn test_fetch_express_packument() {
    let client = RegistryClient::default_client().unwrap();
    let packument = client.fetch_packument("express").await.unwrap();

    assert_eq!(packument.name, "express");
    assert!(packument.dist_tags.contains_key("latest"));
    assert!(!packument.versions.is_empty());

    // Express has many versions
    assert!(packument.versions.len() > 50);

    // Latest should be a valid version
    let latest = packument.latest_version().unwrap();
    assert!(latest.contains('.'));
    println!("express@latest = {latest}");
}

#[tokio::test]
async fn test_resolve_express_caret() {
    let client = RegistryClient::default_client().unwrap();
    let packument = client.fetch_packument("express").await.unwrap();

    // ^4.0.0 should resolve to something >= 4.0.0 and < 5.0.0
    let resolved = resolve_version(&packument, "^4.0.0").unwrap();
    let major: u32 = resolved.version.split('.').next().unwrap().parse().unwrap();
    assert_eq!(major, 4);
    println!("express@^4.0.0 resolved to {}", resolved.version);

    // Check that it has dependencies
    assert!(!resolved.info.dependencies.is_empty());
    println!(
        "  dependencies: {:?}",
        resolved.info.dependencies.keys().collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_fetch_scoped_package() {
    let client = RegistryClient::default_client().unwrap();
    let packument = client.fetch_packument("@types/node").await.unwrap();

    assert_eq!(packument.name, "@types/node");
    assert!(packument.versions.len() > 100);
    println!("@types/node has {} versions", packument.versions.len());
}

#[tokio::test]
async fn test_download_and_verify_tarball() {
    let client = RegistryClient::default_client().unwrap();
    let packument = client.fetch_packument("is-number").await.unwrap();

    // is-number is tiny, good for testing
    let latest = packument.latest_version().unwrap();
    let info = packument.version_info(latest).unwrap();

    println!("is-number@{latest}");
    println!("  tarball: {}", info.dist.tarball);
    println!("  integrity: {:?}", info.dist.integrity);
    println!("  size: {:?}", info.dist.unpacked_size);

    // Download tarball
    let data = client
        .fetch_tarball(&info.dist.tarball, info.dist.integrity.as_deref())
        .await
        .unwrap();

    assert!(!data.is_empty());
    println!("  downloaded {} bytes", data.len());

    // List files
    let files = tarball::list_tarball(&data).unwrap();
    assert!(!files.is_empty());
    println!("  files: {:?}", files);

    // Should contain package.json and index.js
    assert!(files.iter().any(|f| f == "package.json"));
}

#[tokio::test]
async fn test_extract_tarball() {
    let client = RegistryClient::default_client().unwrap();
    let packument = client.fetch_packument("is-number").await.unwrap();
    let latest = packument.latest_version().unwrap();
    let info = packument.version_info(latest).unwrap();

    let data = client
        .fetch_tarball(&info.dist.tarball, info.dist.integrity.as_deref())
        .await
        .unwrap();

    // Extract to temp dir
    let tmp = tempfile::tempdir().unwrap();
    tarball::extract_tarball(&data, tmp.path()).unwrap();

    // Verify package.json exists
    let pkg_json = tmp.path().join("package.json");
    assert!(pkg_json.exists());

    // Parse it
    let content = std::fs::read_to_string(&pkg_json).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(parsed["name"], "is-number");
    println!("extracted is-number@{latest} to {}", tmp.path().display());
}

#[tokio::test]
async fn test_integrity_verification_fails() {
    let client = RegistryClient::default_client().unwrap();
    let packument = client.fetch_packument("is-number").await.unwrap();
    let latest = packument.latest_version().unwrap();
    let info = packument.version_info(latest).unwrap();

    // Download without verification first
    let data = client
        .fetch_tarball(&info.dist.tarball, None)
        .await
        .unwrap();

    // Verify with correct integrity should pass
    if let Some(ref integrity) = info.dist.integrity {
        tarball::verify_integrity(&data, integrity).unwrap();
    }

    // Verify with wrong integrity should fail
    let fake_integrity = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    assert!(tarball::verify_integrity(&data, fake_integrity).is_err());
}

#[tokio::test]
async fn test_nonexistent_package() {
    let client = RegistryClient::default_client().unwrap();
    let result = client
        .fetch_packument("this-package-definitely-does-not-exist-abc123xyz789")
        .await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("not found"), "unexpected error: {err}");
}
