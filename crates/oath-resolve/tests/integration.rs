//! Integration test: resolve real dependency trees

use oath_fetch::RegistryClient;
use oath_resolve::{Resolver, Lockfile};
use oath_resolve::resolver::ResolveOptions;
use std::collections::HashMap;

#[tokio::test]
async fn test_resolve_is_number() {
    // is-number has zero dependencies -- simplest case
    let client = RegistryClient::default_client().unwrap();
    let mut resolver = Resolver::new(client, ResolveOptions::default());

    let mut deps = HashMap::new();
    deps.insert("is-number".to_string(), "^7.0.0".to_string());

    let graph = resolver.resolve(&deps, &HashMap::new()).await.unwrap();

    assert_eq!(graph.package_count(), 1);
    let node = graph.get("is-number@7.0.0").unwrap();
    assert_eq!(node.name, "is-number");
    assert_eq!(node.version, "7.0.0");
    assert!(node.integrity.is_some());
    assert!(node.dependencies.is_empty());
    println!("resolved is-number: {node:?}");
}

#[tokio::test]
async fn test_resolve_chalk() {
    // chalk has a small dependency tree (~5 deps)
    let client = RegistryClient::default_client().unwrap();
    let mut resolver = Resolver::new(client, ResolveOptions {
        include_dev: false,
        include_optional: false,
        max_depth: 256,
    });

    let mut deps = HashMap::new();
    deps.insert("chalk".to_string(), "^5.0.0".to_string());

    let graph = resolver.resolve(&deps, &HashMap::new()).await.unwrap();

    // chalk 5.x has minimal deps (just ansi-styles in older versions, zero in 5.3+)
    println!("chalk resolved {} packages:", graph.package_count());
    for (key, node) in &graph.nodes {
        println!("  {key}: deps={:?}", node.dependencies.keys().collect::<Vec<_>>());
    }

    // Should be small (chalk 5+ is pure ESM with no deps)
    assert!(graph.package_count() <= 5);
}

#[tokio::test]
async fn test_resolve_multiple_direct_deps() {
    let client = RegistryClient::default_client().unwrap();
    let mut resolver = Resolver::new(client, ResolveOptions {
        include_dev: false,
        include_optional: false,
        max_depth: 256,
    });

    let mut deps = HashMap::new();
    deps.insert("is-number".to_string(), "^7.0.0".to_string());
    deps.insert("is-odd".to_string(), "^3.0.0".to_string());

    let graph = resolver.resolve(&deps, &HashMap::new()).await.unwrap();

    println!("resolved {} packages:", graph.package_count());
    for (key, _) in &graph.nodes {
        println!("  {key}");
    }

    // is-odd depends on is-number, so we should see dedup
    assert!(graph.package_count() >= 2);
    assert!(graph.roots.len() == 2);
}

#[tokio::test]
async fn test_resolve_and_write_lockfile() {
    let client = RegistryClient::default_client().unwrap();
    let mut resolver = Resolver::new(client, ResolveOptions {
        include_dev: false,
        include_optional: false,
        max_depth: 256,
    });

    let mut deps = HashMap::new();
    deps.insert("is-number".to_string(), "^7.0.0".to_string());

    let graph = resolver.resolve(&deps, &HashMap::new()).await.unwrap();
    let lockfile = Lockfile::from_graph(&graph, "test-project", "1.0.0");

    // Write to temp file
    let tmp = tempfile::NamedTempFile::new().unwrap();
    lockfile.write(tmp.path()).unwrap();

    // Read back
    let loaded = Lockfile::read(tmp.path()).unwrap();
    assert_eq!(loaded.lockfile_version, 1);
    assert_eq!(loaded.name, "test-project");
    assert_eq!(loaded.package_count(), 1);
    assert!(loaded.is_locked("is-number", "7.0.0"));

    let content = std::fs::read_to_string(tmp.path()).unwrap();
    println!("lockfile:\n{content}");
}

#[tokio::test]
async fn test_resolve_express() {
    // Express has ~60 transitive deps. Real-world test.
    let client = RegistryClient::default_client().unwrap();
    let mut resolver = Resolver::new(client, ResolveOptions {
        include_dev: false,
        include_optional: false,
        max_depth: 256,
    });

    let mut deps = HashMap::new();
    deps.insert("express".to_string(), "^4.18.0".to_string());

    let graph = resolver.resolve(&deps, &HashMap::new()).await.unwrap();

    println!("express resolved {} packages", graph.package_count());

    // Express 4.x has ~60 deps total
    assert!(graph.package_count() > 25);
    assert!(graph.package_count() < 100);

    // Check for some known deps
    let has_body_parser = graph.nodes.keys().any(|k| k.starts_with("body-parser@"));
    let has_cookie = graph.nodes.keys().any(|k| k.starts_with("cookie@"));
    assert!(has_body_parser, "missing body-parser");
    assert!(has_cookie, "missing cookie");

    // Check install scripts
    let scripts = graph.packages_with_install_scripts();
    println!("packages with install scripts: {}", scripts.len());
    for pkg in &scripts {
        println!("  WARNING: {}@{} has install scripts", pkg.name, pkg.version);
    }
}
