use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use oath_registry::postgres_api::PostgresRegistry;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let mode = std::env::args().nth(1).unwrap_or_else(|| "serve".into());
    if mode == "migrate" {
        let database_url = std::env::var("OATH_MIGRATION_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .context("OATH_MIGRATION_DATABASE_URL or DATABASE_URL is required")?;
        oath_registry::control_plane::PostgresControlPlane::migrate_url(&database_url).await?;
        tracing::info!("registry migrations completed");
        return Ok(());
    }
    if mode == "analysis-worker" {
        return run_analysis_worker().await;
    }

    let registry = Arc::new(connect_registry().await?);
    bootstrap(&registry).await?;
    match mode.as_str() {
        "serve" | "api" => serve(registry).await,
        "outbox-worker" => run_outbox_worker(registry).await,
        "maintenance-worker" => run_maintenance_worker(registry).await,
        value => anyhow::bail!(
            "unknown registry mode `{value}`; use serve, analysis-worker, outbox-worker, maintenance-worker, or migrate"
        ),
    }
}

async fn connect_registry() -> Result<PostgresRegistry> {
    let database_url = std::env::var("OATH_WORKER_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .context("DATABASE_URL is required; SQLite is unsupported")?;
    let data = PathBuf::from(
        std::env::var("OATH_REGISTRY_DATA").unwrap_or_else(|_| ".oath-registry".into()),
    );
    let objects = oath_registry::object_backend::artifact_store_from_env(data.join("objects"))?;
    PostgresRegistry::connect(&database_url, objects, &data.join("registry-signing.key")).await
}

async fn bootstrap(registry: &PostgresRegistry) -> Result<()> {
    if let Ok(token) = std::env::var("OATH_REGISTRY_TOKEN") {
        let organization = std::env::var("OATH_REGISTRY_ORG").unwrap_or_else(|_| "default".into());
        registry
            .bootstrap_token(&organization, &token, "admin")
            .await?;
    }
    Ok(())
}

async fn serve(registry: Arc<PostgresRegistry>) -> Result<()> {
    let bind = std::env::var("OATH_REGISTRY_BIND").unwrap_or_else(|_| "0.0.0.0:4873".into());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(%bind, mode = "api", "oath-registry listening");
    axum::serve(
        listener,
        oath_registry::postgres_api::router((*registry).clone()),
    )
    .await?;
    Ok(())
}

async fn run_analysis_worker() -> Result<()> {
    let token = std::env::var("OATH_ANALYZER_TOKEN")
        .context("OATH_ANALYZER_TOKEN is required for analysis-worker")?;
    let bind = std::env::var("OATH_ANALYZER_BIND").unwrap_or_else(|_| "0.0.0.0:4874".into());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(%bind, mode = "analysis-worker", "oath analyzer listening");
    axum::serve(
        listener,
        oath_registry::analysis_backend::worker_router(&token),
    )
    .await?;
    Ok(())
}

async fn run_outbox_worker(registry: Arc<PostgresRegistry>) -> Result<()> {
    tracing::info!(mode = "outbox-worker", "oath registry worker started");
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    loop {
        interval.tick().await;
        if let Err(error) = registry.drain_outbox().await {
            tracing::warn!(%error, "registry audit outbox worker failed");
        }
    }
}

async fn run_maintenance_worker(registry: Arc<PostgresRegistry>) -> Result<()> {
    tracing::info!(mode = "maintenance-worker", "oath registry worker started");
    let mut interval = tokio::time::interval(Duration::from_secs(3600));
    loop {
        interval.tick().await;
        if let Err(error) = registry.prune_expired_rate_limits().await {
            tracing::warn!(%error, "registry rate-limit maintenance failed");
        }
    }
}
