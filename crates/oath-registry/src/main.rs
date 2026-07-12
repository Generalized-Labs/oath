#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let data = std::path::PathBuf::from(
        std::env::var("OATH_REGISTRY_DATA").unwrap_or_else(|_| ".oath-registry".into()),
    );
    let object_store =
        oath_registry::object_backend::artifact_store_from_env(data.join("objects"))?;
    let database_url = std::env::var("DATABASE_URL").map_err(|_| {
        anyhow::anyhow!(
            "DATABASE_URL is required; SQLite is no longer supported by the live registry"
        )
    })?;
    let registry = oath_registry::postgres_api::PostgresRegistry::connect(
        &database_url,
        object_store,
        &data.join("registry-signing.key"),
    )
    .await?;
    if let Ok(token) = std::env::var("OATH_REGISTRY_TOKEN") {
        let organization = std::env::var("OATH_REGISTRY_ORG").unwrap_or_else(|_| "default".into());
        registry
            .bootstrap_token(&organization, &token, "admin")
            .await?;
    }
    let app = oath_registry::postgres_api::router(registry);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:4873").await?;
    tracing::info!("oath-registry listening on :4873");
    axum::serve(listener, app).await?;
    Ok(())
}
