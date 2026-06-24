use axum::{Json, Router, routing::get};
use serde_json::json;

async fn health() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok", "service": "oath-registry" }))
}

async fn package_meta(
    axum::extract::Path((scope, name)): axum::extract::Path<(String, String)>,
) -> Json<serde_json::Value> {
    // TODO: lookup from store
    Json(json!({
        "name": format!("@{scope}/{name}"),
        "versions": {}
    }))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let app = Router::new()
        .route("/health", get(health))
        .route("/@{scope}/{name}", get(package_meta));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:4873").await?;
    tracing::info!("oath-registry listening on :4873");
    axum::serve(listener, app).await?;
    Ok(())
}
