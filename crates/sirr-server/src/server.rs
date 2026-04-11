use axum::{routing::get, Router};

pub async fn run() -> anyhow::Result<()> {
    let app = Router::new().route("/health", get(|| async { "ok" }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:7843").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
