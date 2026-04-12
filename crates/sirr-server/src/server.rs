use crate::handlers::{router, AppState};
use crate::store::{crypto, Store};
use std::sync::Arc;

pub async fn run() -> anyhow::Result<()> {
    let data_dir = crate::dirs::data_dir()?;
    let key_path = data_dir.join("sirr.key");

    let encryption_key = if key_path.exists() {
        let bytes = std::fs::read(&key_path)?;
        crypto::load_key(&bytes)
            .ok_or_else(|| anyhow::anyhow!("invalid key file at {}", key_path.display()))?
    } else {
        std::fs::create_dir_all(&data_dir)?;
        let key = crypto::generate_key();
        std::fs::write(&key_path, key.as_bytes())?;
        key
    };

    let store = Store::open(data_dir.join("sirr.db"))?;

    let state = AppState {
        store: Arc::new(store),
        encryption_key: Arc::new(encryption_key),
    };

    let app = router(state);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:7843").await?;
    tracing::info!("sirrd listening on 0.0.0.0:7843");
    axum::serve(listener, app).await?;
    Ok(())
}
