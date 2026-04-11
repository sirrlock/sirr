#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sirr_server::server::run().await
}
