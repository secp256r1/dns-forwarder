use log::info;

mod cache;
mod config;
mod dns;
mod server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let config_path = std::env::args()
        .nth(1)
        .map(std::path::PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("usage: dns-forwarder <config.toml>"))?;

    info!("loading config from {}", config_path.display());
    config::init(&config_path)?;
    let config = config::config()?;
    cache::init(config.cache.max_entries).await;
    server::run().await
}
