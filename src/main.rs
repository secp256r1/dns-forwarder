use tracing::info;

mod cache;
mod config;
mod dns;
mod server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let config_path = std::env::args()
        .nth(1)
        .map(std::path::PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("usage: dns-forwarder <config.toml>"))?;

    info!("loading config from {}", config_path.display());
    config::init(&config_path)?;

    let config = config::config()?;
    if config.cache.enabled {
        cache::init(config.cache.max_entries, config.cache.ttl_seconds);
    }

    server::run().await
}
