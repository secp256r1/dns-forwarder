use std::{net::SocketAddr, sync::Arc};

use anyhow::{Result, anyhow, bail};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use crate::{
    cache,
    config::{Config, NftSet, config},
    dns::{
        Response, analyze_response, build_a_response, build_nxdomain_response, build_soa_response,
        parse_qname,
    },
};

pub async fn run() -> Result<()> {
    let config = config()?;

    let socket = Arc::new(UdpSocket::bind(config.listen).await?);
    info!("listening on {}", config.listen);

    let mut buf = [0u8; 512];

    loop {
        let (len, client_addr) = socket.recv_from(&mut buf).await?;
        let query = buf[..len].to_vec();

        let socket = socket.clone();

        tokio::spawn(async move {
            match forward(&query).await {
                Ok(response) => {
                    if let Err(e) = socket.send_to(&response, client_addr).await {
                        warn!("failed to send response to {}: {}", client_addr, e);
                    }
                }
                Err(e) => {
                    warn!("failed to forward query from {}: {}", client_addr, e);
                }
            }
        });
    }
}

async fn forward(query: &[u8]) -> Result<Vec<u8>> {
    if query.len() < 12 {
        bail!("query too short");
    }

    let qname = parse_qname(query)?;

    let config = config()?;

    let reversed_qname: String = qname.chars().rev().collect();

    if let Some((_, ip)) = config.local_domains.ancestor(&reversed_qname) {
        debug!("local domain match: {} -> {}", qname, ip);
        return build_a_response(query, &ip.octets());
    }

    if config.blocklist.ancestor(&reversed_qname).is_some() {
        debug!("private domain or blocklist match: {qname}");
        return build_nxdomain_response(query);
    }

    if config.cache.enabled {
        let key = query[2..].to_vec();
        match cache::get(&key) {
            Some(cached) => Ok([&query[..2], &cached].concat()),
            None => query_upstreams(&qname, query, &reversed_qname, config, Some(key)).await,
        }
    } else {
        query_upstreams(&qname, query, &reversed_qname, config, None).await
    }
}

async fn query_upstreams(
    qname: &str,
    query: &[u8],
    reversed_qname: &str,
    config: &Config,
    key: Option<Vec<u8>>,
) -> Result<Vec<u8>> {
    let rule = config
        .rules
        .iter()
        .find(|i| i.suffix_trie.ancestor(reversed_qname).is_some());

    let upstreams = rule.map(|i| &i.upstreams).unwrap_or(&config.upstream);

    let r = forward_to_upstreams(qname, query, upstreams).await?;

    let info = analyze_response(&r)?;

    if rule.map(|i| i.block_aaaa) == Some(true) && matches!(info, Response::Aaaa) {
        debug!("AAAA record detected, returning SOA response");
        return build_soa_response(query);
    }

    if let (Some(set), Response::A(a_records)) =
        (rule.as_ref().and_then(|i| i.nft_set.clone()), info)
        && !a_records.is_empty()
    {
        let qname = qname.to_string();
        let records = a_records.clone();
        tokio::task::spawn_blocking(move || add_to_nft_set(&qname, &set, &records)).await??;
    }

    if let Some(key) = key {
        cache::insert(key, r[2..].to_vec());
    }
    Ok(r)
}

async fn forward_to_upstreams(
    qname: &str,
    query: &[u8],
    upstreams: &[SocketAddr],
) -> Result<Vec<u8>> {
    let upstream = fastrand::choice(upstreams).ok_or_else(|| anyhow!("invalid upstreams"))?;

    let socket = UdpSocket::bind("0.0.0.0:0").await?;

    debug!("query {qname} from {upstream}");
    socket.send_to(query, upstream).await?;

    let mut buf = vec![0u8; 512];
    match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        socket.recv_from(&mut buf),
    )
    .await
    {
        Ok(Ok((len, _addr))) => Ok(buf[..len].to_vec()),
        Ok(Err(e)) => {
            bail!("query {qname} from {upstream} error: {e}");
        }
        Err(_) => {
            bail!("query {qname} from {upstream} timed out");
        }
    }
}

/// Add IP addresses to an nftables set.
/// Executes `nft add element <family> <table> <set> { <ip1>, <ip2>, ... }`.
fn add_to_nft_set(qname: &str, s: &NftSet, ips: &[String]) -> Result<()> {
    let config = config()?;

    let elements = ips
        .iter()
        .map(|ip| format!("{ip} timeout {}s", config.cache.ttl_seconds + 10))
        .collect::<Vec<_>>()
        .join(", ");
    let out = std::process::Command::new("nft")
        .arg("add")
        .arg("element")
        .arg(&s.family)
        .arg(&s.table)
        .arg(&s.set)
        .arg(format!("{{ {} }}", elements))
        .output()?;

    if out.status.success() {
        debug!(
            "added {} IP(s) of {qname} to nftables set '{}'",
            ips.len(),
            s.set
        );
    } else {
        warn!(
            "nft add element '{}' failed: {}",
            s.set,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}
