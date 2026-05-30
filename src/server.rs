use std::sync::Arc;

use anyhow::{Result, anyhow, bail};
use log::{debug, info, warn};
use tokio::net::UdpSocket;

use crate::{
    cache,
    config::{NftSet, config},
    dns::{
        Response, analyze_response, build_a_response, build_nxdomain_response, build_soa_response,
        cap_response_ttl, parse_qname,
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

    let key = query[2..].to_vec();
    match cache::get(&key).await {
        Some((cached, remaining_ttl)) => {
            let mut response = [&query[..2], &cached].concat();
            debug!("cache {qname} ttl {remaining_ttl}");
            cap_response_ttl(&mut response, remaining_ttl)?;
            Ok(response)
        }
        None => {
            let rule = config
                .forward_rules
                .iter()
                .find(|i| i.suffix_trie.ancestor(&reversed_qname).is_some());

            if let Some(rule) = &rule {
                debug!("match rule {:?}", rule.name);
            }

            let upstreams = rule.map(|i| &i.upstreams).unwrap_or(&config.default_server);
            let upstream =
                fastrand::choice(upstreams).ok_or_else(|| anyhow!("invalid upstreams"))?;

            let socket = UdpSocket::bind("0.0.0.0:0").await?;

            debug!("query {qname} from {upstream}");
            socket.send_to(query, upstream).await?;

            let mut buf = vec![0u8; 512];
            let len = match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                socket.recv_from(&mut buf),
            )
            .await
            {
                Ok(Ok((len, _))) => len,
                Ok(Err(e)) => {
                    bail!("query {qname} from {upstream} error: {e}");
                }
                Err(_) => {
                    bail!("query {qname} from {upstream} timed out");
                }
            };

            let (info, min_ttl) = analyze_response(&buf[..len])?;

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
                tokio::task::spawn_blocking(move || {
                    add_to_nft_set(&qname, &set, &records, min_ttl * 2)
                })
                .await??;
            }

            cache::insert(key, buf[2..len].to_vec(), min_ttl).await;
            Ok(buf[..len].to_vec())
        }
    }
}

/// Add IP addresses to an nftables set.
/// Executes `nft add element <family> <table> <set> { <ip1>, <ip2>, ... }`.
fn add_to_nft_set(qname: &str, s: &NftSet, ips: &[String], timeout_secs: u32) -> Result<()> {
    let elements = ips
        .iter()
        .map(|ip| format!("{ip} timeout {timeout_secs}s"))
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
