use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use anyhow::{Result, anyhow, bail};
use log::{debug, info, warn};
use tokio::net::UdpSocket;

use crate::{
    cache,
    config::{NftSet, config},
    dns::{
        QueryInfo, Response, analyze_response, build_a_response, build_cname_chase_response,
        build_empty_response, cap_response_ttl,
    },
    extra_domain, forwarder,
};

pub async fn run() -> Result<()> {
    let config = config()?;

    let socket = Arc::new(UdpSocket::bind(config.listen).await?);
    info!("listening on {}", config.listen);

    let mut buf = [0u8; 4096];

    loop {
        let (len, client_addr) = socket.recv_from(&mut buf).await?;
        let query = buf[..len].to_vec();

        let socket = socket.clone();

        tokio::spawn(async move {
            match query_handler(&query).await {
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

async fn query_handler(query: &[u8]) -> Result<Vec<u8>> {
    let info = QueryInfo::parse(query)?;
    let query_id = &query[..2];
    let config = config()?;

    if let Some(ip) = config.local_domains.get(&info.qname) {
        debug!("local domain match: {} -> {ip}", &info.qname);
        return build_a_response(query, &ip.octets());
    }

    if config.blocklist.get(&info.qname).is_some() {
        debug!("private domain or blocklist match: {}", &info.qname);
        return build_empty_response(query);
    }

    match cache::get(&info).await {
        Some((cached, remaining_ttl)) => {
            let mut response = [query_id, &cached].concat();
            debug!("cache {} ttl {remaining_ttl}", &info.qname);
            cap_response_ttl(&mut response, remaining_ttl)?;
            Ok(response)
        }
        None => {
            let rule = match config
                .forward_rules
                .iter()
                .find(|i| i.suffix_trie.get(&info.qname).is_some())
            {
                Some(rule) => Some(rule),
                None => extra_domain::match_domain(&info.qname)
                    .await
                    .and_then(|rule_id| config.forward_rules.iter().find(|i| i.id == rule_id)),
            };

            if let Some(rule) = &rule {
                debug!("match rule {:?}", rule.name);
            }

            if info.qtype == 28 && rule.map(|i| i.block_aaaa) == Some(true) {
                debug!(
                    "AAAA query {} blocked, returning NOERROR empty response",
                    info.qname
                );
                return build_empty_response(query);
            }

            let upstreams = rule.map(|i| &i.upstreams).unwrap_or(&config.default_server);
            let (r, resp, ttl) = resolve_with_cname_chase(
                &info,
                query,
                upstreams,
                rule.map(|i| i.id),
                Vec::new(),
                0,
            )
            .await?;

            if let (Some(set), Response::A(a_records)) =
                (rule.as_ref().and_then(|i| i.nft_set.clone()), resp)
                && !a_records.is_empty()
            {
                let qname = info.qname.clone();
                let records = a_records.clone();
                tokio::task::spawn_blocking(move || {
                    add_to_nft_set(&qname, &set, &records, ttl * 2)
                })
                .await??;
            }

            let r = &r[2..];
            cache::insert(&info, r.to_vec(), ttl).await;
            Ok([query_id, r].concat())
        }
    }
}

async fn resolve_with_cname_chase(
    info: &QueryInfo,
    original_query: &[u8],
    upstreams: &[SocketAddr],
    rule_id: Option<usize>,
    mut cname_chain: Vec<(String, u32)>,
    depth: usize,
) -> Result<(Vec<u8>, Response, u32)> {
    if depth > 10 {
        bail!("CNAME resolution exceeded max depth of 10");
    }

    let current_query = info.build(fastrand::u16(..));
    let response = query_from_upstream(&info.qname, &current_query, upstreams).await?;

    let (resp, ttl) = analyze_response(&response)?;
    match resp {
        x @ (Response::A(_) | Response::Aaaa) => {
            let final_response = if cname_chain.is_empty() {
                response
            } else {
                build_cname_chase_response(original_query, &cname_chain, &response, &x, ttl)?
            };
            Ok((final_response, x, ttl))
        }
        Response::Cname(target) => {
            if cname_chain.iter().any(|(name, _)| name == &target) {
                bail!("CNAME loop detected: {}", target);
            }
            if let Some(rule_id) = rule_id {
                extra_domain::add_domain(&target, rule_id).await;
            }
            cname_chain.push((target.clone(), ttl));

            let info = info.new_qname(&target);

            Box::pin(resolve_with_cname_chase(
                &info,
                original_query,
                upstreams,
                rule_id,
                cname_chain,
                depth + 1,
            ))
            .await
        }
    }
}

async fn query_from_upstream(
    qname: &str,
    query: &[u8],
    upstreams: &[SocketAddr],
) -> Result<Vec<u8>> {
    let upstream = fastrand::choice(upstreams).ok_or_else(|| anyhow!("invalid upstreams"))?;
    debug!("query {qname} from {upstream}");
    forwarder::get(upstream)
        .await?
        .forward(query, qname, upstream)
        .await
}

fn add_to_nft_set(qname: &str, s: &NftSet, ips: &[Ipv4Addr], timeout_secs: u32) -> Result<()> {
    let ips: Vec<_> = ips.iter().filter(|ip| !s.contains(ip)).collect();

    if ips.is_empty() {
        debug!(
            "all IPs for {qname} already exist in nftables set '{}', skipping",
            s.set
        );
        return Ok(());
    }

    let elements = ips
        .iter()
        .map(|ip| format!("{ip} timeout {timeout_secs}s"))
        .collect::<Vec<_>>()
        .join(", ");

    let add_out = std::process::Command::new("nft")
        .arg("add")
        .arg("element")
        .arg(&s.family)
        .arg(&s.table)
        .arg(&s.set)
        .arg(format!("{{ {elements} }}"))
        .output()?;

    if add_out.status.success() {
        debug!(
            "added/updated {} IP(s) of {qname} to nftables set '{}'",
            ips.len(),
            s.set
        );
    } else {
        warn!(
            "nft add element '{}' failed: {}",
            s.set,
            String::from_utf8_lossy(&add_out.stderr).trim()
        );
    }
    Ok(())
}
