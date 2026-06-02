use std::{net::SocketAddr, sync::Arc};

use anyhow::{Error, Result, anyhow, bail};
use log::{debug, info, warn};
use tokio::net::UdpSocket;

use crate::{
    cache,
    config::{NftSet, config},
    dns::{
        Response, analyze_response, build_a_response, build_nxdomain_response, build_query,
        cap_response_ttl, parse_qname, parse_query_type_and_class,
    },
    forwarder,
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
    if query.len() < 12 {
        bail!("query too short");
    }

    let qname = parse_qname(query)?;

    let config = config()?;

    if let Some(ip) = config.local_domains.get(&qname) {
        debug!("local domain match: {} -> {}", qname, ip);
        return build_a_response(query, &ip.octets());
    }

    if config.blocklist.get(&qname).is_some() {
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
            if let Some(cname_rule) = config
                .cname_rules
                .iter()
                .find(|i| i.suffix_trie.get(&qname).is_some())
            {
                let (qtype, qclass) = parse_query_type_and_class(query)?;
                if qtype == 1 || qtype == 28 {
                    let target = fastrand::choice(&cname_rule.cname_targets)
                        .ok_or_else(|| anyhow!("empty cname_list"))?;
                    debug!(
                        "cname chase: {} -> {}, rule: {:?}",
                        qname, target, cname_rule.name
                    );

                    let query_id = u16::from_be_bytes([query[0], query[1]]);
                    let sub_query = build_query(target, qtype, qclass, query_id);
                    let r = query_from_upstream(target, &sub_query, &config.default_server).await?;
                    let (_, min_ttl) = analyze_response(&r)?;
                    cache::insert(key, r[2..].to_vec(), min_ttl).await;
                    return Ok(r);
                }
            }

            let rule = config
                .forward_rules
                .iter()
                .find(|i| i.suffix_trie.get(&qname).is_some());

            if let Some(rule) = &rule {
                debug!("match rule {:?}", rule.name);
            }

            let (qtype, _) = parse_query_type_and_class(query)?;
            if qtype == 28 && rule.map(|i| i.block_aaaa) == Some(true) {
                debug!("AAAA record detected, returning NXDOMAIN response");
                return build_nxdomain_response(query);
            }

            let upstreams = rule.map(|i| &i.upstreams).unwrap_or(&config.default_server);
            let r = query_from_upstream(&qname, query, upstreams).await?;
            let (info, min_ttl) = analyze_response(&r)?;

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

            cache::insert(key, r[2..].to_vec(), min_ttl).await;
            Ok(r)
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
    let f = forwarder::get(upstream).await?;
    f.send(query).await?;

    match tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let result = f.recv().await?;
            if result[..2] == query[..2] {
                return Ok::<_, Error>(result);
            }
        }
    })
    .await?
    {
        Ok(r) => Ok(r),
        Err(_) => {
            bail!("upstream query {qname} from {upstream} timed out");
        }
    }
}

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
