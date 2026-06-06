use std::{net::IpAddr, net::Ipv4Addr, process::Command};

use log::warn;
use serde::Deserialize;

use super::NftElement;

#[derive(Deserialize, Debug)]
pub(super) struct NftablesRoot {
    pub nftables: Vec<NftablesItem>,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub(super) enum NftablesItem {
    Set(NftSetData),
    Other(()),
}

#[derive(Deserialize, Debug)]
pub(super) struct NftSetData {
    pub set: NftSetInfo,
}

#[derive(Deserialize, Debug)]
pub(super) struct NftSetInfo {
    #[allow(dead_code)]
    pub family: String,
    pub name: String,
    #[allow(dead_code)]
    pub table: String,
    #[serde(rename = "type")]
    pub set_type: String,
    #[serde(default)]
    pub elem: Vec<NftSetElem>,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub(super) enum NftSetElem {
    Simple(String),
    Prefixed(NftPrefix),
    Ranged(NftRange),
    WithTimeout(NftElemWithTimeout),
}

#[derive(Deserialize, Debug)]
pub(super) struct NftPrefix {
    pub prefix: NftPrefixInfo,
}

#[derive(Deserialize, Debug)]
pub(super) struct NftPrefixInfo {
    pub addr: String,
    pub len: u8,
}

#[derive(Deserialize, Debug)]
pub(super) struct NftRange {
    pub range: [String; 2],
}

#[derive(Deserialize, Debug)]
pub(super) struct NftElemWithTimeout {
    pub elem: NftElemInner,
}

#[derive(Deserialize, Debug)]
pub(super) struct NftElemInner {
    pub val: String,
}

pub(super) fn ipv4_prefix_to_range(ip: Ipv4Addr, prefix: u8) -> (Ipv4Addr, Ipv4Addr) {
    let mask = u32::MAX << (32 - prefix);
    let masked = u32::from(ip) & mask;
    let end = masked | !mask;
    (ip, Ipv4Addr::from(end))
}

pub(super) fn parse_nft_elements(output: &str) -> Vec<NftElement> {
    let mut elements = Vec::new();

    let root: NftablesRoot = match serde_json::from_str(output) {
        Ok(v) => v,
        Err(e) => {
            warn!("failed to parse nftables JSON output: {e}");
            return elements;
        }
    };

    for item in &root.nftables {
        let set_info = match item {
            NftablesItem::Set(s) => &s.set,
            NftablesItem::Other(_) => continue,
        };

        if set_info.set_type != "ipv4_addr" {
            warn!(
                "nftables set '{}' has type '{}', only 'ipv4_addr' is supported, skipping",
                set_info.name, set_info.set_type
            );
            return elements;
        }

        for elem in &set_info.elem {
            match elem {
                NftSetElem::Simple(s) => {
                    if let Ok(ip) = s.parse::<Ipv4Addr>() {
                        let ip = IpAddr::V4(ip);
                        elements.push(NftElement { start: ip, end: ip });
                    }
                }
                NftSetElem::Prefixed(p) => {
                    if let Ok(ip) = p.prefix.addr.parse::<Ipv4Addr>() {
                        let (start, end) = ipv4_prefix_to_range(ip, p.prefix.len);
                        elements.push(NftElement {
                            start: IpAddr::V4(start),
                            end: IpAddr::V4(end),
                        });
                    }
                }
                NftSetElem::Ranged(r) => {
                    if let (Ok(start), Ok(end)) =
                        (r.range[0].parse::<Ipv4Addr>(), r.range[1].parse::<Ipv4Addr>())
                    {
                        elements.push(NftElement {
                            start: IpAddr::V4(start),
                            end: IpAddr::V4(end),
                        });
                    }
                }
                NftSetElem::WithTimeout(e) => {
                    if let Ok(ip) = e.elem.val.parse::<Ipv4Addr>() {
                        let ip = IpAddr::V4(ip);
                        elements.push(NftElement { start: ip, end: ip });
                    }
                }
            }
        }
    }
    elements
}

pub(super) fn fetch_existing_nft_elements(family: &str, table: &str, set: &str) -> Vec<NftElement> {
    let output = Command::new("nft")
        .arg("--json")
        .arg("list")
        .arg("set")
        .arg(family)
        .arg(table)
        .arg(set)
        .output();
    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            parse_nft_elements(&stdout)
        }
        Ok(out) => {
            warn!(
                "nft list set '{}' failed: {}",
                set,
                String::from_utf8_lossy(&out.stderr).trim()
            );
            Vec::new()
        }
        Err(e) => {
            warn!("failed to run nft list set '{}': {}", set, e);
            Vec::new()
        }
    }
}
