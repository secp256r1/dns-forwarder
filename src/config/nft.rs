use std::{net::Ipv4Addr, process::Command};

use anyhow::{Context, Error, Result, bail};
use serde::Deserialize;

use super::NftElement;

#[derive(Deserialize, Debug)]
pub(super) struct NftablesRoot {
    pub nftables: Vec<NftablesItem>,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub(super) enum NftablesItem {
    Set {
        set: NftSetInfo,
    },
    #[allow(dead_code)]
    MetaInfo {
        metainfo: MetaInfo,
    },
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct MetaInfo {
    version: String,
    release_name: String,
    json_schema_version: i32,
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
    pub elem: Vec<NftSetElem>,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub(super) enum NftSetElem {
    Simple(String),
    Prefixed { prefix: NftPrefixInfo },
    Ranged { range: [String; 2] },
    WithTimeout { elem: NftElemInner },
}

impl TryFrom<&NftSetElem> for NftElement {
    type Error = Error;

    fn try_from(value: &NftSetElem) -> Result<Self> {
        Ok(match value {
            NftSetElem::Simple(s) => NftElement::Value(s.parse()?),
            NftSetElem::Prefixed { prefix } => prefix.try_into()?,
            NftSetElem::Ranged { range } => NftElement::Interval {
                start: range[0].parse()?,
                end: range[1].parse()?,
            },
            NftSetElem::WithTimeout { elem } => elem.val.as_ref().try_into()?,
        })
    }
}

#[derive(Deserialize, Debug)]
pub(super) struct NftPrefixInfo {
    pub addr: String,
    pub len: u8,
}

impl TryFrom<&NftPrefixInfo> for NftElement {
    type Error = Error;

    fn try_from(value: &NftPrefixInfo) -> Result<Self> {
        let ip: Ipv4Addr = value.addr.parse()?;
        let mask = if value.len == 0 {
            0
        } else {
            u32::MAX << (32 - value.len)
        };
        let masked = ip.to_bits() & mask;
        let end = masked | !mask;

        Ok(NftElement::Interval {
            start: Ipv4Addr::from(masked),
            end: Ipv4Addr::from(end),
        })
    }
}

#[derive(Deserialize, Debug)]
pub(super) struct NftElemInner {
    pub val: Box<NftSetElem>,
    #[allow(dead_code)]
    pub timeout: u64,
    #[allow(dead_code)]
    pub expires: u64,
}

pub(super) fn parse_nft_elements(output: &str) -> Result<Vec<NftElement>> {
    let mut elements = Vec::new();

    let root: NftablesRoot =
        serde_json::from_str(output).context("failed to parse nftables JSON output")?;

    for item in &root.nftables {
        let set_info = match item {
            NftablesItem::Set { set } => set,
            NftablesItem::MetaInfo { .. } => continue,
        };

        if set_info.set_type != "ipv4_addr" {
            bail!(
                "nftables set '{}' has type '{}', only 'ipv4_addr' is supported, skipping",
                set_info.name,
                set_info.set_type
            );
        }

        for elem in &set_info.elem {
            elements.push(elem.try_into()?);
        }
    }

    Ok(elements)
}

pub(super) fn fetch_existing_nft_elements(
    family: &str,
    table: &str,
    set: &str,
) -> Result<Vec<NftElement>> {
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
            parse_nft_elements(&String::from_utf8_lossy(&out.stdout))
        }
        Ok(out) => {
            bail!(
                "nft list set '{}' failed: {}",
                set,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Err(e) => {
            bail!("failed to run nft list set '{}': {}", set, e);
        }
    }
}
