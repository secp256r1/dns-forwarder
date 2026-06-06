use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    process::Command,
    sync::OnceLock,
};

use anyhow::{Context, Result, anyhow, bail};
use log::{info, warn};
use serde::Deserialize;

use crate::trie::DomainTrie;

const PRIVATE_DOMAINS: &[&str] = &["lan", "local", "home.arpa", "corp", "internal"];

static CONFIG: OnceLock<Config> = OnceLock::new();

#[derive(Deserialize, Clone)]
struct RawConfig {
    pub listen: String,
    pub default_server: Vec<String>,
    pub rules: Vec<RuleConfig>,
    pub cache: Option<CacheConfig>,
}

#[derive(Deserialize, Clone)]
pub struct RuleConfig {
    pub name: Option<String>,
    pub domain_files: Vec<String>,
    #[serde(flatten)]
    pub kind: RuleKind,
}

#[derive(Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleKind {
    Forward {
        upstreams: Vec<String>,
        #[serde(default)]
        block_aaaa: bool,
        /// "family table set" — e.g. "inet fw xip". When set, A-record IPs are added to this nftables set.
        nft_set: Option<String>,
    },
    Block,
    Local,
    Cname {
        cname_list: Vec<String>,
    },
}

impl RawConfig {
    fn from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: RawConfig = toml::from_str(&content)?;
        Ok(config)
    }
}

/// A rule ready for matching at runtime.
#[derive(Clone)]
pub struct ForwardRule {
    pub name: Option<String>,
    pub suffix_trie: DomainTrie<()>,
    pub upstreams: Vec<SocketAddr>,
    pub block_aaaa: bool,
    pub nft_set: Option<NftSet>,
}

#[derive(Clone)]
pub struct CnameRule {
    pub name: Option<String>,
    pub suffix_trie: DomainTrie<()>,
    pub cname_targets: Vec<String>,
}

#[derive(Clone)]
pub struct NftSet {
    pub family: String,
    pub table: String,
    pub set: String,
    pub existing_elements: Vec<NftElement>,
}

#[derive(Clone, Debug)]
pub struct NftElement {
    pub start: IpAddr,
    pub end: IpAddr,
}

#[derive(Deserialize, Clone)]
pub struct CacheConfig {
    pub max_entries: usize,
    pub max_ttl: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        CacheConfig {
            max_entries: 100_000,
            max_ttl: 3600,
        }
    }
}

#[derive(Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub default_server: Vec<SocketAddr>,
    pub cache: CacheConfig,
    pub forward_rules: Vec<ForwardRule>,
    pub cname_rules: Vec<CnameRule>,
    pub local_domains: DomainTrie<Ipv4Addr>,
    pub blocklist: DomainTrie<()>,
}

impl Config {
    pub fn from_file(path: &Path) -> Result<Self> {
        let config = RawConfig::from_file(path)?;
        let base_dir = path.parent().unwrap_or(Path::new("."));

        let listen = parse_dns_server_addr(&config.listen)?;
        let mut default_server = Vec::new();
        for i in &config.default_server {
            default_server.push(parse_dns_server_addr(i)?);
        }

        if default_server.is_empty() {
            bail!("at least one upstream is required in the config");
        }

        let mut local_domains = DomainTrie::new();
        let mut blocklist = DomainTrie::new();
        let mut cname_rules = Vec::new();
        let mut forward_rules = Vec::new();

        for rule in &config.rules {
            let name = &rule.name;

            match &rule.kind {
                RuleKind::Forward {
                    upstreams: rule_upstreams,
                    block_aaaa,
                    nft_set,
                } => {
                    let mut suffix_trie = DomainTrie::new();
                    for path in &rule.domain_files {
                        for domain in read_domain_file(&base_dir.join(path))? {
                            suffix_trie.insert(&domain, ());
                        }
                    }

                    let mut upstreams = Vec::new();
                    for i in rule_upstreams {
                        upstreams.push(parse_dns_server_addr(i)?);
                    }

                    if upstreams.is_empty() {
                        bail!("at least one upstream is required in the config rule {name:?}");
                    }

                    let nft_set = match nft_set {
                        Some(s) => {
                            let parts: Vec<&str> = s.split_whitespace().collect();
                            if parts.len() != 3 {
                                bail!("invalid nft_set '{s}', expected format 'family table set'");
                            }

                            let family = parts[0].to_string();
                            let table = parts[1].to_string();
                            let set = parts[2].to_string();
                            let existing_elements = fetch_existing_nft_elements(&family, &table, &set);
                            if !existing_elements.is_empty() {
                                info!("loaded {} existing nftables elements for set '{}'", existing_elements.len(), set);
                            }
                            Some(NftSet {
                                family,
                                table,
                                set,
                                existing_elements,
                            })
                        }
                        None => None,
                    };

                    forward_rules.push(ForwardRule {
                        name: rule.name.clone(),
                        suffix_trie,
                        upstreams,
                        block_aaaa: *block_aaaa,
                        nft_set,
                    });
                }
                RuleKind::Cname { cname_list } => {
                    let mut suffix_trie = DomainTrie::new();
                    for path in &rule.domain_files {
                        for domain in read_domain_file(&base_dir.join(path))? {
                            suffix_trie.insert(&domain, ());
                        }
                    }

                    cname_rules.push(CnameRule {
                        name: rule.name.clone(),
                        suffix_trie,
                        cname_targets: cname_list.clone(),
                    });
                }
                RuleKind::Block => {
                    for path in &rule.domain_files {
                        for domain in read_domain_file(&base_dir.join(path))? {
                            blocklist.insert(&domain, ());
                        }
                    }
                }
                RuleKind::Local => {
                    for f in &rule.domain_files {
                        let full_path = base_dir.join(f);
                        let content = fs::read_to_string(&full_path).with_context(|| {
                            format!("reading local domain file {}", full_path.display())
                        })?;
                        for line in content.lines() {
                            let line = line.trim();
                            if line.is_empty() || line.starts_with('#') {
                                continue;
                            }
                            let (name, ip) = line
                                .split_once('=')
                                .map(|(a, b)| (a.trim(), b.trim()))
                                .ok_or_else(|| anyhow!("invalid local domain line: '{line}'"))?;
                            let ip: Ipv4Addr = ip.parse().with_context(|| {
                                format!("invalid IP in local domain line: '{line}'")
                            })?;
                            local_domains.insert(name, ip);
                        }
                    }
                }
            }
        }

        for i in PRIVATE_DOMAINS {
            blocklist.insert(i, ());
        }

        Ok(Config {
            listen,
            default_server,
            forward_rules,
            cname_rules,
            cache: config.cache.unwrap_or_default(),
            local_domains,
            blocklist,
        })
    }
}

fn parse_dns_server_addr(s: &str) -> Result<SocketAddr> {
    Ok(match s.parse::<SocketAddr>() {
        Ok(socket) => socket,
        Err(_) => match s.parse::<IpAddr>() {
            Ok(ip) => (ip, 53).into(),
            Err(_) => bail!("invalid dns server addr"),
        },
    })
}

fn parse_nft_elements(output: &str) -> Vec<NftElement> {
    let mut elements = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('{') || line.starts_with('}') {
            continue;
        }
        let line = line.trim_end_matches(',').trim();
        if line.is_empty() {
            continue;
        }
        let elem = line.split_whitespace().next().unwrap_or("");
        if elem.is_empty() {
            continue;
        }
        if let Some((start_str, end_str)) = elem.split_once('-') {
            if let (Ok(start), Ok(end)) = (start_str.parse::<IpAddr>(), end_str.parse::<IpAddr>()) {
                elements.push(NftElement { start, end });
            }
        } else if let Some((ip_str, prefix_str)) = elem.split_once('/') {
            if let (Ok(ip), Ok(prefix)) = (ip_str.parse::<IpAddr>(), prefix_str.parse::<u8>()) {
                let start = ip;
                let end = match ip {
                    IpAddr::V4(ipv4) => {
                        let mask = u32::MAX << (32 - prefix);
                        let masked = u32::from(ipv4) & mask;
                        let end_ip = masked | !mask;
                        IpAddr::V4(Ipv4Addr::from(end_ip))
                    }
                    IpAddr::V6(ipv6) => {
                        let segments = ipv6.segments();
                        let prefix_bits = prefix as usize;
                        let full_segments = prefix_bits / 16;
                        let remaining_bits = prefix_bits % 16;
                        let mut end_segments = [0u16; 8];
                        for i in 0..full_segments {
                            end_segments[i] = segments[i];
                        }
                        if remaining_bits > 0 && full_segments < 8 {
                            let mask = 0xFFFF << (16 - remaining_bits);
                            end_segments[full_segments] = segments[full_segments] | !mask;
                        }
                        for i in (full_segments + (if remaining_bits > 0 { 1 } else { 0 }))..8 {
                            end_segments[i] = 0xFFFF;
                        }
                        IpAddr::V6(std::net::Ipv6Addr::from(end_segments))
                    }
                };
                elements.push(NftElement { start, end });
            }
        } else if let Ok(ip) = elem.parse::<IpAddr>() {
            elements.push(NftElement { start: ip, end: ip });
        }
    }
    elements
}

fn fetch_existing_nft_elements(family: &str, table: &str, set: &str) -> Vec<NftElement> {
    let output = Command::new("nft")
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

fn read_domain_file(path: &Path) -> Result<Vec<String>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("reading domain file {}", path.display()))?;
    let mut result = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        result.push(line.to_string());
    }

    Ok(result)
}

pub fn init(path: &Path) -> Result<()> {
    let config = Config::from_file(path)?;
    CONFIG.get_or_init(|| config);

    Ok(())
}

pub fn config() -> Result<&'static Config> {
    CONFIG.get().ok_or_else(|| anyhow!("get config error"))
}
