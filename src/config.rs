use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::OnceLock,
};

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use trie_hard::TrieHard;

const PRIVATE_DOMAINS: &[&str] = &[".lan", ".local", ".home.arpa", ".corp", ".internal"];

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
    pub suffix_trie: TrieHard<'static, ()>,
    pub upstreams: Vec<SocketAddr>,
    pub block_aaaa: bool,
    pub nft_set: Option<NftSet>,
}

#[derive(Clone)]
pub struct NftSet {
    pub family: String,
    pub table: String,
    pub set: String,
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
    pub local_domains: TrieHard<'static, Ipv4Addr>,
    pub blocklist: TrieHard<'static, ()>,
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

        let mut local_domain: Vec<(&'static [u8], Ipv4Addr)> = Vec::new();
        let mut blocklist: Vec<(&'static [u8], ())> = Vec::new();
        let mut forward_rules = Vec::new();
        for rule in &config.rules {
            let name = &rule.name;

            match &rule.kind {
                RuleKind::Forward {
                    upstreams: rule_upstreams,
                    block_aaaa,
                    nft_set,
                } => {
                    let mut suffix_entries: Vec<(&'static [u8], ())> = Vec::new();
                    for path in &rule.domain_files {
                        let full_path = base_dir.join(path);
                        let content = fs::read_to_string(&full_path).with_context(|| {
                            format!("reading {name:?} rule domain file {}", full_path.display())
                        })?;
                        for line in content.lines() {
                            let s = line.trim();
                            if s.is_empty() {
                                continue;
                            }
                            suffix_entries.push((reversed_str(s), ()));
                        }
                    }

                    let suffix_trie = TrieHard::new(suffix_entries);

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

                            Some(NftSet {
                                family: parts[0].to_string(),
                                table: parts[1].to_string(),
                                set: parts[2].to_string(),
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
                RuleKind::Block => {
                    for f in &rule.domain_files {
                        let full_path = base_dir.join(f);
                        let content = fs::read_to_string(&full_path).with_context(|| {
                            format!("reading blocklist file {}", full_path.display())
                        })?;
                        for line in content.lines() {
                            let line = line.trim();
                            if line.is_empty() || line.starts_with('#') {
                                continue;
                            }
                            blocklist.push((reversed_str(line), ()));
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
                            local_domain.push((reversed_str(name), ip));
                        }
                    }
                }
            }
        }

        for i in PRIVATE_DOMAINS {
            blocklist.push((reversed_str(i), ()));
        }

        Ok(Config {
            listen,
            default_server,
            forward_rules,
            cache: config.cache.unwrap_or_default(),
            local_domains: TrieHard::new(local_domain),
            blocklist: TrieHard::new(blocklist),
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

fn reversed_str(s: &str) -> &'static [u8] {
    let reversed: String = s.chars().rev().collect();
    Box::leak(reversed.into_bytes().into_boxed_slice())
}

pub fn init(path: &Path) -> Result<()> {
    let config = Config::from_file(path)?;
    CONFIG.get_or_init(|| config);

    Ok(())
}

pub fn config() -> Result<&'static Config> {
    CONFIG.get().ok_or_else(|| anyhow!("get config error"))
}
