use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::OnceLock,
};

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use trie_hard::TrieHard;

static CONFIG: OnceLock<Config> = OnceLock::new();

#[derive(Deserialize, Clone)]
struct RawConfig {
    pub listen: String,
    pub upstream: Vec<String>,
    pub rules: Vec<RuleConfig>,
    pub cache: Option<CacheConfig>,
    pub local_domain: Option<PathBuf>,
}

#[derive(Deserialize, Clone)]
pub struct RuleConfig {
    pub domain_files: Vec<PathBuf>,
    pub upstreams: Vec<String>,
    #[serde(default)]
    pub block_aaaa: bool,
    /// "family table set" — e.g. "inet fw xip". When set, A-record IPs are added to this nftables set.
    pub nft_set: Option<String>,
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
pub struct Rule {
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
    pub enabled: bool,
    pub max_entries: usize,
    pub ttl_seconds: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        CacheConfig {
            enabled: true,
            max_entries: 10000,
            ttl_seconds: 300,
        }
    }
}

#[derive(Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub upstream: Vec<SocketAddr>,
    pub rules: Vec<Rule>,
    pub cache: CacheConfig,
    pub local_domains: TrieHard<'static, Ipv4Addr>,
}

impl Config {
    pub fn from_file(path: &Path) -> Result<Self> {
        let config = RawConfig::from_file(path)?;
        let base_dir = path.parent().unwrap_or(Path::new("."));
        let listen = parse_dns_server_addr(&config.listen)?;
        let mut upstream = Vec::new();
        for i in &config.upstream {
            upstream.push(parse_dns_server_addr(i)?);
        }

        if upstream.is_empty() {
            bail!("at least one upstream is required in the config");
        }

        let mut rules = Vec::new();
        for i in &config.rules {
            let mut suffix_entries: Vec<(&'static [u8], ())> = Vec::new();
            for path in &i.domain_files {
                let full_path = base_dir.join(path);
                let content = fs::read_to_string(&full_path)
                    .with_context(|| format!("reading domain file {}", full_path.display()))?;
                for line in content.lines() {
                    let s = line.trim();
                    if s.is_empty() {
                        continue;
                    }
                    let reversed: String = s.chars().rev().collect();
                    suffix_entries
                        .push((Box::leak(reversed.into_bytes().into_boxed_slice()), ()));
                }
            }

            let suffix_trie = TrieHard::new(suffix_entries);

            let mut upstreams = Vec::new();
            for i in &i.upstreams {
                upstreams.push(parse_dns_server_addr(i)?);
            }

            if upstreams.is_empty() {
                bail!("at least one upstream is required in the config rule",);
            }

            let nft_set = match &i.nft_set {
                Some(s) => {
                    let parts: Vec<&str> = s.split_whitespace().collect();
                    if parts.len() != 3 {
                        bail!(
                            "invalid nft_set '{}', expected format 'family table set'",
                            s
                        );
                    }

                    Some(NftSet {
                        family: parts[0].to_string(),
                        table: parts[1].to_string(),
                        set: parts[2].to_string(),
                    })
                }
                None => None,
            };

            rules.push(Rule {
                suffix_trie,
                upstreams,
                block_aaaa: i.block_aaaa,
                nft_set,
            });
        }

        let mut local_entries: Vec<(&'static [u8], Ipv4Addr)> = Vec::new();
        if let Some(ref path) = config.local_domain {
            let full_path = base_dir.join(path);
            if full_path.exists() {
            let content = fs::read_to_string(&full_path)
                .with_context(|| format!("reading local domain file {}", full_path.display()))?;
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let (name, ip) = line
                    .split_once('=')
                    .map(|(a, b)| (a.trim(), b.trim()))
                    .ok_or_else(|| anyhow!("invalid local domain line: '{}'", line))?;
                let ip: Ipv4Addr = ip
                    .parse()
                    .with_context(|| format!("invalid IP in local domain line: '{}'", line))?;
                let reversed: String = name.chars().rev().collect();
                local_entries
                    .push((Box::leak(reversed.into_bytes().into_boxed_slice()), ip));
            }
            }
        }
        let local_domains = TrieHard::new(local_entries);

        Ok(Config {
            listen,
            upstream,
            rules,
            cache: config.cache.unwrap_or_default(),
            local_domains,
        })
    }
}

fn parse_dns_server_addr(s: &str) -> Result<SocketAddr> {
    let (addr, port) = match s.split_once(':') {
        Some((addr, port)) => (addr, port.parse()?),
        None => (s, 53),
    };

    let addr: IpAddr = addr.parse()?;

    Ok((addr, port).into())
}

pub fn init(path: &Path) -> Result<()> {
    let config = Config::from_file(path)?;
    CONFIG.get_or_init(|| config);

    Ok(())
}

pub fn config() -> Result<&'static Config> {
    CONFIG.get().ok_or_else(|| anyhow!("get config error"))
}
