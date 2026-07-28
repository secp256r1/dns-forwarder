use std::time::{Duration, Instant};

use tokio::sync::{OnceCell, RwLock};
use tokio::time::interval;

use crate::trie::DomainTrie;

/// Extra domain entry with expiration time
#[derive(Clone, Debug)]
struct ExtraDomainEntry {
    rule_id: usize,
    expires_at: Instant,
}

static RULE_EXTRA_DOMAIN: OnceCell<RwLock<DomainTrie<ExtraDomainEntry>>> = OnceCell::const_new();

/// TTL for dynamically learned CNAME targets (default: 1 hour)
const EXTRA_DOMAIN_TTL: Duration = Duration::from_secs(3600);

/// Cleanup interval for expired entries
const CLEANUP_INTERVAL: Duration = Duration::from_secs(300);

pub async fn init() {
    let trie = RwLock::new(DomainTrie::new());
    RULE_EXTRA_DOMAIN.get_or_init(|| async { trie }).await;

    // Spawn background cleanup task
    tokio::spawn(async {
        let mut interval = interval(CLEANUP_INTERVAL);
        loop {
            interval.tick().await;
            cleanup_expired().await;
        }
    });
}

pub async fn add_domain(domain: &str, rule_id: usize) {
    if let Some(lock) = RULE_EXTRA_DOMAIN.get() {
        let mut trie = lock.write().await;
        trie.insert(
            domain,
            ExtraDomainEntry {
                rule_id,
                expires_at: Instant::now() + EXTRA_DOMAIN_TTL,
            },
        );
    }
}

pub async fn match_domain(domain: &str) -> Option<usize> {
    match RULE_EXTRA_DOMAIN.get() {
        Some(l) => {
            let mut trie = l.write().await;
            // Clean up expired entries on read path too
            cleanup_expired_trie(&mut trie).await;
            trie.get(domain)
                .filter(|entry| entry.expires_at > Instant::now())
                .map(|entry| entry.rule_id)
        }
        None => None,
    }
}

async fn cleanup_expired() {
    if let Some(lock) = RULE_EXTRA_DOMAIN.get() {
        let mut trie = lock.write().await;
        cleanup_expired_trie(&mut trie).await;
    }
}

async fn cleanup_expired_trie(trie: &mut DomainTrie<ExtraDomainEntry>) {
    let now = Instant::now();
    
    // Collect all valid (non-expired) entries
    let mut valid_entries = Vec::new();
    trie.iter(|domain, entry| {
        if entry.expires_at > now {
            valid_entries.push((domain.to_string(), entry.clone()));
        }
    });
    
    // Rebuild trie with only valid entries
    let mut new_trie = DomainTrie::new();
    for (domain, entry) in valid_entries {
        new_trie.insert(&domain, entry);
    }
    
    *trie = new_trie;
}
