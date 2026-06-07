use tokio::sync::{OnceCell, RwLock};

use crate::trie::DomainTrie;

pub static RULE_EXTRA_DOMAIN: OnceCell<RwLock<DomainTrie<usize>>> = OnceCell::const_new();

pub async fn init() {
    RULE_EXTRA_DOMAIN
        .get_or_init(|| async { RwLock::new(DomainTrie::new()) })
        .await;
}

pub async fn add_domain(domain: &str, rule_id: usize) {
    if let Some(lock) = RULE_EXTRA_DOMAIN.get() {
        let mut trie = lock.write().await;
        trie.insert(domain, rule_id);
    }
}

pub async fn match_domain(domain: &str) -> Option<usize> {
    match RULE_EXTRA_DOMAIN.get() {
        Some(l) => {
            let t = l.read().await;
            t.get(domain).copied()
        }
        None => None,
    }
}
