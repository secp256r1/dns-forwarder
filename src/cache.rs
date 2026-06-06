use lru::LruCache;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{OnceCell, RwLock};

type CacheKey = (Arc<str>, u16, u16);
type Cache = LruCache<CacheKey, (Vec<u8>, Instant)>;

static CACHE: OnceCell<RwLock<Cache>> = OnceCell::const_new();

pub async fn init(max_entries: usize) {
    CACHE
        .get_or_init(|| async {
            RwLock::new(LruCache::new(
                std::num::NonZeroUsize::new(max_entries).unwrap(),
            ))
        })
        .await;
}

pub async fn get(qname: &str, qtype: u16, qclass: u16) -> Option<(Vec<u8>, u32)> {
    let cache = CACHE.get()?;
    let mut rl = cache.write().await;
    let now = Instant::now();
    let key = (Arc::from(qname.to_ascii_lowercase()), qtype, qclass);

    if let Some((value, deadline)) = rl.get(&key) {
        if now >= *deadline {
            rl.pop(&key);
            None
        } else {
            let remaining_secs = deadline.duration_since(now).as_secs() as u32;
            Some((value.clone(), remaining_secs))
        }
    } else {
        None
    }
}

pub async fn insert(qname: &str, qtype: u16, qclass: u16, value: Vec<u8>, ttl_seconds: u32) {
    if let Some(lock) = CACHE.get() {
        let mut cache = lock.write().await;
        let deadline = Instant::now() + Duration::from_secs(ttl_seconds as u64);
        let key = (Arc::from(qname.to_ascii_lowercase()), qtype, qclass);
        cache.put(key, (value, deadline));
    }
}
