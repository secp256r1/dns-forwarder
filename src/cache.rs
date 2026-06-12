use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use lru::LruCache;
use tokio::sync::{OnceCell, RwLock};

use crate::dns::QueryInfo;

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

fn key(query: &QueryInfo) -> (Arc<str>, u16, u16) {
    (
        Arc::from(query.qname.to_ascii_lowercase()),
        query.qtype,
        query.qclass,
    )
}

pub async fn get(query: &QueryInfo) -> Option<(Vec<u8>, u32)> {
    let cache = CACHE.get()?;
    let now = Instant::now();
    let key = key(query);

    {
        let rl = cache.read().await;
        if let Some((value, deadline)) = rl.peek(&key)
            && now < *deadline
        {
            let remaining_secs = deadline.duration_since(now).as_secs() as u32;
            return Some((value.clone(), remaining_secs));
        }
    }

    let mut wl = cache.write().await;
    if let Some((_, deadline)) = wl.peek(&key)
        && now >= *deadline
    {
        wl.pop(&key);
    }
    None
}

pub async fn insert(query: &QueryInfo, value: Vec<u8>, ttl_seconds: u32) {
    if let Some(lock) = CACHE.get() {
        let mut cache = lock.write().await;
        let deadline = Instant::now() + Duration::from_secs(ttl_seconds as u64);
        cache.put(key(query), (value, deadline));
    }
}
