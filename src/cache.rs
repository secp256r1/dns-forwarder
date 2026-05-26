use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

static CACHE: std::sync::OnceLock<Mutex<Cache>> = std::sync::OnceLock::new();

struct Cache {
    map: HashMap<Vec<u8>, (Vec<u8>, Instant)>,
    max_entries: usize,
    ttl: Duration,
}

pub fn init(max_entries: usize, ttl_seconds: u64) {
    let cache = Cache {
        map: HashMap::new(),
        max_entries,
        ttl: Duration::from_secs(ttl_seconds),
    };
    CACHE.get_or_init(|| Mutex::new(cache));
}

pub fn get(key: &Vec<u8>) -> Option<Vec<u8>> {
    let mut cache = CACHE.get()?.lock().ok()?;
    let (value, deadline) = cache.map.get(key)?;
    if Instant::now() >= *deadline {
        cache.map.remove(key);
        return None;
    }
    Some(value.clone())
}

pub fn insert(key: Vec<u8>, value: Vec<u8>) {
    if let Some(lock) = CACHE.get()
        && let Ok(mut cache) = lock.lock()
    {
        cache
            .map
            .retain(|_, (_, deadline)| Instant::now() < *deadline);
        if cache.map.len() >= cache.max_entries
            && let Some(key) = cache.map.keys().next().cloned()
        {
            cache.map.remove(&key);
        }
        let ttl = cache.ttl;
        cache.map.insert(key, (value, Instant::now() + ttl));
    }
}
