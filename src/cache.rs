use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};
use tokio::sync::{OnceCell, RwLock};

static CACHE: OnceCell<RwLock<Cache>> = OnceCell::const_new();

struct Cache {
    map: HashMap<Vec<u8>, (Vec<u8>, Instant)>,
    order: VecDeque<Vec<u8>>,
    max_entries: usize,
}

pub async fn init(max_entries: usize) {
    let cache = Cache {
        map: HashMap::new(),
        order: VecDeque::new(),
        max_entries,
    };
    CACHE.get_or_init(|| async { RwLock::new(cache) }).await;
}

pub async fn get(key: &Vec<u8>) -> Option<(Vec<u8>, u32)> {
    let cache = CACHE.get()?;
    let now = Instant::now();
    let rl = cache.read().await;
    let (value, deadline) = rl.map.get(key)?;
    if now >= *deadline {
        drop(rl);
        let mut wl = cache.write().await;
        wl.map.remove(key);
        None
    } else {
        let remaining_secs = deadline.duration_since(now).as_secs() as u32;
        Some((value.clone(), remaining_secs))
    }
}

pub async fn insert(key: Vec<u8>, value: Vec<u8>, ttl_seconds: u32) {
    if let Some(lock) = CACHE.get() {
        let mut cache = lock.write().await;
        let deadline = Instant::now() + Duration::from_secs(ttl_seconds as u64);

        if !cache.map.contains_key(&key) {
            cache.order.push_back(key.clone());
        }

        cache.map.insert(key, (value, deadline));

        while cache.map.len() > cache.max_entries {
            if let Some(front) = cache.order.pop_front() {
                cache.map.remove(&front);
            }
        }
    }
}
