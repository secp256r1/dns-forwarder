use std::{
    collections::{HashMap, VecDeque},
    hash::{Hash, Hasher},
    time::{Duration, Instant},
};
use tokio::sync::{OnceCell, RwLock};

static CACHE: OnceCell<RwLock<Cache>> = OnceCell::const_new();

#[derive(Clone, Eq)]
pub struct CacheKey {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

impl PartialEq for CacheKey {
    fn eq(&self, other: &Self) -> bool {
        self.qname.eq_ignore_ascii_case(&other.qname)
            && self.qtype == other.qtype
            && self.qclass == other.qclass
    }
}

impl Hash for CacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.qname.to_lowercase().hash(state);
        self.qtype.hash(state);
        self.qclass.hash(state);
    }
}

struct Cache {
    map: HashMap<CacheKey, (Vec<u8>, Instant)>,
    order: VecDeque<CacheKey>,
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

pub async fn get(key: &CacheKey) -> Option<(Vec<u8>, u32)> {
    let cache = CACHE.get()?;
    let now = Instant::now();
    let mut rl = cache.write().await;
    if let Some((value, deadline)) = rl.map.get(key) {
        if now >= *deadline {
            rl.map.remove(key);
            if let Some(pos) = rl.order.iter().position(|k| k == key) {
                rl.order.remove(pos);
            }
            None
        } else {
            let remaining_secs = deadline.duration_since(now).as_secs() as u32;
            Some((value.clone(), remaining_secs))
        }
    } else {
        None
    }
}

pub async fn insert(key: CacheKey, value: Vec<u8>, ttl_seconds: u32) {
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
