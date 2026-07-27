use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
};

use anyhow::{Result, bail};
use log::{error, warn};
use tokio::{
    net::UdpSocket,
    sync::{OnceCell, RwLock, oneshot},
    time::{Duration, timeout},
};

type WaiterMap = Arc<RwLock<HashMap<u16, oneshot::Sender<Vec<u8>>>>>;

const FORWARD_TIMEOUT: Duration = Duration::from_secs(5);

static FORWARDER: OnceCell<Arc<RwLock<HashMap<SocketAddr, Forwarder>>>> = OnceCell::const_new();

#[derive(Clone)]
pub struct Forwarder {
    socket: Arc<UdpSocket>,
    waiters: WaiterMap,
}

impl Forwarder {
    pub async fn forward(&self, query: &[u8], qname: &str) -> Result<Vec<u8>> {
        if query.len() < 2 {
            bail!("query too short");
        }
        let query_id = u16::from_be_bytes([query[0], query[1]]);

        let (tx, rx) = oneshot::channel();
        self.waiters.write().await.insert(query_id, tx);

        if let Err(e) = self.socket.send(query).await {
            self.waiters.write().await.remove(&query_id);
            bail!("send query {qname} to upstream error: {e}");
        }

        match timeout(FORWARD_TIMEOUT, rx).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_)) => bail!("get {qname} result cancelled"),
            Err(_) => {
                self.waiters.write().await.remove(&query_id);
                bail!("get {qname} result timed out")
            }
        }
    }
}

pub async fn init() {
    FORWARDER
        .get_or_init(|| async { Arc::new(RwLock::new(HashMap::new())) })
        .await;
}

pub async fn get(remote_addr: &SocketAddr) -> Result<Forwarder> {
    let Some(forwarder) = FORWARDER.get() else {
        bail!("forwarder not initialized");
    };

    {
        let read_guard = forwarder.read().await;
        if let Some(f) = read_guard.get(remote_addr) {
            return Ok(f.clone());
        }
    }

    let remote_addr = *remote_addr;
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(remote_addr).await?;
    let socket = Arc::new(socket);
    let waiters: WaiterMap = Arc::new(RwLock::new(HashMap::new()));

    // Receiver task: reads responses from the upstream and routes them
    // to the matching forward() caller via the query id. On socket error,
    // removes this Forwarder from the global map so the next request
    // recreates the socket (and spawns a fresh receiver).
    let recv_waiters = waiters.clone();
    let recv_socket = socket.clone();
    tokio::task::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            match recv_socket.recv(&mut buf).await {
                Ok(len) => {
                    if len < 2 {
                        continue;
                    }
                    let query_id = u16::from_be_bytes([buf[0], buf[1]]);
                    if let Some(tx) = recv_waiters.write().await.remove(&query_id)
                        && tx.send(buf[..len].to_vec()).is_err()
                    {
                        warn!("response from {remote_addr} for 0x{query_id:04x} arrived after caller dropped");
                    }
                }
                Err(e) => {
                    error!("recv from {remote_addr} error: {e}");
                    break;
                }
            }
        }
        // Drop all pending waiters; their forward() calls will get RecvError.
        recv_waiters.write().await.clear();
        if let Some(forwarder) = FORWARDER.get() {
            forwarder.write().await.remove(&remote_addr);
        }
    });

    let new_forwarder = Forwarder {
        socket: socket.clone(),
        waiters: waiters.clone(),
    };

    forwarder
        .write()
        .await
        .insert(remote_addr, new_forwarder.clone());

    Ok(new_forwarder)
}
