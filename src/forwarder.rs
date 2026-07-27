use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
};

use anyhow::{Result, bail};
use log::{error, warn};
use tokio::{
    net::UdpSocket,
    sync::{OnceCell, RwLock, mpsc, oneshot},
    time::{Duration, Instant, timeout},
};

type PendingMap = Arc<RwLock<HashMap<u16, (oneshot::Sender<Vec<u8>>, Instant)>>>;

static FORWARDER: OnceCell<Arc<RwLock<HashMap<SocketAddr, Forwarder>>>> = OnceCell::const_new();

#[derive(Clone)]
pub struct Forwarder {
    send: mpsc::Sender<(Vec<u8>, oneshot::Sender<Vec<u8>>)>,
}

impl Forwarder {
    pub async fn forward(
        &self,
        query: &[u8],
        qname: &str,
        upstream: &SocketAddr,
    ) -> Result<Vec<u8>> {
        let (tx, rx) = oneshot::channel();
        self.send.send((query.to_vec(), tx)).await?;
        match timeout(Duration::from_secs(5), rx).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_)) => bail!("get {qname} result from forwarder {upstream} cancelled"),
            Err(_) => bail!("get {qname} result from forwarder {upstream} timed out"),
        }
    }
}

pub async fn init() {
    FORWARDER
        .get_or_init(|| async { Arc::new(RwLock::new(HashMap::new())) })
        .await;
}

pub async fn get(remote_addr: &SocketAddr) -> Result<Forwarder> {
    match FORWARDER.get() {
        Some(forwarder) => {
            let read_guard = forwarder.read().await;
            Ok(match read_guard.get(remote_addr) {
                Some(socket) => socket.clone(),
                None => {
                    drop(read_guard);

                    let remote_addr = *remote_addr;
                    let (send, sender_recv) =
                        mpsc::channel::<(Vec<u8>, oneshot::Sender<Vec<u8>>)>(1000);

                    let socket = UdpSocket::bind("0.0.0.0:0").await?;
                    socket.connect(remote_addr).await?;
                    let socket = Arc::new(socket);

                    let pending: PendingMap = Arc::new(RwLock::new(HashMap::new()));
                    let pending_ttl = Duration::from_secs(5);
                    let shutdown = Arc::new(tokio::sync::Notify::new());

                    // Sender task: reads from mpsc, sends to UDP, registers pending oneshot
                    let sender_socket = socket.clone();
                    let sender_pending = pending.clone();
                    let sender_shutdown = shutdown.clone();
                    tokio::task::spawn(async move {
                        let mut recv = sender_recv;
                        loop {
                            tokio::select! {
                                biased;
                                _ = sender_shutdown.notified() => break,
                                msg = recv.recv() => match msg {
                                    Some((query, resp_tx)) => {
                                        if query.len() < 2 {
                                            continue;
                                        }
                                        let query_id =
                                            u16::from_be_bytes([query[0], query[1]]);
                                        {
                                            let mut map = sender_pending.write().await;
                                            map.retain(|_, (_, deadline)| *deadline > Instant::now());
                                            map.insert(query_id, (resp_tx, Instant::now() + pending_ttl));
                                        }
                                        if let Err(e) = sender_socket.send(&query).await {
                                            error!("send to {remote_addr} error: {e}");
                                            sender_pending.write().await.remove(&query_id);
                                        }
                                    }
                                    None => break,
                                }
                            }
                        }
                        // Channel closed or shutdown: drop pending waiters so receivers don't hang.
                        let map = std::mem::take(&mut *sender_pending.write().await);
                        for (_, (tx, _)) in map {
                            let _ = tx.send(Vec::new());
                        }
                    });

                    // Receiver task: reads from UDP, routes response to the matching oneshot sender
                    let receiver_pending = pending;
                    let receiver_shutdown = shutdown.clone();
                    tokio::task::spawn(async move {
                        let mut buf = [0u8; 4096];
                        loop {
                            let r = match socket.recv(&mut buf).await {
                                Ok(len) => buf[..len].to_vec(),
                                Err(e) => {
                                    error!("recv from {remote_addr} error: {e}");
                                    break;
                                }
                            };
                            if r.len() < 2 {
                                continue;
                            }
                            let query_id = u16::from_be_bytes([r[0], r[1]]);
                            if let Some((tx, _)) = receiver_pending.write().await.remove(&query_id)
                                && tx.send(r).is_err()
                            {
                                warn!("response for {remote_addr} query 0x{query_id:04x} arrived after timeout");
                            }
                        }
                        // Socket closed: notify sender to exit and drop pending waiters.
                        receiver_shutdown.notify_waiters();
                        let map = std::mem::take(&mut *receiver_pending.write().await);
                        for (_, (tx, _)) in map {
                            let _ = tx.send(Vec::new());
                        }
                    });

                    let socket_channel = Forwarder { send };

                    let mut write_guard = forwarder.write().await;
                    write_guard.insert(remote_addr, socket_channel.clone());

                    socket_channel
                }
            })
        }
        None => bail!("get forwarder error"),
    }
}
