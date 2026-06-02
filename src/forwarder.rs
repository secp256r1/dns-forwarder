use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use anyhow::{Result, bail};
use log::error;
use tokio::{
    net::UdpSocket,
    sync::{OnceCell, RwLock, broadcast, mpsc},
};

static FORWARDER: OnceCell<Arc<RwLock<HashMap<SocketAddr, Forwarder>>>> = OnceCell::const_new();

#[derive(Clone)]
pub struct Forwarder {
    send: mpsc::Sender<Vec<u8>>,
    recv: broadcast::Sender<Vec<u8>>,
}

impl Forwarder {
    pub async fn send(&self, query: &[u8]) -> Result<()> {
        Ok(self.send.send(query.to_vec()).await?)
    }

    pub async fn recv(&self) -> Result<Vec<u8>> {
        let mut recv = self.recv.subscribe();
        Ok(recv.recv().await?)
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
                    let (send, sender_recv) = tokio::sync::mpsc::channel(1000);
                    let (recv, _) = tokio::sync::broadcast::channel(1000);
                    let socket_channel = Forwarder { send, recv };

                    let socket = UdpSocket::bind("0.0.0.0:0").await?;
                    socket.connect(remote_addr).await?;
                    let socket = Arc::new(socket);
                    let socket_recv = socket.clone();

                    tokio::task::spawn(async move {
                        let mut sender_recv = sender_recv;
                        loop {
                            if let Some(query) = sender_recv.recv().await
                                && let Err(e) = socket_recv.send(&query).await
                            {
                                error!("send to {remote_addr} error: {e}");
                            }
                        }
                    });

                    let send_socket_channel = socket_channel.clone();
                    tokio::task::spawn(async move {
                        loop {
                            let mut buf = [0u8; 4096];
                            let len = match socket.recv(&mut buf).await {
                                Ok(len) => len,
                                Err(e) => {
                                    error!("recv from {remote_addr} error: {e}");
                                    continue;
                                }
                            };
                            if let Err(e) = send_socket_channel.recv.send(buf[..len].to_vec()) {
                                error!("send recv result from {remote_addr} error: {e}");
                            }
                        }
                    });

                    let mut write_guard = forwarder.write().await;
                    write_guard.insert(remote_addr, socket_channel.clone());

                    socket_channel
                }
            })
        }
        None => bail!("get forwarder error"),
    }
}
