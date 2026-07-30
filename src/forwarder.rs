use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::atomic::{AtomicU16, Ordering},
    sync::Arc,
};

use anyhow::{Result, bail};
use log::{error, warn};
use tokio::{
    net::UdpSocket,
    sync::{Mutex, mpsc, oneshot},
    time::{Duration, timeout},
};

const FORWARD_TIMEOUT: Duration = Duration::from_secs(5);

/// Messages from `forward()` callers to the per-upstream receiver task.
/// The receiver task owns the pending-response map privately, so routing
/// an upstream response (the hot path) never takes any cross-task lock.
enum Command {
    Register(u16, oneshot::Sender<Vec<u8>>),
    Cancel(u16),
}

static FORWARDER: tokio::sync::OnceCell<Arc<Mutex<HashMap<SocketAddr, Forwarder>>>> =
    tokio::sync::OnceCell::const_new();

pub struct Forwarder {
    socket: Arc<UdpSocket>,
    next_id: Arc<AtomicU16>,
    cmd_tx: mpsc::UnboundedSender<Command>,
}

impl Clone for Forwarder {
    fn clone(&self) -> Self {
        Forwarder {
            socket: self.socket.clone(),
            next_id: self.next_id.clone(),
            cmd_tx: self.cmd_tx.clone(),
        }
    }
}

impl Forwarder {
    pub async fn forward(&self, mut query: Vec<u8>, qname: &str) -> Result<Vec<u8>> {
        if query.len() < 2 {
            bail!("query too short");
        }
        let query_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        query[..2].copy_from_slice(&query_id.to_be_bytes());

        let (tx, rx) = oneshot::channel();
        // Register the waiter *before* sending, so a response that lands
        // between send() and await() is not missed.
        if self.cmd_tx.send(Command::Register(query_id, tx)).is_err() {
            bail!("receiver for {qname} closed");
        }

        if let Err(e) = self.socket.send(&query).await {
            let _ = self.cmd_tx.send(Command::Cancel(query_id));
            bail!("send query {qname} to upstream error: {e}");
        }

        match timeout(FORWARD_TIMEOUT, rx).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_)) => bail!("get {qname} result cancelled"),
            Err(_) => {
                let _ = self.cmd_tx.send(Command::Cancel(query_id));
                bail!("get {qname} result timed out")
            }
        }
    }
}

pub async fn init() {
    FORWARDER
        .get_or_init(|| async { Arc::new(Mutex::new(HashMap::new())) })
        .await;
}

pub async fn get(remote_addr: &SocketAddr) -> Result<Forwarder> {
    let Some(table) = FORWARDER.get() else {
        bail!("forwarder not initialized");
    };

    // Fast path: read lock + double-check on the slow path.
    {
        if let Some(f) = table.lock().await.get(remote_addr) {
            return Ok(f.clone());
        }
    }

    let remote_addr = *remote_addr;

    let bind_addr = if remote_addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
    socket.connect(remote_addr).await?;

    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<Command>();

    // Receiver task: sole owner of the pending-response map. It concurrently
    // accepts waiter registrations and routes upstream responses by query id.
    // On socket error it drops all pending waiters (their forward() calls get
    // RecvError) and removes this Forwarder from the global map so the next
    // request recreates the socket and spawns a fresh receiver.
    let recv_socket = socket.clone();
    tokio::task::spawn(async move {
        let mut waiters: HashMap<u16, oneshot::Sender<Vec<u8>>> = HashMap::new();
        let mut buf = [0u8; 4096];

        loop {
            tokio::select! {
                // Bias toward commands so a cancel racing with an incoming
                // response still lets us drop the waiter cleanly.
                biased;

                cmd = cmd_rx.recv() => match cmd {
                    Some(Command::Register(id, tx)) => {
                        if waiters.insert(id, tx).is_some() {
                            // Wrapping u16 means collisions are expected after
                            // 65535 forwards; the unlucky older waiter is
                            // dropped and its forward() will get RecvError.
                            warn!("query id 0x{id:04x} on {remote_addr} reused, dropping previous waiter");
                        }
                    }
                    Some(Command::Cancel(id)) => {
                        waiters.remove(&id);
                    }
                    None => break,
                },

                recv = recv_socket.recv(&mut buf) => match recv {
                    Ok(len) => {
                        if len < 2 {
                            continue;
                        }
                        let query_id = u16::from_be_bytes([buf[0], buf[1]]);
                        if let Some(tx) = waiters.remove(&query_id)
                            && tx.send(buf[..len].to_vec()).is_err()
                        {
                            warn!(
                                "response from {remote_addr} for 0x{query_id:04x} \
                                 arrived after caller dropped"
                            );
                        }
                    }
                    Err(e) => {
                        error!("recv from {remote_addr} error: {e}");
                        break;
                    }
                },
            }
        }

        // Drop all pending waiters; their forward() calls will get RecvError.
        waiters.clear();

        // Only remove the entry we created: compare socket identity so we
        // don't clobber a freshly-rebuilt Forwarder another task created
        // after our recv error.
        if let Some(table) = FORWARDER.get() {
            let mut guard = table.lock().await;
            if let Some(f) = guard.get(&remote_addr)
                && Arc::ptr_eq(&f.socket, &recv_socket)
            {
                guard.remove(&remote_addr);
            }
        }
    });

    let new_forwarder = Forwarder {
        socket: socket.clone(),
        next_id: Arc::new(AtomicU16::new(1)),
        cmd_tx,
    };

    // Slow-path insert with double-check to prevent duplicate creation under
    // concurrent gets for the same upstream. Losing the race just drops the
    // socket + receiver task we built (the cancel path drops pending waiters).
    let mut table = table.lock().await;
    if let Some(existing) = table.get(&remote_addr) {
        return Ok(existing.clone());
    }
    table.insert(remote_addr, new_forwarder.clone());
    Ok(new_forwarder)
}
