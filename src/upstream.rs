use crate::config::UpstreamConfig;
use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::{net::UdpSocket, task::JoinSet, time::timeout};
use tracing::{debug, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Pool
// ─────────────────────────────────────────────────────────────────────────────

/// A pool of upstream DNS server addresses that can forward raw DNS queries.
///
/// Each call to [`UpstreamPool::query`] opens a fresh ephemeral UDP socket so
/// that concurrent queries never share state.  On Linux with `SO_REUSEPORT`
/// multiple short-lived sockets bound to 0.0.0.0:0 are extremely cheap.
///
/// Strategy (when `parallel = true`, the default):
///   1. Fire the query at **all** primary servers simultaneously.
///   2. Return the first valid response; abort the slower in-flight tasks.
///   3. If every primary server fails / times out, try fallback servers
///      (also in parallel).
///
/// Strategy (when `parallel = false`):
///   1. Try each primary server in order (with `retries` per server).
///   2. Then try each fallback server in order.
pub struct UpstreamPool {
    primary:  Vec<SocketAddr>,
    fallback: Vec<SocketAddr>,
    timeout:  Duration,
    retries:  u32,
    parallel: bool,
}

impl UpstreamPool {
    pub fn new(cfg: UpstreamConfig) -> Result<Self> {
        let parse = |list: &[String]| -> Result<Vec<SocketAddr>> {
            list.iter()
                .map(|s| {
                    s.parse::<SocketAddr>()
                     .map_err(|e| anyhow!("Invalid upstream address '{s}': {e}"))
                })
                .collect()
        };

        Ok(Self {
            primary:  parse(&cfg.primary)?,
            fallback: parse(&cfg.fallback)?,
            timeout:  Duration::from_millis(cfg.timeout_ms),
            retries:  cfg.retries,
            parallel: cfg.parallel,
        })
    }

    /// Forward `query_bytes` to an upstream server and return the raw response
    /// bytes with the message ID already replaced to `client_id`.
    pub async fn query(&self, query_bytes: &[u8], client_id: u16) -> Result<Vec<u8>> {
        let resp = if self.parallel {
            self.query_parallel(query_bytes).await?
        } else {
            self.query_sequential(query_bytes).await?
        };

        Ok(set_id(resp, client_id))
    }

    // ── Parallel strategy ─────────────────────────────────────────────────

    async fn query_parallel(&self, query: &[u8]) -> Result<Vec<u8>> {
        // --- Phase 1: primary servers ---
        if !self.primary.is_empty() {
            if let Ok(resp) = race(&self.primary, query, self.timeout).await {
                return Ok(resp);
            }
            warn!("All primary upstream servers failed; trying fallback");
        }

        // --- Phase 2: fallback servers ---
        if !self.fallback.is_empty() {
            if let Ok(resp) = race(&self.fallback, query, self.timeout).await {
                return Ok(resp);
            }
        }

        Err(anyhow!("All upstream DNS servers failed"))
    }

    // ── Sequential strategy ───────────────────────────────────────────────

    async fn query_sequential(&self, query: &[u8]) -> Result<Vec<u8>> {
        let servers = self.primary.iter().chain(self.fallback.iter());
        for &addr in servers {
            for attempt in 0..=self.retries {
                match send_recv(query, addr, self.timeout).await {
                    Ok(resp) => {
                        debug!(?addr, attempt, "upstream ok");
                        return Ok(resp);
                    }
                    Err(e) => warn!(?addr, attempt, "upstream error: {e}"),
                }
            }
        }
        Err(anyhow!("All upstream DNS servers failed"))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Send one UDP DNS query to every address in `addrs` simultaneously and
/// return the first successful response.  All losing tasks are aborted.
async fn race(addrs: &[SocketAddr], query: &[u8], dur: Duration) -> Result<Vec<u8>> {
    let mut set: JoinSet<Result<Vec<u8>>> = JoinSet::new();

    for &addr in addrs {
        let q = query.to_vec();
        set.spawn(async move { send_recv(&q, addr, dur).await });
    }

    let mut last_err = anyhow!("no servers");
    while let Some(res) = set.join_next().await {
        match res {
            Ok(Ok(resp)) => {
                set.abort_all();
                return Ok(resp);
            }
            Ok(Err(e)) => last_err = e,
            Err(e)     => last_err = anyhow!("task panic: {e}"),
        }
    }
    Err(last_err)
}

/// Send a single UDP DNS query to `addr` and return the raw response bytes.
///
/// A fresh ephemeral socket is created for each call; this means there is no
/// shared state between concurrent calls and no risk of ID collision.
async fn send_recv(query: &[u8], addr: SocketAddr, dur: Duration) -> Result<Vec<u8>> {
    let bind: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };

    let sock = UdpSocket::bind(bind).await
        .map_err(|e| anyhow!("bind ephemeral socket: {e}"))?;

    sock.send_to(query, addr).await
        .map_err(|e| anyhow!("send to {addr}: {e}"))?;

    let mut buf = vec![0u8; 4096];
    let len = timeout(dur, async {
        let (n, _) = sock.recv_from(&mut buf).await?;
        Ok::<usize, std::io::Error>(n)
    })
    .await
    .map_err(|_| anyhow!("timeout after {}ms waiting for {addr}", dur.as_millis()))?
    .map_err(|e| anyhow!("recv from {addr}: {e}"))?;

    buf.truncate(len);
    Ok(buf)
}

/// Replace the first two bytes (message ID) of a raw DNS message.
#[inline]
fn set_id(mut buf: Vec<u8>, id: u16) -> Vec<u8> {
    if buf.len() >= 2 {
        buf[0] = (id >> 8) as u8;
        buf[1] = (id & 0xff) as u8;
    }
    buf
}
