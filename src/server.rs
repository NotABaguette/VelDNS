use crate::{
    cache::DnsCache,
    config::Config,
    handler::Handler,
    metrics::{self, Metrics},
    static_store::StaticStore,
    tunnel_mask::TunnelMask,
    upstream::UpstreamPool,
};
use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};
use tracing::{error, info, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────

pub async fn run(
    cfg:         Config,
    store:       Arc<StaticStore>,
    cache:       Arc<DnsCache>,
    metrics:     Arc<Metrics>,
    pool:        Arc<UpstreamPool>,
    tunnel_mask: Arc<TunnelMask>,
) -> Result<()> {
    let cfg     = Arc::new(cfg);
    let workers = cfg.worker_count();

    // ── Background tasks ─────────────────────────────────────────────
    let cache_bg = cache.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop { tick.tick().await; cache_bg.purge_expired(); }
    });

    tokio::spawn(metrics::reporter(metrics.clone(), Duration::from_secs(30)));

    // ── Spawn workers for every bind address ─────────────────────────
    let mut joins = Vec::new();

    for addr_str in &cfg.server.bind {
        let addr: SocketAddr = addr_str
            .parse()
            .with_context(|| format!("Invalid bind address '{addr_str}'"))?;

        info!("Listening on udp/{addr} with {workers} worker(s)");

        for wid in 0..workers {
            let sock = make_udp_socket(addr, cfg.server.recv_buf, cfg.server.send_buf)?;
            let sock = Arc::new(UdpSocket::from_std(sock)?);

            let h = Handler {
                cfg:         cfg.clone(),
                store:       store.clone(),
                cache:       cache.clone(),
                pool:        pool.clone(),
                metrics:     metrics.clone(),
                tunnel_mask: tunnel_mask.clone(),
            };

            joins.push(tokio::spawn(async move {
                udp_worker(wid, sock, h).await;
            }));
        }

        if cfg.server.tcp {
            let tcp_sock = make_tcp_listener(addr)?;
            let listener = TcpListener::from_std(tcp_sock)?;
            info!("Listening on tcp/{addr}");

            let h = Handler {
                cfg:         cfg.clone(),
                store:       store.clone(),
                cache:       cache.clone(),
                pool:        pool.clone(),
                metrics:     metrics.clone(),
                tunnel_mask: tunnel_mask.clone(),
            };

            joins.push(tokio::spawn(async move {
                tcp_acceptor(listener, h).await;
            }));
        }
    }

    futures::future::join_all(joins).await;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// UDP worker
// ─────────────────────────────────────────────────────────────────────────────

async fn udp_worker(id: usize, sock: Arc<UdpSocket>, handler: Handler) {
    let mut buf = vec![0u8; 4096];

    loop {
        let (len, src) = match sock.recv_from(&mut buf).await {
            Ok(v)  => v,
            Err(e) => {
                error!("worker-{id} recv error: {e}");
                tokio::time::sleep(Duration::from_millis(5)).await;
                continue;
            }
        };

        let query = buf[..len].to_vec();
        let sock  = sock.clone();
        let h     = handler.clone();

        tokio::spawn(async move {
            if let Some(resp) = h.handle(&query).await {
                if let Err(e) = sock.send_to(&resp, src).await {
                    warn!("send to {src}: {e}");
                }
            }
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TCP acceptor
// ─────────────────────────────────────────────────────────────────────────────

async fn tcp_acceptor(listener: TcpListener, handler: Handler) {
    loop {
        match listener.accept().await {
            Ok((stream, src)) => {
                let h = handler.clone();
                tokio::spawn(async move {
                    if let Err(e) = tcp_session(stream, src, h).await {
                        warn!("tcp/{src}: {e}");
                    }
                });
            }
            Err(e) => {
                error!("tcp accept error: {e}");
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    }
}

async fn tcp_session(
    mut stream: tokio::net::TcpStream,
    _src:       SocketAddr,
    handler:    Handler,
) -> anyhow::Result<()> {
    loop {
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf).await {
            Ok(_)  => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 { continue; }

        let mut query = vec![0u8; msg_len];
        stream.read_exact(&mut query).await?;

        if let Some(resp) = handler.handle(&query).await {
            let rlen = resp.len() as u16;
            stream.write_all(&rlen.to_be_bytes()).await?;
            stream.write_all(&resp).await?;
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Socket construction
// ─────────────────────────────────────────────────────────────────────────────

fn make_udp_socket(addr: SocketAddr, rcvbuf: usize, sndbuf: usize) -> anyhow::Result<std::net::UdpSocket> {
    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let sock   = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    sock.set_reuse_port(true)?;

    if rcvbuf > 0 { let _ = sock.set_recv_buffer_size(rcvbuf); }
    if sndbuf > 0 { let _ = sock.set_send_buffer_size(sndbuf); }

    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;

    Ok(sock.into())
}

fn make_tcp_listener(addr: SocketAddr) -> anyhow::Result<std::net::TcpListener> {
    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let sock   = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    sock.listen(1024)?;

    Ok(sock.into())
}