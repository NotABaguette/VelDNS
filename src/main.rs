mod cache;
mod config;
mod handler;
mod metrics;
mod server;
mod static_store;
mod tunnel_mask;
mod upstream;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;
use tunnel_mask::TunnelMask;

/// VelDNS – High-performance DNS server
///
/// Features:
///   • Static record overrides loaded from a CSV file (never forwarded upstream)
///   • Upstream mirroring with configurable primary + fallback servers
///   • TTL-respecting in-memory cache (millions of entries)
///   • DNSSEC-aware: passes RRSIG/DNSKEY/DS/NSEC* records, sets DO bit
///   • SO_REUSEPORT multi-worker UDP listener (one worker per CPU core)
#[derive(Parser)]
#[command(
    name    = "veldns",
    version,
    about   = "High-performance DNS server with static overrides and upstream mirroring",
    long_about = None,
)]
struct Args {
    /// Path to the TOML configuration file
    #[arg(short, long, default_value = "config.toml", env = "VELDNS_CONFIG")]
    config: PathBuf,

    /// Override log level (trace|debug|info|warn|error)
    #[arg(short, long, env = "VELDNS_LOG")]
    log: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // ── Load configuration ───────────────────────────────────────────────────
    let cfg = config::Config::load(&args.config)?;

    // ── Logging ──────────────────────────────────────────────────────────────
    let log_level = args
        .log
        .as_deref()
        .unwrap_or(&cfg.logging.level)
        .to_string();
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&log_level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();

    info!(
        "VelDNS v{} starting – workers={} bind={:?}",
        env!("CARGO_PKG_VERSION"),
        cfg.worker_count(),
        cfg.server.bind
    );

    // ── Static records ───────────────────────────────────────────────────────
    let static_store = static_store::StaticStore::load(&cfg.static_records.file)?;

    // ── Shared state ─────────────────────────────────────────────────────────
    let cache = Arc::new(cache::DnsCache::new(cfg.cache.clone()));
    let metrics = Arc::new(metrics::Metrics::new());
    let upstream = Arc::new(upstream::UpstreamPool::new(cfg.upstream.clone())?);
    let tunnel_mask = Arc::new(TunnelMask::new(&cfg.tunnel_mask));
    tunnel_mask.spawn_eviction_task();

    // ── Run ──────────────────────────────────────────────────────────────────
    server::run(cfg, static_store, cache, metrics, upstream, tunnel_mask).await
}
