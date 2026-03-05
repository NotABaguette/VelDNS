use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::info;

/// All performance counters.  Every field is a separate atomic to avoid
/// false-sharing; padding is deliberately omitted here because the fields are
/// only written once per query (cheap).
#[derive(Debug, Default)]
pub struct Metrics {
    // Query routing
    pub queries_total:    AtomicU64,
    pub queries_static:   AtomicU64,  // answered from static CSV
    pub queries_cached:   AtomicU64,  // answered from cache
    pub queries_upstream: AtomicU64,  // forwarded to upstream
    pub queries_failed:   AtomicU64,  // SERVFAIL sent back

    // Cache
    pub cache_hits:   AtomicU64,
    pub cache_misses: AtomicU64,

    // Upstream health
    pub upstream_ok:       AtomicU64,
    pub upstream_errors:   AtomicU64,
    pub upstream_timeouts: AtomicU64,

    // Traffic volume
    pub bytes_rx: AtomicU64,
    pub bytes_tx: AtomicU64,
}

macro_rules! inc {
    ($name:ident) => {
        #[allow(dead_code)]
        pub fn $name(&self) {
            self.$name.fetch_add(1, Ordering::Relaxed);
        }
    };
}

macro_rules! add {
    ($name:ident, $field:ident) => {
        pub fn $name(&self, n: u64) {
            self.$field.fetch_add(n, Ordering::Relaxed);
        }
    };
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    inc!(queries_total);
    inc!(queries_static);
    inc!(queries_cached);
    inc!(queries_upstream);
    inc!(queries_failed);
    inc!(cache_hits);
    inc!(cache_misses);
    inc!(upstream_ok);
    inc!(upstream_errors);
    inc!(upstream_timeouts);
    add!(add_bytes_rx, bytes_rx);
    add!(add_bytes_tx, bytes_tx);

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            queries_total:    self.queries_total.load(Ordering::Relaxed),
            queries_static:   self.queries_static.load(Ordering::Relaxed),
            queries_cached:   self.queries_cached.load(Ordering::Relaxed),
            queries_upstream: self.queries_upstream.load(Ordering::Relaxed),
            queries_failed:   self.queries_failed.load(Ordering::Relaxed),
            cache_hits:       self.cache_hits.load(Ordering::Relaxed),
            cache_misses:     self.cache_misses.load(Ordering::Relaxed),
            upstream_ok:      self.upstream_ok.load(Ordering::Relaxed),
            upstream_errors:  self.upstream_errors.load(Ordering::Relaxed),
            upstream_timeouts:self.upstream_timeouts.load(Ordering::Relaxed),
            bytes_rx:         self.bytes_rx.load(Ordering::Relaxed),
            bytes_tx:         self.bytes_tx.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct Snapshot {
    pub queries_total:     u64,
    pub queries_static:    u64,
    pub queries_cached:    u64,
    pub queries_upstream:  u64,
    pub queries_failed:    u64,
    pub cache_hits:        u64,
    pub cache_misses:      u64,
    pub upstream_ok:       u64,
    pub upstream_errors:   u64,
    pub upstream_timeouts: u64,
    pub bytes_rx:          u64,
    pub bytes_tx:          u64,
}

/// Background task that logs a one-liner metrics summary every `interval`.
pub async fn reporter(metrics: Arc<Metrics>, interval: Duration) {
    let mut prev      = metrics.snapshot();
    let mut prev_time = Instant::now();
    let mut ticker    = tokio::time::interval(interval);
    ticker.tick().await; // skip the immediate first tick

    loop {
        ticker.tick().await;
        let cur     = metrics.snapshot();
        let elapsed = prev_time.elapsed().as_secs_f64().max(f64::EPSILON);

        let qps = (cur.queries_total - prev.queries_total) as f64 / elapsed;
        let hit_pct = if cur.cache_hits + cur.cache_misses > 0 {
            cur.cache_hits as f64 / (cur.cache_hits + cur.cache_misses) as f64 * 100.0
        } else {
            0.0
        };

        info!(
            qps = format!("{qps:.0}"),
            total     = cur.queries_total,
            r#static  = cur.queries_static,
            cached    = cur.queries_cached,
            upstream  = cur.queries_upstream,
            failed    = cur.queries_failed,
            cache_hit = format!("{hit_pct:.1}%"),
            up_err    = cur.upstream_errors,
            up_to     = cur.upstream_timeouts,
            rx_mb     = format!("{:.2}", cur.bytes_rx as f64 / 1_048_576.0),
            tx_mb     = format!("{:.2}", cur.bytes_tx as f64 / 1_048_576.0),
            "stats"
        );

        prev      = cur;
        prev_time = Instant::now();
    }
}
