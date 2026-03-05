use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

// Import the tunnel_mask config type so we can embed it in the top-level config.
// This avoids a circular dependency: config only imports from tunnel_mask::config,
// which has no back-reference to the rest of VelDNS.
use crate::tunnel_mask::config::TunnelMaskConfig;

// ─────────────────────────────────────────────────────────────────────────────
// Top-level
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    pub server:         ServerConfig,
    pub upstream:       UpstreamConfig,
    pub cache:          CacheConfig,
    pub dnssec:         DnssecConfig,
    pub static_records: StaticConfig,
    pub logging:        LoggingConfig,
    pub tunnel_mask:    TunnelMaskConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server:         ServerConfig::default(),
            upstream:       UpstreamConfig::default(),
            cache:          CacheConfig::default(),
            dnssec:         DnssecConfig::default(),
            static_records: StaticConfig::default(),
            logging:        LoggingConfig::default(),
            tunnel_mask:    TunnelMaskConfig::default(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Server
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ServerConfig {
    /// List of UDP addresses to listen on, e.g. ["0.0.0.0:53", "[::]:53"]
    pub bind: Vec<String>,

    /// Worker threads per bind address.  0 = number of logical CPU cores.
    pub workers: usize,

    /// Maximum UDP payload advertised in EDNS0 OPT records (bytes).
    pub max_udp_payload: u16,

    /// Also listen for TCP DNS (for large responses / zone-transfers).
    pub tcp: bool,

    /// Per-socket receive buffer size in bytes (0 = OS default).
    pub recv_buf: usize,

    /// Per-socket send buffer size in bytes (0 = OS default).
    pub send_buf: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind:            vec!["0.0.0.0:5353".to_string()],
            workers:         0,
            max_udp_payload: 4096,
            tcp:             true,
            recv_buf:        0,
            send_buf:        0,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Upstream
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct UpstreamConfig {
    /// Primary resolvers – tried first (parallel if parallel=true).
    pub primary: Vec<String>,

    /// Fallback resolvers – used only when all primary servers fail.
    pub fallback: Vec<String>,

    /// Per-server query timeout in milliseconds.
    pub timeout_ms: u64,

    /// Maximum retry attempts per server before marking it failed.
    pub retries: u32,

    /// Fire queries at all primary servers simultaneously and use the
    /// fastest response.  Wastes a little bandwidth but greatly reduces
    /// tail latency.
    pub parallel: bool,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            primary:    vec!["8.8.8.8:53".into(), "8.8.4.4:53".into()],
            fallback:   vec!["1.1.1.1:53".into(), "1.0.0.1:53".into()],
            timeout_ms: 3_000,
            retries:    2,
            parallel:   true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cache
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct CacheConfig {
    /// Enable the in-memory response cache.
    pub enabled: bool,

    /// Maximum number of cache entries before eviction begins.
    pub max_entries: usize,

    /// Clamp TTLs to at least this many seconds (prevents zero-TTL storms).
    pub min_ttl: u32,

    /// Clamp TTLs to at most this many seconds.
    pub max_ttl: u32,

    /// TTL used for NXDOMAIN / SERVFAIL negative cache entries.
    pub negative_ttl: u32,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled:      true,
            max_entries:  1_000_000,
            min_ttl:      30,
            max_ttl:      86_400,
            negative_ttl: 300,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DNSSEC
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct DnssecConfig {
    /// Forward DNSSEC records (RRSIG, DNSKEY, DS, NSEC, NSEC3) transparently
    /// and set the DO bit in upstream queries.
    pub enabled: bool,

    /// Perform full chain-of-trust validation on upstream responses via the
    /// hickory-resolver validator.  Adds a small latency overhead.
    pub validate: bool,
}

impl Default for DnssecConfig {
    fn default() -> Self {
        Self {
            enabled:  true,
            validate: false,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Static records
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct StaticConfig {
    /// Path to the CSV file containing static records.
    pub file: String,

    /// Mark responses for static domains as Authoritative (AA bit).
    pub authoritative: bool,
}

impl Default for StaticConfig {
    fn default() -> Self {
        Self {
            file:          "static_records.csv".into(),
            authoritative: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Logging
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// Minimum log level: trace | debug | info | warn | error
    pub level: String,

    /// Log every individual DNS query (noisy; useful for debugging).
    pub log_queries: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level:       "info".into(),
            log_queries: false,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let src = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read config file: {}", path.display()))?;
        let cfg: Config = toml::from_str(&src)
            .with_context(|| format!("Cannot parse config file: {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        anyhow::ensure!(!self.server.bind.is_empty(), "server.bind must not be empty");
        anyhow::ensure!(
            !self.upstream.primary.is_empty() || !self.upstream.fallback.is_empty(),
            "at least one upstream DNS server must be configured"
        );
        Ok(())
    }

    /// Effective number of worker threads.
    pub fn worker_count(&self) -> usize {
        if self.server.workers == 0 {
            num_cpus::get().max(1)
        } else {
            self.server.workers
        }
    }
}
