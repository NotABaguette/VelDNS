use crate::tunnel_mask::TunnelMaskConfig;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

// ─────────────────────────────────────────────────────────────────────────────
// Top-level
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    pub upstream: UpstreamConfig,
    pub cache: CacheConfig,
    pub dnssec: DnssecConfig,
    pub static_records: StaticConfig,
    pub logging: LoggingConfig,
    pub tunnel_mask: TunnelMaskConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            upstream: UpstreamConfig::default(),
            cache: CacheConfig::default(),
            dnssec: DnssecConfig::default(),
            static_records: StaticConfig::default(),
            logging: LoggingConfig::default(),
            tunnel_mask: TunnelMaskConfig::default(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Server
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ServerConfig {
    pub bind: Vec<String>,
    pub workers: usize,
    pub max_udp_payload: u16,
    pub tcp: bool,
    pub recv_buf: usize,
    pub send_buf: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: vec!["0.0.0.0:5353".to_string()],
            workers: 0,
            max_udp_payload: 4096,
            tcp: true,
            recv_buf: 0,
            send_buf: 0,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Upstream
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct UpstreamConfig {
    pub primary: Vec<String>,
    pub fallback: Vec<String>,
    pub timeout_ms: u64,
    pub retries: u32,
    pub parallel: bool,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            primary: vec!["8.8.8.8:53".into(), "8.8.4.4:53".into()],
            fallback: vec!["1.1.1.1:53".into(), "1.0.0.1:53".into()],
            timeout_ms: 3_000,
            retries: 2,
            parallel: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cache
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct CacheConfig {
    pub enabled: bool,
    pub max_entries: usize,
    pub min_ttl: u32,
    pub max_ttl: u32,
    pub negative_ttl: u32,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_entries: 1_000_000,
            min_ttl: 30,
            max_ttl: 86_400,
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
    pub enabled: bool,
    pub validate: bool,
}

impl Default for DnssecConfig {
    fn default() -> Self {
        Self {
            enabled: true,
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
    pub file: String,
    pub authoritative: bool,
}

impl Default for StaticConfig {
    fn default() -> Self {
        Self {
            file: "static_records.csv".into(),
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
    pub level: String,
    pub log_queries: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
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
        anyhow::ensure!(
            !self.server.bind.is_empty(),
            "server.bind must not be empty"
        );
        anyhow::ensure!(
            !self.upstream.primary.is_empty() || !self.upstream.fallback.is_empty(),
            "at least one upstream DNS server must be configured"
        );
        Ok(())
    }

    pub fn worker_count(&self) -> usize {
        if self.server.workers == 0 {
            num_cpus::get().max(1)
        } else {
            self.server.workers
        }
    }
}
