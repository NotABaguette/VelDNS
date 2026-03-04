use serde::{Deserialize, Serialize};

/// Configuration for the tunnel masking feature.
///
/// Deserialized from the `[tunnel_mask]` section of `config.toml`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct TunnelMaskConfig {
    /// Enable the tunnel masking feature.
    pub enabled: bool,

    /// Operating mode: `"client"` or `"server"`.
    pub mode: String,

    /// The cover/relay DNS zone.  The VelDNS server node must be the
    /// authoritative NS for this zone.
    pub relay_zone: String,

    /// Encoding mode: `"hex"` (default, maximum stealth) or `"syllable"`.
    pub encoding: String,

    // ── Client-only ──────────────────────────────────────────────────
    /// Upstream recursive resolver(s) to send masked queries through.
    pub resolver: Vec<String>,

    /// Timeout (ms) waiting for the final fragment response.
    pub session_ttl_ms: u64,

    /// Maximum total QNAME length (characters) for masked queries.
    pub max_qname_len: usize,

    /// Characters per hex label (default 12, looks like CDN hashes).
    pub label_len: usize,

    /// Random jitter range (ms) inserted between non-final fragment sends.
    /// `[min, max]` – set both to 0 to disable.
    pub send_jitter_ms: [u64; 2],

    // ── Server-only ─────────────────────────────────────────────────
    /// Address of the real dnstt / slipstream server to forward to.
    pub upstream_addr: String,

    /// Maximum AAAA records in the final response (stealth vs throughput).
    pub max_response_records: usize,

    /// TTL for dummy (non-final fragment) responses.
    pub dummy_ttl: u32,

    /// TTL for the real data (final fragment) response.
    pub response_ttl: u32,

    // ── Detection tuning (client only) ──────────────────────────────
    /// Known tunnel zone suffixes.  Queries for these zones are always
    /// intercepted (score += 1 per match).
    pub known_tunnel_zones: Vec<String>,

    /// Enable heuristic auto-detection (entropy, label length, etc.).
    pub auto_detect: bool,

    /// QNAME length above which a query is considered suspect.
    pub qname_len_threshold: usize,

    /// Individual label length above which a query is suspect.
    pub label_len_threshold: usize,

    /// Shannon entropy (bits/char) threshold for any single label.
    pub entropy_threshold: f64,

    /// Fraction of base-32 characters `[a-z2-7]` in any label.
    pub base32_fraction_threshold: f64,
}

impl Default for TunnelMaskConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: "client".into(),
            relay_zone: "relay.example.net".into(),
            encoding: "hex".into(),

            resolver: vec!["8.8.8.8:53".into()],
            session_ttl_ms: 5000,
            max_qname_len: 120,
            label_len: 12,
            send_jitter_ms: [3, 15],

            upstream_addr: "127.0.0.1:5353".into(),
            max_response_records: 10,
            dummy_ttl: 60,
            response_ttl: 30,

            known_tunnel_zones: vec![],
            auto_detect: true,
            qname_len_threshold: 80,
            label_len_threshold: 30,
            entropy_threshold: 3.8,
            base32_fraction_threshold: 0.85,
        }
    }
}

/// Which role this VelDNS instance plays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeMode {
    Client,
    Server,
}

impl TunnelMaskConfig {
    pub fn node_mode(&self) -> NodeMode {
        if self.mode.eq_ignore_ascii_case("server") {
            NodeMode::Server
        } else {
            NodeMode::Client
        }
    }
}
