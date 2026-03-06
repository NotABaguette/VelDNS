//! Configuration types for the `tunnel_mask` subsystem.
//!
//! Deserialized from the `[tunnel_mask]` section of `config.toml`.

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Node mode
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeMode {
    /// This VelDNS instance sits in the restricted network alongside the
    /// dnstt / slipstream client.  It fragments outgoing tunnel queries into
    /// innocent-looking AAAA queries and reassembles the response.
    Client,

    /// This VelDNS instance sits in the open network alongside the
    /// dnstt / slipstream server.  It reassembles incoming fragments, forwards
    /// the original query to the tunnel server, and returns the response packed
    /// into AAAA records.
    Server,
}

impl Default for NodeMode {
    fn default() -> Self {
        NodeMode::Client
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Encoding mode
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EncodingMode {
    /// Hex encoding — no structural markers, indistinguishable from CDN hash
    /// lookups.  Maximum stealth.  **This is the default and recommended mode.**
    Hex,

    /// Syllable (CVC word) encoding — structured metadata label with a `tm`
    /// prefix.  May be fingerprinted by ML-based DNS classifiers.  Use only
    /// where hex mode is impractical.
    Syllable,
}

impl Default for EncodingMode {
    fn default() -> Self {
        EncodingMode::Hex
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level TunnelMaskConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Full configuration for the `tunnel_mask` subsystem.
///
/// All fields have sensible defaults; most operators only need to set `enabled`,
/// `mode`, `relay_zone`, and either `resolver` (client) or `upstream_addr`
/// (server).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct TunnelMaskConfig {
    // ── Global ───────────────────────────────────────────────────────────────
    /// Enable or disable the entire subsystem.  When `false` (default),
    /// `handle_query` is a no-op and adds zero overhead.
    pub enabled: bool,

    /// `"client"` — restricted network node that intercepts and fragments.
    /// `"server"` — open network node that reassembles and forwards.
    pub mode: NodeMode,

    /// DNS zone suffix used in every relay AAAA query QNAME.
    /// Must be delegated to the server node's authoritative IP at your registrar.
    ///
    /// Example: `"relay.example.net"`
    pub relay_zone: String,

    /// Wire encoding for the fragment QNAME.
    /// `"hex"` (default) — maximum stealth.
    /// `"syllable"` — optional, slightly higher fingerprinting risk.
    pub encoding: EncodingMode,

    // ── Client-only ───────────────────────────────────────────────────────────
    /// Upstream recursive resolver(s) through which masked queries are routed.
    ///
    /// **Queries go HERE, not directly to the server node.**  The recursive
    /// resolver forwards them through the DNS hierarchy to the server node
    /// (which is authoritative for `relay_zone`).  This makes the traffic
    /// indistinguishable from normal DNS.
    ///
    /// Typically matches `[upstream].primary`.  Default: `["8.8.8.8:53"]`.
    pub resolver: Vec<String>,

    /// How long (ms) the client waits for the final-fragment response before
    /// returning SERVFAIL to the tunnel client.  Default: 5000.
    pub session_ttl_ms: u64,

    /// Maximum total QNAME length (characters) for masked queries, including
    /// the relay zone suffix.  Payload capacity per fragment is derived from
    /// this.  Default: 120.
    pub max_qname_len: usize,

    /// Number of hex characters per DNS label in **hex** encoding mode.
    /// Shorter labels look more like CDN content hashes.  Default: 12.
    pub label_len: usize,

    /// `[min_ms, max_ms]` — random jitter range between successive non-final
    /// fragment sends.  Avoids a burst pattern.  Default: `[3, 15]`.
    pub send_jitter_ms: [u64; 2],

    // ── Server-only ───────────────────────────────────────────────────────────
    /// `IP:port` of the real dnstt / slipstream server.  The server node
    /// forwards reconstructed original queries here.  Default: `"127.0.0.1:5353"`.
    pub upstream_addr: String,

    /// Maximum number of AAAA records in a single data response.  Each record
    /// carries 16 bytes of encoded tunnel response.  Default: 10 (= 158 B net).
    pub max_response_records: usize,

    /// TTL (seconds) for dummy AAAA responses sent for non-final fragments.
    /// Non-zero so the recursive resolver sees healthy DNS behaviour.
    /// Default: 60.
    pub dummy_ttl: u32,

    /// TTL (seconds) for AAAA records in the final data response.
    /// Default: 30.
    pub response_ttl: u32,

    /// How long the server waits (ms) after receiving the final fragment for
    /// late-arriving earlier fragments before returning SERVFAIL.
    ///
    /// Real recursive paths can reorder or delay packets by hundreds of
    /// milliseconds; a very small wait window causes avoidable reassembly
    /// failures under normal internet jitter.  Default: 1200.
    pub final_spin_wait_ms: u64,

    // ── Detection tuning (client only) ───────────────────────────────────────
    /// QNAME suffixes that are unconditionally treated as tunnel zones.
    /// Matching queries bypass the scoring heuristic entirely.
    pub known_tunnel_zones: Vec<String>,

    /// Enable heuristic auto-detection for queries whose QNAME does not match
    /// any `known_tunnel_zones` entry.  Default: true.
    pub auto_detect: bool,

    /// QNAME length (chars) above which the "long QNAME" rule fires (+1 point).
    /// Default: 80.
    pub qname_len_threshold: usize,

    /// Label length (chars) above which the "long label" rule fires (+1 point).
    /// Default: 30.
    pub label_len_threshold: usize,

    /// Shannon entropy of the longest label above which the "high entropy"
    /// rule fires (+1 point).  Default: 3.8.
    pub entropy_threshold: f64,

    /// Fraction of base32 alphabet characters `[a-z2-7]` in the longest label
    /// above which the "base32 saturation" rule fires (+1 point).  Default: 0.85.
    pub base32_fraction_threshold: f64,

    // ── Syllable encoder (optional) ───────────────────────────────────────────
    /// Path to a plain-text file containing one CVC word per line (4 096+
    /// entries).  If set and the file exists, it replaces the built-in word
    /// table.  If the file has fewer than 4 096 entries the remainder is filled
    /// from the built-in table.  Ignored when `encoding = "hex"`.
    pub syllable_list_file: Option<String>,
}

impl Default for TunnelMaskConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: NodeMode::Client,
            relay_zone: "relay.example.net".into(),
            encoding: EncodingMode::Hex,
            resolver: vec!["8.8.8.8:53".into()],
            session_ttl_ms: 5_000,
            max_qname_len: 120,
            label_len: 12,
            send_jitter_ms: [3, 15],
            upstream_addr: "127.0.0.1:5353".into(),
            max_response_records: 10,
            dummy_ttl: 60,
            response_ttl: 30,
            final_spin_wait_ms: 1_200,
            known_tunnel_zones: vec![],
            auto_detect: true,
            qname_len_threshold: 80,
            label_len_threshold: 30,
            entropy_threshold: 3.8,
            base32_fraction_threshold: 0.85,
            syllable_list_file: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Derived capacity helpers
// ─────────────────────────────────────────────────────────────────────────────

impl TunnelMaskConfig {
    /// Maximum raw **payload** bytes per fragment in hex encoding mode.
    ///
    /// From the spec:
    /// ```text
    /// available  = max_qname_len - relay_zone.len() - 1      (leading dot)
    /// labels     = floor(available / (label_len + 1))
    /// hex_chars  = labels × label_len
    /// total_bytes = floor(hex_chars / 2)
    /// payload    = total_bytes − 10                          (10-byte frame header)
    /// ```
    #[allow(dead_code)]
    pub fn bytes_per_fragment_hex(&self) -> usize {
        let zone_len = self.relay_zone.trim_matches('.').len();
        let label_with_dot = self.label_len + 1;
        let available = self.max_qname_len.saturating_sub(zone_len + 1);
        let n_labels = available / label_with_dot;
        if n_labels == 0 {
            return 1;
        }
        let hex_chars = n_labels * self.label_len;
        let total_bytes = hex_chars / 2;
        total_bytes.saturating_sub(10).max(1)
    }

    /// Maximum raw **payload** bytes per fragment in syllable encoding mode.
    ///
    /// ```text
    /// metadata label: "tm" + 8hex + "-" + 2d + "-" + 2d + "-" + 2d + "-" + 1d
    ///               = 22 chars  (+1 dot separator = 23)
    /// each pair label ≤ 21 chars (+1 dot separator = 22)
    /// each pair encodes 6 bytes
    /// ```
    #[allow(dead_code)]
    pub fn bytes_per_fragment_syllable(&self) -> usize {
        const METADATA_WITH_DOT: usize = 23; // 22 chars + leading dot
        const PAIR_WITH_DOT: usize = 22; // 21 chars max + dot
        const BYTES_PER_PAIR: usize = 6;

        let zone_len = self.relay_zone.trim_matches('.').len();
        // Bytes consumed by fixed parts: metadata + dot-before-zone + zone
        let fixed = METADATA_WITH_DOT + zone_len + 1;
        if self.max_qname_len <= fixed {
            return BYTES_PER_PAIR;
        }
        let available = self.max_qname_len - fixed;
        let n_pairs = (available / PAIR_WITH_DOT).max(1);
        n_pairs * BYTES_PER_PAIR
    }

    /// Maximum raw payload bytes per fragment for the configured encoding mode.
    #[allow(dead_code)]
    pub fn bytes_per_fragment(&self) -> usize {
        match self.encoding {
            EncodingMode::Hex => self.bytes_per_fragment_hex(),
            EncodingMode::Syllable => self.bytes_per_fragment_syllable(),
        }
    }
}
