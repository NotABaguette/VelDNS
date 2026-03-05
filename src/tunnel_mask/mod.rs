//! `tunnel_mask` — DNS tunnel traffic masking subsystem for VelDNS.
//!
//! ## Overview
//!
//! Intercepts dnstt / slipstream tunnel queries and relays them through a
//! layer of innocent-looking AAAA queries between two VelDNS nodes (one in
//! the restricted network, one in the open network).  No DoH, no HTTP — pure
//! UDP DNS the entire way.
//!
//! ## Node modes
//!
//! | Mode     | Where it runs              | What it does                              |
//! |----------|----------------------------|-------------------------------------------|
//! | `client` | Restricted network         | Detects, fragments, fires, reassembles    |
//! | `server` | Open network (near tunnel) | Buffers fragments, forwards, encodes AAAA |
//!
//! ## Behavior guarantee (server node)
//!
//! The server node **always** sends a DNS response:
//! * Non-final fragment → dummy AAAA response (consistent ULA, non-zero TTL)
//! * Final fragment     → data AAAA response (tunnel response packed into AAAA RDATA)
//! * Decode error       → dummy AAAA response
//! The recursive resolver therefore always sees a healthy authoritative server.
//!
//! ## Integration
//!
//! In `src/handler.rs`, **before** the static-store / cache / upstream checks:
//!
//! ```rust,ignore
//! if let Some(resp) = self.tunnel_mask.handle_query(
//!     name, u16::from(qtype), msg.id(), src_addr, raw
//! ).await {
//!     self.metrics.add_bytes_tx(resp.len() as u64);
//!     return Some(resp);
//! }
//! ```
//!
//! In `src/main.rs`:
//!
//! ```rust,ignore
//! let tunnel_mask = Arc::new(TunnelMask::new(cfg.tunnel_mask.clone()));
//! Arc::clone(&tunnel_mask).spawn_eviction_task();
//! ```

pub mod config;
pub mod detector;
pub mod encoder;
pub mod fragmenter;

mod client;
mod server;

use std::net::SocketAddr;
use std::sync::Arc;

use tracing::debug;

pub use config::TunnelMaskConfig;

use client::ClientRelay;
use server::ServerRelay;

// ─────────────────────────────────────────────────────────────────────────────
// Inner state (mode-specific)
// ─────────────────────────────────────────────────────────────────────────────

enum Inner {
    Disabled,
    Client(ClientRelay),
    Server(ServerRelay),
}

// ─────────────────────────────────────────────────────────────────────────────
// Public façade
// ─────────────────────────────────────────────────────────────────────────────

/// The single entry-point for the tunnel masking subsystem.
///
/// All mutable state lives inside `Arc`s; the struct itself is immutable after
/// construction and cheap to share across tasks.
pub struct TunnelMask {
    cfg:   Arc<TunnelMaskConfig>,
    inner: Inner,
}

impl TunnelMask {
    /// Construct a `TunnelMask` from the parsed configuration.
    ///
    /// When `cfg.enabled == false` all calls to `handle_query` return `None`
    /// immediately with zero overhead.
    pub fn new(cfg: TunnelMaskConfig) -> Self {
        use config::NodeMode;

        let cfg = Arc::new(cfg);

        if !cfg.enabled {
            return Self { cfg, inner: Inner::Disabled };
        }

        // Build the encoder that both the client and server nodes use to
        // encode / decode fragment QNAMEs.  The encoder is constructed once
        // here and shared via Arc so no allocation happens on the hot path.
        let enc = encoder::make_encoder(
            &cfg.encoding,
            cfg.label_len,
            cfg.syllable_list_file.as_deref(),
        );

        let inner = match cfg.mode {
            NodeMode::Client => Inner::Client(
                ClientRelay::new(Arc::clone(&cfg), Arc::clone(&enc)),
            ),
            NodeMode::Server => Inner::Server(
                ServerRelay::new(Arc::clone(&cfg), Arc::clone(&enc)),
            ),
        };

        Self { cfg, inner }
    }

    /// Call this at startup to spawn the background session-eviction task.
    ///
    /// Only meaningful for server-mode nodes; no-ops on client / disabled nodes.
    pub fn spawn_eviction_task(self: Arc<Self>) {
        if let Inner::Server(ref relay) = self.inner {
            let sessions = relay.sessions_handle();
            server::spawn_eviction_task(sessions, self.cfg.session_ttl_ms);
        }
    }

    /// Main intercept hook.  Called from `Handler::handle()` **before** any
    /// static-store, cache, or upstream logic.
    ///
    /// Returns:
    ///   * `Some(bytes)` — the caller sends these bytes as the DNS response
    ///                     and stops further processing.
    ///   * `None`        — query was not intercepted; caller continues with
    ///                     the normal VelDNS pipeline (static store → cache →
    ///                     upstream forward).
    ///
    /// On the **server node**, every relay-zone AAAA query always produces
    /// `Some(response)` — a dummy AAAA for non-final fragments and a data
    /// AAAA for the final fragment.  `None` is returned only for queries
    /// that are not AAAA, or whose QNAME does not end with the relay zone.
    pub async fn handle_query(
        &self,
        qname:    &str,
        qtype:    u16,
        dns_id:   u16,
        src_addr: SocketAddr,
        _raw:     &[u8],
    ) -> Option<Vec<u8>> {
        match &self.inner {
            Inner::Disabled => None,

            // ── Client node ───────────────────────────────────────────────
            // Intercept queries that look like tunnel traffic (heuristic +
            // known zone list), fragment them, relay through the configured
            // recursive resolver, and wait for the final AAAA data response.
            Inner::Client(relay) => {
                if !detector::is_tunnel_query(qname, qtype, &self.cfg) {
                    return None;
                }
                debug!(name = qname, qtype, "tunnel_mask client: intercepted tunnel query");
                relay.handle_query(qname, qtype, dns_id, src_addr).await
            }

            // ── Server node ───────────────────────────────────────────────
            // Intercept AAAA queries whose QNAME ends with the relay zone.
            // The server ALWAYS returns a response for these queries.
            Inner::Server(relay) => {
                // Only AAAA (type 28) queries carry fragment data.
                if qtype != 28 {
                    return None;
                }

                let zone = self.cfg.relay_zone.trim_matches('.');
                let q    = qname.trim_end_matches('.');

                // Only relay-zone queries belong to this subsystem.
                if !(q == zone || q.ends_with(&format!(".{}", zone))) {
                    return None;
                }

                // In syllable encoding mode the first label of every fragment
                // QNAME starts with "tm" (the structured metadata label).
                // In hex encoding mode, labels are raw hex — no prefix at all.
                // Apply the prefix guard only in syllable mode; letting it run
                // in hex mode would silently drop every legitimate hex query.
                use config::EncodingMode;
                if matches!(self.cfg.encoding, EncodingMode::Syllable) {
                    // Strip the zone suffix to check the first data label.
                    let data_part = q.strip_suffix(&format!(".{}", zone))
                        .unwrap_or(q);
                    let first_label = data_part.split('.').next().unwrap_or("");
                    if !first_label.starts_with("tm") {
                        return None;
                    }
                }

                // Bug fix (Bug 3): pass `qtype` as the second argument — the
                // previous call was `relay.handle_query(qname, dns_id, src_addr)`
                // which omitted the required `qtype: u16` parameter.
                relay.handle_query(qname, qtype, dns_id, src_addr).await
            }
        }
    }
}
