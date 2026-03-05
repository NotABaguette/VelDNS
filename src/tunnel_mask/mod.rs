//! # Tunnel Mask
//!
//! Disguises dnstt / slipstream DNS tunnel queries by re-encoding them as
//! multiple innocent-looking AAAA queries for a cover (relay) domain.
//!
//! Two roles:
//!
//! - **Client node** – intercepts tunnel queries, fragments them, sends the
//!   fragments as hex-labelled AAAA queries through the upstream recursive
//!   resolver, waits for the final response, reconstructs the tunnel response.
//!
//! - **Server node** – authoritative NS for the relay zone; reassembles
//!   fragments, forwards the original query to the real tunnel server, packs
//!   the tunnel response into AAAA records.

mod client;
pub mod config;
mod detector;
mod encoder;
mod fragmenter;
mod server;

pub use config::TunnelMaskConfig;

use config::NodeMode;
use encoder::HexEncoder;
use std::sync::Arc;
use tracing::{info, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Public facade
// ─────────────────────────────────────────────────────────────────────────────

pub struct TunnelMask {
    inner: MaskInner,
}

enum MaskInner {
    Disabled,
    Client(client::ClientRelay),
    Server(server::ServerRelay),
}

impl TunnelMask {
    /// Build a `TunnelMask` from configuration.
    pub fn new(cfg: &TunnelMaskConfig) -> Self {
        if !cfg.enabled {
            return Self {
                inner: MaskInner::Disabled,
            };
        }

        // Select encoder (hex is default; syllable is a TODO placeholder)
        let encoder: Box<dyn encoder::MaskEncoder> = match cfg.encoding.as_str() {
            "syllable" => {
                warn!("tunnel_mask: syllable encoding is not yet implemented – using hex");
                Box::new(HexEncoder {
                    label_len: cfg.label_len,
                })
            }
            _ => Box::new(HexEncoder {
                label_len: cfg.label_len,
            }),
        };

        match cfg.node_mode() {
            NodeMode::Client => {
                info!(
                    "tunnel_mask: CLIENT mode – relay_zone={}, resolver={:?}",
                    cfg.relay_zone, cfg.resolver,
                );
                Self {
                    inner: MaskInner::Client(client::ClientRelay::new(cfg.clone(), encoder)),
                }
            }
            NodeMode::Server => {
                info!(
                    "tunnel_mask: SERVER mode – relay_zone={}, upstream={}",
                    cfg.relay_zone, cfg.upstream_addr,
                );
                Self {
                    inner: MaskInner::Server(server::ServerRelay::new(cfg.clone(), encoder)),
                }
            }
        }
    }

    /// Intercept a DNS query.
    ///
    /// Returns `Some(response_bytes)` if the query was handled by the tunnel
    /// mask (either relayed on the client or answered on the server).
    /// Returns `None` to let the normal VelDNS handler process the query.
    pub async fn handle_query(
        &self,
        qname: &str,
        qtype: u16,
        dns_id: u16,
        raw_query: &[u8],
    ) -> Option<Vec<u8>> {
        match &self.inner {
            MaskInner::Disabled => None,
            MaskInner::Client(c) => c.handle_query(qname, qtype, dns_id, raw_query).await,
            MaskInner::Server(s) => s.handle_query(qname, qtype, dns_id, raw_query).await,
        }
    }

    /// Spawn background session-eviction task (server mode only).
    /// Call once at startup.  No-op in client / disabled mode.
    pub fn spawn_eviction_task(self: &Arc<Self>) {
        if let MaskInner::Server(ref s) = self.inner {
            s.spawn_eviction_task();
        }
    }
}
