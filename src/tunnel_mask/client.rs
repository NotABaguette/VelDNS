//! Client-node relay logic.
//!
//! When VelDNS is configured as `mode = "client"`:
//!
//! 1. The detector flags an incoming query as a tunnel query.
//! 2. The QNAME string (as-is, including dots) is used as the raw payload.
//! 3. The payload is fragmented into N `FragmentEnvelope`s.
//! 4. For each fragment a binary frame (10-byte header + payload) is built,
//!    encoded into a masked AAAA query QNAME, and sent to the **upstream
//!    recursive resolver** (NOT directly to the server node).
//! 5. Non-final fragments are sent **concurrently**: each is dispatched as an
//!    independent Tokio task that sleeps its own random jitter delay, then
//!    sends.  All jitter sleeps happen in parallel so total elapsed time is
//!    ≈ max(jitter) rather than sum(jitter × N).
//! 6. After all non-final fragments have been sent, the final fragment is sent.
//!    The client then enters a receive loop, matching responses by the final
//!    fragment's DNS transaction ID.  Dummy responses from non-final fragments
//!    arrive and are discarded.
//! 7. When the final response is received its AAAA records are decoded back to
//!    the original tunnel DNS response bytes.  The DNS transaction ID is patched
//!    to match the original client query before the bytes are returned.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use hickory_proto::op::{Edns, Message, MessageType, OpCode};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use rand::Rng;
use std::str::FromStr;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, trace, warn};

use crate::tunnel_mask::config::TunnelMaskConfig;
use crate::tunnel_mask::encoder::{FrameHeader, MaskEncoder};
use crate::tunnel_mask::fragmenter::{self, FragmentEnvelope};

// ─────────────────────────────────────────────────────────────────────────────
// ClientRelay
// ─────────────────────────────────────────────────────────────────────────────

pub struct ClientRelay {
    cfg:     Arc<TunnelMaskConfig>,
    encoder: Arc<dyn MaskEncoder>,
}

impl ClientRelay {
    pub fn new(cfg: Arc<TunnelMaskConfig>, encoder: Arc<dyn MaskEncoder>) -> Self {
        Self { cfg, encoder }
    }

    /// Intercept a tunnel query, relay it through the recursive resolver, and
    /// return the decoded tunnel response wire bytes.
    ///
    /// The returned bytes have their DNS transaction ID patched to `original_id`
    /// so that the dnstt / slipstream client accepts the response.
    ///
    /// Returns `None` on timeout or unrecoverable error; the caller should send
    /// SERVFAIL in that case.
    pub async fn handle_query(
        &self,
        qname:       &str,
        qtype:       u16,
        original_id: u16,
        _src_addr:   SocketAddr,
    ) -> Option<Vec<u8>> {
        match self.relay(qname, qtype, original_id).await {
            Ok(resp) => Some(resp),
            Err(e)   => {
                warn!("tunnel_mask client relay failed for qname={qname}: {e:#}");
                None
            }
        }
    }

    // ── Private relay logic ───────────────────────────────────────────────────

    async fn relay(&self, qname: &str, qtype: u16, original_id: u16) -> Result<Vec<u8>> {
        let cfg = &self.cfg;

        // ── 1. Build payload: QNAME bytes as-is (including dots) ──────────
        // Per spec: "treat remainder as raw payload string bytes" including dots.
        let payload = qname.as_bytes().to_vec();

        // ── 2. Fragment ───────────────────────────────────────────────────
        let capacity = self.encoder.payload_capacity(cfg.max_qname_len, &cfg.relay_zone);
        let fragments = fragmenter::fragment(qtype as u8, &payload, capacity);
        let total     = fragments.len();

        trace!(
            qname,
            fragments = total,
            capacity,
            "tunnel_mask client: fragmenting query"
        );

        // ── 3. Bind one ephemeral UDP socket for the whole session ─────────
        // Pick a resolver from the configured list (round-robin).
        let resolver = pick_resolver(&cfg.resolver)
            .context("tunnel_mask client: no resolver configured")?;

        let bind_addr: SocketAddr = if resolver.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        // Wrap in Arc so it can be shared across concurrent send tasks.
        let sock = Arc::new(UdpSocket::bind(bind_addr).await
            .context("tunnel_mask client: bind ephemeral socket")?);

        // ── 4. Assign a DNS transaction ID to each fragment query ──────────
        // We record the final fragment's ID so we can match the response.
        let txids: Vec<u16> = (0..total).map(|_| next_query_id()).collect();
        let final_txid = txids[total - 1];

        debug!(
            session   = format!("{:08x}", fragments[0].session_id),
            fragments = total,
            ?resolver,
            final_txid,
            "tunnel_mask client: sending fragments"
        );

        // ── 5. Send non-final fragments CONCURRENTLY with per-task jitter ──
        //
        // BUG FIX: the original code did:
        //   send frag[i] → sleep(jitter) → send frag[i+1] → sleep → ...
        // Each fragment waited for the previous one's jitter sleep AND for the
        // resolver's round-trip (~1 s each).  With 7 non-final frags that put
        // frag 7 (the final) ~7 s after frag 0 — well past session_ttl_ms=5000.
        //
        // Fix: pre-build every wire packet, then spawn one task per non-final
        // fragment.  Each task sleeps its own independent random jitter and
        // sends.  All tasks are in flight simultaneously; the final fragment is
        // sent only after all spawned tasks have at least been *dispatched*
        // (join_all ensures they've completed their sends before we enter the
        // receive loop, but crucially they sleep concurrently, not serially).
        let mut send_handles = Vec::with_capacity(total.saturating_sub(1));

        for i in 0..total.saturating_sub(1) {
            let qname_frag = self.build_qname(&fragments[i]);
            let wire = match build_dns_query(&qname_frag, RecordType::AAAA, txids[i]) {
                Ok(w)  => w,
                Err(e) => { warn!(seq = i, "tunnel_mask client: build query: {e}"); continue; }
            };

            let sock_clone  = Arc::clone(&sock);
            let jitter_min  = cfg.send_jitter_ms[0];
            let jitter_max  = cfg.send_jitter_ms[1];
            let seq         = i;

            send_handles.push(tokio::spawn(async move {
                // Each fragment sleeps its own independent jitter — they all
                // sleep concurrently, so total elapsed ≈ max(jitter) not sum.
                let jitter = random_jitter_ms(jitter_min, jitter_max);
                tokio::time::sleep(Duration::from_millis(jitter)).await;
                if let Err(e) = sock_clone.send_to(&wire, resolver).await {
                    warn!(seq, "tunnel_mask client: send failed: {e}");
                }
            }));
        }

        // Wait for all non-final fragments to be sent before sending the final.
        // This preserves the spec requirement that the final fragment arrives
        // last at the server (so the server's spin-wait finds all earlier frags
        // already in the reassembly session).
        futures::future::join_all(send_handles).await;

        // ── 6. Send the final fragment ─────────────────────────────────────
        let qname_final = self.build_qname(&fragments[total - 1]);
        let final_wire  = build_dns_query(&qname_final, RecordType::AAAA, final_txid)
            .context("tunnel_mask client: build final query")?;
        sock.send_to(&final_wire, resolver).await
            .context("tunnel_mask client: send final fragment")?;

        trace!(
            session   = format!("{:08x}", fragments[0].session_id),
            final_txid,
            "tunnel_mask client: final fragment sent, entering response wait loop"
        );

        // ── 7. Wait loop: receive until final_txid response arrives ────────
        // The server responds to EVERY fragment (dummy AAAA for non-final,
        // data AAAA for final).  We discard all responses whose DNS transaction
        // ID does not match `final_txid`.
        let deadline  = Instant::now() + Duration::from_millis(cfg.session_ttl_ms);
        let mut recv_buf = vec![0u8; 8192];

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(anyhow!(
                    "tunnel_mask client: timeout waiting for final response \
                     (session={:08x}, final_txid={final_txid})",
                    fragments[0].session_id
                ));
            }

            let n = match timeout(remaining, sock.recv(&mut recv_buf)).await {
                Ok(Ok(n))  => n,
                Ok(Err(e)) => return Err(anyhow!("tunnel_mask client: recv error: {e}")),
                Err(_)     => return Err(anyhow!(
                    "tunnel_mask client: timeout (session={:08x})",
                    fragments[0].session_id
                )),
            };

            let resp = &recv_buf[..n];

            // Parse the DNS response header to extract the transaction ID.
            // If parsing fails (malformed packet), just discard and keep waiting.
            let dns_id = match Message::from_vec(resp) {
                Ok(msg) => msg.id(),
                Err(_)  => {
                    trace!("tunnel_mask client: received malformed DNS packet, discarding");
                    continue;
                }
            };

            if dns_id != final_txid {
                // Dummy response to one of the non-final fragments — discard.
                trace!(
                    received_id = dns_id,
                    final_txid,
                    "tunnel_mask client: discarding non-final response"
                );
                continue;
            }

            // ── 8. Decode the AAAA records back to tunnel response bytes ───
            let mut decoded = decode_aaaa_response(resp)
                .context("tunnel_mask client: decode final AAAA response")?;

            // Patch the DNS transaction ID to match the original client query
            // so the dnstt / slipstream client accepts the response.
            if decoded.len() >= 2 {
                let id_be = original_id.to_be_bytes();
                decoded[0] = id_be[0];
                decoded[1] = id_be[1];
            }

            debug!(
                session   = format!("{:08x}", fragments[0].session_id),
                resp_len  = decoded.len(),
                "tunnel_mask client: relay complete"
            );

            return Ok(decoded);
        }
    }

    // ── QNAME construction ────────────────────────────────────────────────────

    /// Build the full masked QNAME for one fragment using the configured encoder.
    fn build_qname(&self, frag: &FragmentEnvelope) -> String {
        let frame = build_frame(frag);
        self.encoder.encode(&frame, &self.cfg.relay_zone)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Frame builder
// ─────────────────────────────────────────────────────────────────────────────

/// Assemble the binary frame (10-byte header + payload) for one fragment.
///
/// Frame layout:
/// ```text
/// [session_id: 4B][nonce: 2B][frag_idx: 1B][frag_total: 1B][qtype: 1B][reserved: 1B][payload]
/// ```
fn build_frame(frag: &FragmentEnvelope) -> Vec<u8> {
    let hdr = FrameHeader {
        session_id: frag.session_id,
        nonce:      frag.nonce,
        frag_idx:   frag.seq,
        frag_total: frag.total,
        qtype:      frag.qtype,
        reserved:   0,
    };
    let mut frame = hdr.to_bytes().to_vec();
    frame.extend_from_slice(&frag.payload);
    frame
}

// ─────────────────────────────────────────────────────────────────────────────
// DNS query builder
// ─────────────────────────────────────────────────────────────────────────────

/// Build a raw DNS AAAA query wire message with EDNS(0).
fn build_dns_query(qname: &str, qtype: RecordType, id: u16) -> Result<Vec<u8>> {
    let mut msg = Message::new();
    msg.set_id(id);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);

    let name = Name::from_str(&ensure_fqdn(qname))
        .with_context(|| format!("tunnel_mask client: invalid QNAME '{qname}'"))?;
    let mut q = hickory_proto::op::Query::new();
    q.set_name(name);
    q.set_query_type(qtype);
    q.set_query_class(DNSClass::IN);
    msg.add_query(q);

    // EDNS(0) OPT record with 4096-byte payload size.
    let mut edns = Edns::new();
    edns.set_max_payload(4096);
    edns.set_dnssec_ok(false);
    msg.set_edns(edns);

    msg.to_vec().context("tunnel_mask client: serialize DNS query")
}

// ─────────────────────────────────────────────────────────────────────────────
// AAAA response decoder
// ─────────────────────────────────────────────────────────────────────────────

/// Extract the original tunnel response bytes from an AAAA data response.
///
/// Payload layout in the AAAA RDATA:
/// ```text
/// bytes 0–1   : big-endian u16 = length L of original tunnel response
/// bytes 2..2+L: original DNS tunnel response wire bytes
/// bytes 2+L.. : zero padding (ignored)
/// ```
fn decode_aaaa_response(raw: &[u8]) -> Result<Vec<u8>> {
    let msg = Message::from_vec(raw)
        .context("tunnel_mask client: parse AAAA response")?;

    // Concatenate 16-byte RDATA from all AAAA answer records in order.
    let mut payload: Vec<u8> = Vec::new();
    for record in msg.answers() {
        if record.record_type() != RecordType::AAAA { continue; }
        if let Some(RData::AAAA(addr)) = record.data() {
            payload.extend_from_slice(&addr.0.octets());
        }
    }

    if payload.len() < 2 {
        return Err(anyhow!(
            "tunnel_mask client: AAAA response has no payload ({} answer records)",
            msg.answers().len()
        ));
    }

    let length = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    if payload.len() < 2 + length {
        return Err(anyhow!(
            "tunnel_mask client: AAAA response payload too short \
             (have {} bytes after length prefix, need {length})",
            payload.len() - 2
        ));
    }

    Ok(payload[2..2 + length].to_vec())
}

// ─────────────────────────────────────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────────────────────────────────────

/// Atomic counter for unique per-query DNS transaction IDs.
static QUERY_ID_COUNTER: AtomicU32 = AtomicU32::new(1);

fn next_query_id() -> u16 {
    QUERY_ID_COUNTER
        .fetch_add(1, Ordering::Relaxed) as u16
}

/// Round-robin across the configured resolver list.
static RESOLVER_COUNTER: AtomicU32 = AtomicU32::new(0);

fn pick_resolver(resolvers: &[String]) -> Result<SocketAddr> {
    if resolvers.is_empty() {
        return Err(anyhow!("tunnel_mask: resolver list is empty"));
    }
    let idx = RESOLVER_COUNTER.fetch_add(1, Ordering::Relaxed) as usize % resolvers.len();
    resolvers[idx]
        .parse::<SocketAddr>()
        .map_err(|e| anyhow!("tunnel_mask: invalid resolver '{}': {e}", resolvers[idx]))
}

/// Return a random duration in `[min_ms, max_ms]`.
fn random_jitter_ms(min_ms: u64, max_ms: u64) -> u64 {
    if min_ms >= max_ms { return min_ms; }
    rand::thread_rng().gen_range(min_ms..=max_ms)
}

fn ensure_fqdn(s: &str) -> String {
    if s.ends_with('.') { s.to_string() } else { format!("{s}.") }
}
