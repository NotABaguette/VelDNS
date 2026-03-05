//! Server-node relay logic.
//!
//! When VelDNS is configured as `mode = "server"`:
//!
//! * Every AAAA query whose QNAME ends with `relay_zone` is intercepted.
//! * **The server ALWAYS returns a DNS response.  It is never silent.**
//! * Non-final fragments are buffered and immediately answered with a dummy
//!   AAAA response (a consistent ULA address, non-zero TTL) so the recursive
//!   resolver stays satisfied.
//! * When the final fragment arrives the server spin-waits up to 50 ms for any
//!   late-arriving earlier fragments, reassembles the full payload, reconstructs
//!   the original DNS query, forwards it to the real tunnel server
//!   (`upstream_addr`), and returns the response packed into AAAA records.
//!
//! The 50 ms spin-wait yields cooperatively to the Tokio executor (1 ms sleep
//! per iteration) so other query tasks can insert their fragments concurrently.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{rdata::AAAA, DNSClass, Name, RData, Record, RecordType};
use rand::random;
use std::net::Ipv6Addr;
use std::str::FromStr;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, trace, warn};

use crate::tunnel_mask::config::TunnelMaskConfig;
use crate::tunnel_mask::encoder::MaskEncoder;
use crate::tunnel_mask::fragmenter::new_session_id;

// ─────────────────────────────────────────────────────────────────────────────
// Reassembly session
// ─────────────────────────────────────────────────────────────────────────────

struct ReassemblySession {
    /// Per-index slot for each fragment's raw payload bytes.
    fragments:  Vec<Option<Vec<u8>>>,
    /// Total expected fragment count (from the first-received frame header).
    total:      u8,
    /// How many distinct slots have been filled.
    received:   u8,
    /// Original DNS QTYPE, carried from the frame header of any fragment.
    orig_qtype: RecordType,
    /// Wall-clock creation time; used for TTL-based eviction.
    created_at: Instant,
}

impl ReassemblySession {
    fn new(total: u8, orig_qtype: RecordType) -> Self {
        Self {
            fragments:  vec![None; total as usize],
            total,
            received:   0,
            orig_qtype,
            created_at: Instant::now(),
        }
    }

    /// Insert one fragment payload at position `seq`.
    /// Silently ignores out-of-range indices or duplicate inserts.
    fn insert(&mut self, seq: u8, payload: Vec<u8>) {
        let idx = seq as usize;
        if idx >= self.fragments.len() { return; }
        if self.fragments[idx].is_none() {
            self.received += 1;
        }
        self.fragments[idx] = Some(payload);
    }

    fn is_complete(&self) -> bool {
        self.received >= self.total
    }

    fn is_expired(&self, ttl: Duration) -> bool {
        self.created_at.elapsed() > ttl
    }

    /// Concatenate all fragment payloads in order.
    /// Must only be called when `is_complete()` is `true`.
    fn reassemble(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for slot in &self.fragments {
            out.extend_from_slice(
                slot.as_ref().expect("reassemble called on incomplete session"),
            );
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ServerRelay
// ─────────────────────────────────────────────────────────────────────────────

pub struct ServerRelay {
    cfg:      Arc<TunnelMaskConfig>,
    encoder:  Arc<dyn MaskEncoder>,
    sessions: Arc<DashMap<u32, ReassemblySession>>,
}

impl ServerRelay {
    pub fn new(cfg: Arc<TunnelMaskConfig>, encoder: Arc<dyn MaskEncoder>) -> Self {
        Self {
            cfg,
            encoder,
            sessions: Arc::new(DashMap::new()),
        }
    }

    /// Return the session map handle for use in the background eviction task.
    pub fn sessions_handle(&self) -> Arc<DashMap<u32, ReassemblySession>> {
        Arc::clone(&self.sessions)
    }

    /// Handle one incoming AAAA query on the server node.
    ///
    /// **ALWAYS returns `Some(response_bytes)`.  Never returns `None`.**
    ///
    /// The only case where `None` is returned is when the QNAME does not
    /// belong to the relay zone at all — that signals the caller to pass the
    /// query to the normal VelDNS handler.  That check is already done in
    /// `mod.rs` before this function is called, so in practice the function
    /// always produces a response.
    pub async fn handle_query(
        &self,
        qname:    &str,
        _qtype:   u16, // always AAAA by the time we get here; kept for symmetry
        dns_id:   u16,
        _src:     SocketAddr,
    ) -> Option<Vec<u8>> {
        match self.process(qname, dns_id).await {
            Ok(resp) => Some(resp),
            Err(e)   => {
                warn!("tunnel_mask server error (qname={qname}): {e:#}");
                Some(build_servfail(dns_id))
            }
        }
    }

    // ── Core logic ─────────────────────────────────────────────────────────────

    async fn process(&self, qname: &str, dns_id: u16) -> Result<Vec<u8>> {
        let cfg = &self.cfg;

        // ── 1. Decode the fragment frame from the QNAME ───────────────────
        // If decoding fails the QNAME is not a valid tunnel fragment (could be
        // a misconfigured client, a probe, etc.).  Respond with a dummy AAAA
        // so the recursive resolver stays happy — it is authoritative for this
        // zone and must always answer.
        let (header, payload) = match self.encoder.decode(qname, &cfg.relay_zone) {
            Some(v) => v,
            None    => {
                trace!(
                    qname,
                    "tunnel_mask server: QNAME does not decode as a valid fragment; \
                     returning dummy AAAA"
                );
                return Ok(build_dummy_aaaa_response(dns_id, qname, cfg.dummy_ttl));
            }
        };

        if header.frag_total == 0 {
            return Ok(build_dummy_aaaa_response(dns_id, qname, cfg.dummy_ttl));
        }

        let is_final    = header.frag_idx + 1 == header.frag_total;
        let orig_qtype  = RecordType::from(header.qtype as u16);
        let session_id  = header.session_id;

        trace!(
            session  = format!("{:08x}", session_id),
            seq      = header.frag_idx,
            total    = header.frag_total,
            is_final,
            "tunnel_mask server: fragment received"
        );

        // ── 2. Insert into (or create) the reassembly session ─────────────
        {
            let mut session = self.sessions
                .entry(session_id)
                .or_insert_with(|| ReassemblySession::new(header.frag_total, orig_qtype));
            session.insert(header.frag_idx, payload);
        } // release DashMap shard lock

        // ── 3. Non-final fragment → return dummy AAAA ─────────────────────
        // The recursive resolver expects a response to every query.  We send
        // back a consistent ULA address with a non-zero TTL so it looks like a
        // real authoritative server responding to a routine request.
        if !is_final {
            return Ok(build_dummy_aaaa_response(dns_id, qname, cfg.dummy_ttl));
        }

        // ── 4. Final fragment: spin-wait up to 50 ms for stragglers ───────
        // Earlier fragments may have been reordered or slightly delayed.
        // We yield back to the Tokio executor every 1 ms so other query tasks
        // can insert their fragments concurrently (cooperative, not a true spin).
        let spin_deadline = Instant::now() + Duration::from_millis(50);
        loop {
            let complete = self.sessions
                .get(&session_id)
                .map(|s| s.is_complete())
                .unwrap_or(false);
            if complete { break; }
            if Instant::now() >= spin_deadline {
                self.sessions.remove(&session_id);
                warn!(
                    session = format!("{:08x}", session_id),
                    "tunnel_mask server: timed out waiting for all fragments; returning SERVFAIL"
                );
                return Ok(build_servfail(dns_id));
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        // ── 5. Reassemble ─────────────────────────────────────────────────
        let (orig_qtype, reassembled) = {
            let session = self.sessions
                .get(&session_id)
                .ok_or_else(|| anyhow!("session {:08x} vanished during reassembly", session_id))?;
            (session.orig_qtype, session.reassemble())
        };
        self.sessions.remove(&session_id);

        // ── 6. Reconstruct the original DNS query QNAME ───────────────────
        // The reassembled bytes are the QNAME string exactly as the dnstt /
        // slipstream client sent it (e.g. "aaaabbbb.t.tunnel.example.com"),
        // taken as-is including dots.
        let orig_qname = std::str::from_utf8(&reassembled)
            .context("reassembled QNAME contains invalid UTF-8")?;

        debug!(
            session    = format!("{:08x}", session_id),
            orig_qname,
            ?orig_qtype,
            upstream   = %cfg.upstream_addr,
            "tunnel_mask server: reassembly complete, forwarding to tunnel upstream"
        );

        // ── 7. Forward to the real tunnel server with a fresh DNS ID ──────
        let fresh_id: u16 = new_session_id() as u16 ^ random::<u16>();
        let tunnel_resp = self.forward_to_upstream(orig_qname, fresh_id, orig_qtype).await?;

        // ── 8. Encode tunnel response into AAAA records and return ─────────
        let aaaa_response = build_aaaa_data_response(
            dns_id,
            qname,
            &tunnel_resp,
            cfg.response_ttl,
            cfg.max_response_records,
        )
        .context("tunnel_mask server: build AAAA data response")?;

        Ok(aaaa_response)
    }

    // ── Upstream forwarder ─────────────────────────────────────────────────────

    async fn forward_to_upstream(
        &self,
        qname:  &str,
        dns_id: u16,
        qtype:  RecordType,
    ) -> Result<Vec<u8>> {
        let upstream: SocketAddr = self.cfg.upstream_addr
            .parse()
            .with_context(|| format!("invalid upstream_addr '{}'", self.cfg.upstream_addr))?;

        let bind: SocketAddr = if upstream.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };

        let wire = build_forward_query(qname, qtype, dns_id)
            .context("tunnel_mask server: build forward query")?;

        let sock = UdpSocket::bind(bind).await
            .context("tunnel_mask server: bind socket for upstream forward")?;
        sock.send_to(&wire, upstream).await
            .context("tunnel_mask server: send to tunnel upstream")?;

        let mut buf = vec![0u8; 8192];
        let n = timeout(Duration::from_millis(4_000), async {
            let (n, _) = sock.recv_from(&mut buf).await?;
            Ok::<usize, std::io::Error>(n)
        })
        .await
        .map_err(|_| anyhow!("tunnel_mask server: timeout waiting for tunnel upstream"))?
        .context("tunnel_mask server: recv from tunnel upstream")?;

        buf.truncate(n);
        Ok(buf)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Background eviction task
// ─────────────────────────────────────────────────────────────────────────────

/// Spawn a Tokio task that evicts expired reassembly sessions once per second.
pub fn spawn_eviction_task(
    sessions: Arc<DashMap<u32, ReassemblySession>>,
    ttl_ms:   u64,
) {
    let ttl = Duration::from_millis(ttl_ms);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            let before  = sessions.len();
            sessions.retain(|_, s| !s.is_expired(ttl));
            let evicted = before.saturating_sub(sessions.len());
            if evicted > 0 {
                trace!("tunnel_mask server: evicted {evicted} expired session(s)");
            }
        }
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// DNS message builders
// ─────────────────────────────────────────────────────────────────────────────

/// Build the DNS query to forward to the real tunnel server.
///
/// Uses a caller-supplied `id` (fresh random ID generated per reassembly).
fn build_forward_query(qname: &str, qtype: RecordType, id: u16) -> Result<Vec<u8>> {
    let mut msg = Message::new();
    msg.set_id(id);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);

    let name = Name::from_str(&ensure_fqdn(qname))
        .with_context(|| format!("invalid forward QNAME '{qname}'"))?;
    let mut q = hickory_proto::op::Query::new();
    q.set_name(name);
    q.set_query_type(qtype);
    q.set_query_class(DNSClass::IN);
    msg.add_query(q);

    let mut edns = Edns::new();
    edns.set_max_payload(4096);
    msg.set_edns(edns);

    msg.to_vec().context("serialize forward query")
}

/// Build a dummy AAAA response for a non-final fragment.
///
/// Returns a consistent ULA address (`fd09:b7e2:4a31::1`) with the configured
/// non-zero TTL.  Sets AA=1 since this node is authoritative for the relay zone.
fn build_dummy_aaaa_response(dns_id: u16, qname: &str, ttl: u32) -> Vec<u8> {
    // Consistent ULA address: fd09:b7e2:4a31::1
    // Looks like an internal CDN backend or anycast endpoint.
    const DUMMY_IP: &str = "fd09:b7e2:4a31::1";
    let dummy_ip: Ipv6Addr = DUMMY_IP.parse().expect("static literal is valid");

    let mut msg = Message::new();
    msg.set_id(dns_id);
    msg.set_message_type(MessageType::Response);
    msg.set_op_code(OpCode::Query);
    msg.set_authoritative(true);
    msg.set_recursion_available(false);
    msg.set_response_code(ResponseCode::NoError);

    // Mirror the question section back (best practice for compliant responses).
    if let Ok(name) = Name::from_str(&ensure_fqdn(qname)) {
        let mut q = hickory_proto::op::Query::new();
        q.set_name(name.clone());
        q.set_query_type(RecordType::AAAA);
        q.set_query_class(DNSClass::IN);
        msg.add_query(q);

        let mut rec = Record::new();
        rec.set_name(name)
           .set_ttl(ttl)
           .set_dns_class(DNSClass::IN)
           .set_rr_type(RecordType::AAAA)
           .set_data(Some(RData::AAAA(AAAA(dummy_ip))));
        msg.add_answer(rec);
    }

    msg.to_vec().unwrap_or_default()
}

/// Build the final AAAA data response containing the encoded tunnel response.
///
/// Payload layout packed into AAAA RDATA (16 bytes each):
/// ```text
/// bytes 0–1   : big-endian u16  = len(tunnel_resp)
/// bytes 2+    : tunnel_resp bytes
/// remainder   : zero padding to fill the last 16-byte chunk
/// ```
///
/// Capped at `max_records` AAAA records.  If the tunnel response doesn't fit,
/// the length field is updated to reflect the truncated data length; the tunnel
/// protocol's reliability layer (KCP / QUIC) handles retransmission of the rest.
fn build_aaaa_data_response(
    dns_id:      u16,
    qname:       &str,
    tunnel_resp: &[u8],
    response_ttl: u32,
    max_records:  usize,
) -> Result<Vec<u8>> {
    // Prepend 2-byte big-endian length.
    let full_len = u16::try_from(tunnel_resp.len())
        .map_err(|_| anyhow!("tunnel response too large ({} bytes)", tunnel_resp.len()))?;

    let mut payload = Vec::with_capacity(2 + tunnel_resp.len() + 15);
    payload.extend_from_slice(&full_len.to_be_bytes());
    payload.extend_from_slice(tunnel_resp);

    // Pad to a multiple of 16 bytes.
    let rem = payload.len() % 16;
    if rem != 0 {
        payload.extend(std::iter::repeat(0u8).take(16 - rem));
    }

    // Cap at max_records × 16 bytes.
    let max_bytes = max_records * 16;
    if payload.len() > max_bytes {
        payload.truncate(max_bytes);
        // Update the length field to the truncated data byte count.
        let truncated_data_len = (max_bytes.saturating_sub(2)) as u16;
        let lb = truncated_data_len.to_be_bytes();
        payload[0] = lb[0];
        payload[1] = lb[1];
    }

    // Build the DNS response.
    let mut msg = Message::new();
    msg.set_id(dns_id);
    msg.set_message_type(MessageType::Response);
    msg.set_op_code(OpCode::Query);
    msg.set_authoritative(true);
    msg.set_recursion_available(false);
    msg.set_response_code(ResponseCode::NoError);

    let name = Name::from_str(&ensure_fqdn(qname))
        .with_context(|| format!("invalid QNAME in AAAA data response '{qname}'"))?;

    // Echo the question section.
    let mut q = hickory_proto::op::Query::new();
    q.set_name(name.clone());
    q.set_query_type(RecordType::AAAA);
    q.set_query_class(DNSClass::IN);
    msg.add_query(q);

    // One AAAA answer record per 16-byte chunk.
    for chunk in payload.chunks_exact(16) {
        let ip_bytes: [u8; 16] = chunk.try_into().expect("chunk is always 16 bytes");
        let ip = Ipv6Addr::from(ip_bytes);
        let mut rec = Record::new();
        rec.set_name(name.clone())
           .set_ttl(response_ttl)
           .set_dns_class(DNSClass::IN)
           .set_rr_type(RecordType::AAAA)
           .set_data(Some(RData::AAAA(AAAA(ip))));
        msg.add_answer(rec);
    }

    msg.to_vec().context("serialize AAAA data response")
}

/// Minimal SERVFAIL response for error conditions.
fn build_servfail(dns_id: u16) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(dns_id);
    msg.set_message_type(MessageType::Response);
    msg.set_authoritative(true);
    msg.set_response_code(ResponseCode::ServFail);
    msg.to_vec().unwrap_or_default()
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility
// ─────────────────────────────────────────────────────────────────────────────

fn ensure_fqdn(s: &str) -> String {
    if s.ends_with('.') { s.to_string() } else { format!("{s}.") }
}
