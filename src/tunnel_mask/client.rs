//! Client-side relay: detect tunnel queries, fragment, send masked queries
//! through the recursive resolver, wait for final response, reconstruct.

use super::config::TunnelMaskConfig;
use super::detector::{self, DetectorConfig};
use super::encoder::MaskEncoder;
use super::fragmenter;
use hickory_proto::op::Message;
use hickory_proto::rr::{RData, RecordType};
use rand::{random, Rng};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tracing::{debug, trace, warn};

pub struct ClientRelay {
    cfg: TunnelMaskConfig,
    detector_cfg: DetectorConfig,
    encoder: Box<dyn MaskEncoder>,
}

impl ClientRelay {
    pub fn new(cfg: TunnelMaskConfig, encoder: Box<dyn MaskEncoder>) -> Self {
        let detector_cfg = DetectorConfig::from(&cfg);
        Self {
            cfg,
            detector_cfg,
            encoder,
        }
    }

    /// Returns `Some(response_bytes)` if the query was intercepted and
    /// relayed, `None` if it should be handled normally.
    pub async fn handle_query(
        &self,
        qname: &str,
        qtype: u16,
        dns_id: u16,
        raw_query: &[u8],
    ) -> Option<Vec<u8>> {
        // ── 1. Is this a tunnel query? ───────────────────────────────
        if !detector::is_tunnel_query(qname, qtype, &self.detector_cfg) {
            return None;
        }
        debug!(
            "tunnel_mask client: intercepting query name={} qtype={} dns_id={} ({} bytes)",
            qname,
            qtype,
            dns_id,
            raw_query.len()
        );
        trace!(
            "tunnel_mask client: original query bytes={}",
            bytes_preview(raw_query, 96)
        );

        // ── 2. Fragment the entire raw DNS query ─────────────────────
        let session_id: u32 = random();
        let capacity = self
            .encoder
            .payload_capacity(self.cfg.max_qname_len, &self.cfg.relay_zone);
        if capacity == 0 {
            warn!("tunnel_mask client: payload capacity is 0 — check max_qname_len / relay_zone");
            return None;
        }

        let fragments = fragmenter::fragment(session_id, qtype as u8, raw_query, capacity);
        debug!(
            "tunnel_mask client: session {session_id:#010x}, {} fragment(s), cap={capacity}",
            fragments.len()
        );

        // ── 3. Pick a resolver address ───────────────────────────────
        let resolver_str = self.cfg.resolver.first()?;
        let resolver_addr: SocketAddr = match resolver_str.parse() {
            Ok(a) => a,
            Err(e) => {
                warn!("tunnel_mask client: bad resolver addr: {e}");
                return None;
            }
        };

        // ── 4. Open a socket ─────────────────────────────────────────
        let bind: SocketAddr = if resolver_addr.is_ipv4() {
            ([0u8; 4], 0u16).into()
        } else {
            ([0u16; 8], 0u16).into()
        };
        let sock = match UdpSocket::bind(bind).await {
            Ok(s) => s,
            Err(e) => {
                warn!("tunnel_mask client: bind: {e}");
                return None;
            }
        };

        debug!(
            "tunnel_mask client: resolver={} local_bind={}",
            resolver_addr, bind
        );

        // ── 5. Send all fragment queries ─────────────────────────────
        let mut final_txid: u16 = 0;

        for frag in &fragments {
            let frame = frag.to_frame();
            let masked_qname = self.encoder.encode_qname(&frame, &self.cfg.relay_zone);
            let txid: u16 = random();
            let query_pkt = build_aaaa_query(txid, &masked_qname);

            debug!(
                "tunnel_mask client: frag {}/{} session={:#010x} nonce={:#06x} txid={:#06x} masked_qname={}",
                frag.seq + 1,
                frag.total,
                frag.session_id,
                frag.nonce,
                txid,
                masked_qname
            );
            trace!(
                "tunnel_mask client: frag payload={} frame={} wire_query={}",
                bytes_preview(&frag.payload, 64),
                bytes_preview(&frame, 96),
                bytes_preview(&query_pkt, 96)
            );

            if let Err(e) = sock.send_to(&query_pkt, resolver_addr).await {
                warn!("tunnel_mask client: send: {e}");
                return None;
            }

            if frag.is_final {
                final_txid = txid;
            } else {
                // Jitter between non-final fragments
                let [lo, hi] = self.cfg.send_jitter_ms;
                if hi > 0 && hi >= lo {
                    let jitter = rand::thread_rng().gen_range(lo..=hi);
                    tokio::time::sleep(Duration::from_millis(jitter)).await;
                }
            }
        }

        // ── 6. Wait for the final response (match by txid) ──────────
        let deadline = Instant::now() + Duration::from_millis(self.cfg.session_ttl_ms);
        let mut buf = vec![0u8; 4096];

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                warn!("tunnel_mask client: timeout waiting for final response");
                return None;
            }

            match tokio::time::timeout(remaining, sock.recv_from(&mut buf)).await {
                Ok(Ok((len, _))) if len >= 2 => {
                    let resp_id = u16::from_be_bytes([buf[0], buf[1]]);
                    trace!(
                        "tunnel_mask client: recv id={:#06x} len={} final_txid={:#06x} bytes={}",
                        resp_id,
                        len,
                        final_txid,
                        bytes_preview(&buf[..len], 96)
                    );
                    if resp_id == final_txid {
                        let out = extract_tunnel_response(&buf[..len]);
                        if let Some(ref bytes) = out {
                            debug!(
                                "tunnel_mask client: final response decoded len={} preview={}",
                                bytes.len(),
                                bytes_preview(bytes, 96)
                            );
                        } else {
                            warn!("tunnel_mask client: final response could not be decoded");
                        }
                        return out;
                    }
                    // Dummy response to a non-final fragment → discard.
                    trace!(
                        "tunnel_mask client: discarded non-final response id={:#06x}",
                        resp_id
                    );
                }
                Ok(Ok(_)) => {} // too short, ignore
                Ok(Err(e)) => {
                    warn!("tunnel_mask client: recv: {e}");
                    return None;
                }
                Err(_) => {
                    warn!("tunnel_mask client: timeout");
                    return None;
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DNS wire helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build a minimal DNS query (wire format) for `qname` with QTYPE=AAAA
/// and an EDNS(0) OPT record requesting a 4096-byte UDP payload.
fn build_aaaa_query(id: u16, qname: &str) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(128);

    // ── Header (12 bytes) ────────────────────────────────────────────
    pkt.extend_from_slice(&id.to_be_bytes()); // ID
    pkt.extend_from_slice(&[0x01, 0x00]); // Flags: RD=1
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    pkt.extend_from_slice(&1u16.to_be_bytes()); // ARCOUNT = 1 (OPT)

    // ── Question ─────────────────────────────────────────────────────
    for label in qname.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0); // root label
    pkt.extend_from_slice(&28u16.to_be_bytes()); // QTYPE  = AAAA
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN

    // ── Additional: OPT record ───────────────────────────────────────
    pkt.push(0); // NAME = root
    pkt.extend_from_slice(&41u16.to_be_bytes()); // TYPE = OPT
    pkt.extend_from_slice(&4096u16.to_be_bytes()); // UDP payload size
    pkt.extend_from_slice(&0u32.to_be_bytes()); // Extended RCODE + flags
    pkt.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH = 0

    pkt
}

/// Parse a DNS response (wire bytes) and extract the tunnel response
/// hidden in the AAAA answer records.
///
/// Layout: `[u16 big-endian length L] [L bytes of tunnel response] [zero pad]`
fn extract_tunnel_response(response: &[u8]) -> Option<Vec<u8>> {
    let msg = Message::from_vec(response).ok()?;
    trace!(
        "tunnel_mask client: parsing final dns msg answers={}",
        msg.answers().len()
    );

    let mut aaaa_bytes: Vec<u8> = Vec::new();
    for answer in msg.answers() {
        if answer.record_type() == RecordType::AAAA {
            if let Some(RData::AAAA(aaaa)) = answer.data() {
                aaaa_bytes.extend_from_slice(&aaaa.0.octets());
                trace!(
                    "tunnel_mask client: AAAA chunk={}",
                    bytes_preview(&aaaa.0.octets(), 32)
                );
            }
        }
    }

    if aaaa_bytes.len() < 2 {
        return None;
    }

    let total_len = u16::from_be_bytes([aaaa_bytes[0], aaaa_bytes[1]]) as usize;
    if total_len == 0 || aaaa_bytes.len() < 2 + total_len {
        return None;
    }

    Some(aaaa_bytes[2..2 + total_len].to_vec())
}

fn bytes_preview(data: &[u8], max: usize) -> String {
    let take = data.len().min(max);
    let mut out = String::new();
    for (i, b) in data.iter().take(take).enumerate() {
        if i > 0 {
            out.push(' ');
        }
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{:02x}", b);
    }
    if data.len() > max {
        out.push_str(" ...");
    }
    out
}
