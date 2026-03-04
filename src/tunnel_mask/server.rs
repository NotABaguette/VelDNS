//! Server-side relay: receive masked AAAA queries, buffer fragments,
//! reassemble, forward to real tunnel server, return response as AAAA records.

use super::config::TunnelMaskConfig;
use super::encoder::{self, MaskEncoder};
use dashmap::DashMap;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};
use hickory_proto::rr::rdata::AAAA;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tracing::{debug, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Reassembly session
// ─────────────────────────────────────────────────────────────────────────────

pub struct ReassemblySession {
    fragments:      Vec<Option<Vec<u8>>>,
    total:          u8,
    received_count: u8,
    pub(crate) created_at: Instant,
}

impl ReassemblySession {
    fn new(total: u8) -> Self {
        Self {
            fragments:      vec![None; total as usize],
            total,
            received_count: 0,
            created_at:     Instant::now(),
        }
    }

    fn is_complete(&self) -> bool {
        self.received_count >= self.total
    }

    /// Concatenate all fragments in order.  Returns `None` if any is missing.
    fn assemble(&self) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        for frag in &self.fragments {
            out.extend_from_slice(frag.as_ref()?);
        }
        Some(out)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Server relay
// ─────────────────────────────────────────────────────────────────────────────

pub struct ServerRelay {
    pub(crate) cfg:      TunnelMaskConfig,
    encoder:             Box<dyn MaskEncoder>,
    pub(crate) sessions: Arc<DashMap<u32, ReassemblySession>>,
}

impl ServerRelay {
    pub fn new(cfg: TunnelMaskConfig, encoder: Box<dyn MaskEncoder>) -> Self {
        Self {
            cfg,
            encoder,
            sessions: Arc::new(DashMap::new()),
        }
    }

    /// Returns `Some(response_bytes)` for any query matching the relay zone.
    /// All queries are answered — non-final fragments get a dummy AAAA,
    /// final fragments get the real tunnel response packed into AAAA records.
    pub async fn handle_query(
        &self,
        qname: &str,
        _qtype: u16,
        _dns_id: u16,
        raw_query: &[u8],
    ) -> Option<Vec<u8>> {
        // ── 1. Does the query target our relay zone? ─────────────────
        let rz = self.cfg.relay_zone.to_lowercase();
        let q  = qname.to_lowercase();
        if !q.ends_with(&format!(".{rz}")) && q != rz {
            return None;
        }

        // ── 2. Decode the hex frame ──────────────────────────────────
        let frame_bytes = match self.encoder.decode_qname(&q, &rz) {
            Some(b) => b,
            None => {
                debug!("tunnel_mask server: decode failed for {q}");
                return self.build_dummy_response(raw_query);
            }
        };

        if frame_bytes.len() < encoder::HEADER_LEN {
            return self.build_dummy_response(raw_query);
        }

        let header = match encoder::FrameHeader::decode(&frame_bytes) {
            Some(h) => h,
            None    => return self.build_dummy_response(raw_query),
        };
        let payload = frame_bytes[encoder::HEADER_LEN..].to_vec();

        let sid      = header.session_id;
        let idx      = header.frag_idx as usize;
        let total    = header.frag_total;
        let is_final = header.is_final();

        debug!(
            "tunnel_mask server: session {sid:#010x} frag {}/{total} ({} B){}",
            header.frag_idx + 1,
            payload.len(),
            if is_final { " [FINAL]" } else { "" },
        );

        // ── 3. Insert fragment ───────────────────────────────────────
        {
            let mut entry = self.sessions
                .entry(sid)
                .or_insert_with(|| ReassemblySession::new(total));
            if idx < entry.fragments.len() && entry.fragments[idx].is_none() {
                entry.fragments[idx] = Some(payload);
                entry.received_count += 1;
            }
        }

        // ── 4. Non-final → dummy response ────────────────────────────
        if !is_final {
            return self.build_dummy_response(raw_query);
        }

        // ── 5. Final → wait for completion, then reassemble ──────────
        let deadline = Instant::now() + Duration::from_millis(50);
        loop {
            let complete = self.sessions
                .get(&sid)
                .map(|s| s.is_complete())
                .unwrap_or(false);
            if complete { break; }
            if Instant::now() >= deadline {
                warn!("tunnel_mask server: incomplete session {sid:#010x}, timed out");
                self.sessions.remove(&sid);
                return self.build_servfail(raw_query);
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }

        let original_query = match self.sessions.remove(&sid) {
            Some((_, session)) => match session.assemble() {
                Some(data) => data,
                None => {
                    warn!("tunnel_mask server: assembly gap in session {sid:#010x}");
                    return self.build_servfail(raw_query);
                }
            },
            None => return self.build_servfail(raw_query),
        };

        debug!(
            "tunnel_mask server: reassembled {} bytes, forwarding to {}",
            original_query.len(),
            self.cfg.upstream_addr,
        );

        // ── 6. Forward to the real tunnel server ─────────────────────
        let tunnel_response = self.forward_to_tunnel_server(&original_query).await;

        match tunnel_response {
            Some(resp) => {
                debug!("tunnel_mask server: tunnel responded with {} bytes", resp.len());
                self.build_data_response(raw_query, &resp)
            }
            None => self.build_servfail(raw_query),
        }
    }

    /// Spawn background task that evicts stale reassembly sessions.
    pub fn spawn_eviction_task(&self) {
        let sessions = self.sessions.clone();
        let ttl_ms = self.cfg.session_ttl_ms;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            loop {
                tick.tick().await;
                let now = Instant::now();
                sessions.retain(|_, v| {
                    now.duration_since(v.created_at).as_millis() < ttl_ms as u128
                });
            }
        });
    }

    // ── Networking ───────────────────────────────────────────────────

    async fn forward_to_tunnel_server(&self, query: &[u8]) -> Option<Vec<u8>> {
        let upstream: SocketAddr = match self.cfg.upstream_addr.parse() {
            Ok(a)  => a,
            Err(e) => { warn!("tunnel_mask server: bad upstream_addr: {e}"); return None; }
        };
        let bind: SocketAddr = if upstream.is_ipv4() {
            ([0u8; 4], 0u16).into()
        } else {
            ([0u16; 8], 0u16).into()
        };
        let sock = UdpSocket::bind(bind).await.ok()?;
        sock.send_to(query, upstream).await.ok()?;

        let mut buf = vec![0u8; 4096];
        match tokio::time::timeout(Duration::from_millis(4000), sock.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => Some(buf[..len].to_vec()),
            Ok(Err(e)) => { warn!("tunnel_mask server: tunnel recv: {e}"); None }
            Err(_)     => { warn!("tunnel_mask server: tunnel timeout"); None }
        }
    }

    // ── Response builders ────────────────────────────────────────────

    /// 1 AAAA record with a consistent ULA address – looks like a normal
    /// CDN endpoint.  The client discards this.
    fn build_dummy_response(&self, raw_query: &[u8]) -> Option<Vec<u8>> {
        let msg = Message::from_vec(raw_query).ok()?;
        let qname = msg.queries().first()?.name().clone();

        let mut resp = Message::new();
        resp.set_id(msg.id());
        resp.set_message_type(MessageType::Response);
        resp.set_op_code(OpCode::Query);
        resp.set_authoritative(true);
        resp.set_recursion_available(false);
        resp.set_response_code(ResponseCode::NoError);
        for q in msg.queries() { resp.add_query(q.clone()); }

        let addr: Ipv6Addr = "fd09:b7e2:4a31::1".parse().unwrap();
        let mut rec = Record::new();
        rec.set_name(qname)
           .set_ttl(self.cfg.dummy_ttl)
           .set_dns_class(DNSClass::IN)
           .set_rr_type(RecordType::AAAA)
           .set_data(Some(RData::AAAA(AAAA(addr))));
        resp.add_answer(rec);

        resp.to_vec().ok()
    }

    /// Pack the tunnel response bytes into AAAA records.
    ///
    /// Layout: `[u16 BE length] [data] [zero pad to mod 16]`
    fn build_data_response(
        &self,
        raw_query: &[u8],
        tunnel_resp: &[u8],
    ) -> Option<Vec<u8>> {
        let msg = Message::from_vec(raw_query).ok()?;
        let qname = msg.queries().first()?.name().clone();

        // How many payload bytes can we carry?
        let max_payload = self.cfg.max_response_records * 16;
        // 2 bytes for the length prefix
        let usable = max_payload.saturating_sub(2);
        let actual_len = tunnel_resp.len().min(usable);

        // Build the byte payload
        let mut payload = Vec::with_capacity(max_payload);
        payload.extend_from_slice(&(actual_len as u16).to_be_bytes());
        payload.extend_from_slice(&tunnel_resp[..actual_len]);
        // Pad to a multiple of 16
        while payload.len() % 16 != 0 {
            payload.push(0);
        }

        // Build the DNS response
        let mut resp = Message::new();
        resp.set_id(msg.id());
        resp.set_message_type(MessageType::Response);
        resp.set_op_code(OpCode::Query);
        resp.set_authoritative(true);
        resp.set_recursion_available(false);
        resp.set_response_code(ResponseCode::NoError);
        for q in msg.queries() { resp.add_query(q.clone()); }

        for chunk in payload.chunks(16).take(self.cfg.max_response_records) {
            let mut octets = [0u8; 16];
            octets[..chunk.len()].copy_from_slice(chunk);
            let addr = Ipv6Addr::from(octets);
            let mut rec = Record::new();
            rec.set_name(qname.clone())
               .set_ttl(self.cfg.response_ttl)
               .set_dns_class(DNSClass::IN)
               .set_rr_type(RecordType::AAAA)
               .set_data(Some(RData::AAAA(AAAA(addr))));
            resp.add_answer(rec);
        }

        resp.to_vec().ok()
    }

    fn build_servfail(&self, raw_query: &[u8]) -> Option<Vec<u8>> {
        let msg = Message::from_vec(raw_query).ok()?;
        let mut resp = Message::new();
        resp.set_id(msg.id());
        resp.set_message_type(MessageType::Response);
        resp.set_op_code(OpCode::Query);
        resp.set_recursion_available(false);
        resp.set_response_code(ResponseCode::ServFail);
        for q in msg.queries() { resp.add_query(q.clone()); }
        resp.to_vec().ok()
    }
}