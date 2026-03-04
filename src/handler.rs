use crate::{
    cache::{CacheKey, DnsCache},
    config::Config,
    metrics::Metrics,
    static_store::StaticStore,
    tunnel_mask::TunnelMask,
    upstream::UpstreamPool,
};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::Record;
use std::sync::Arc;
use tracing::{debug, trace, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Handler
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct Handler {
    pub cfg:         Arc<Config>,
    pub store:       Arc<StaticStore>,
    pub cache:       Arc<DnsCache>,
    pub pool:        Arc<UpstreamPool>,
    pub metrics:     Arc<Metrics>,
    pub tunnel_mask: Arc<TunnelMask>,
}

impl Handler {
    pub async fn handle(&self, raw: &[u8]) -> Option<Vec<u8>> {
        self.metrics.queries_total();
        self.metrics.add_bytes_rx(raw.len() as u64);

        // ── Parse ─────────────────────────────────────────────────────────
        let msg = match Message::from_vec(raw) {
            Ok(m)  => m,
            Err(e) => {
                trace!("parse error: {e}");
                self.metrics.queries_failed();
                return None;
            }
        };

        if msg.message_type() != MessageType::Query {
            return None;
        }

        if msg.op_code() != OpCode::Query {
            self.metrics.queries_failed();
            return Some(self.notimp(&msg));
        }

        let q = msg.queries().first()?.clone();
        let qname  = q.name().to_lowercase();
        let qtype  = q.query_type();
        let name_s = qname.to_string();
        let name   = name_s.trim_end_matches('.');

        let do_bit = msg.extensions()
            .as_ref()
            .map(|e| e.dnssec_ok())
            .unwrap_or(false);

        if self.cfg.logging.log_queries {
            debug!(name, ?qtype, do_bit, "query");
        }

        // ── Tunnel Mask intercept (BEFORE static / cache / upstream) ──
        if let Some(response) = self.tunnel_mask.handle_query(
            name,
            u16::from(qtype),
            msg.id(),
            raw,
        ).await {
            self.metrics.add_bytes_tx(response.len() as u64);
            return Some(response);
        }

        // ── 1. Static override ────────────────────────────────────────
        if let Some(records) = self.store.lookup(name, qtype) {
            self.metrics.queries_static();
            let resp = self.build_static_response(&msg, records, false, do_bit);
            return self.encode_and_emit(resp);
        }

        if self.store.has_domain(name) {
            self.metrics.queries_static();
            let resp = self.build_static_response(&msg, vec![], false, do_bit);
            return self.encode_and_emit(resp);
        }

        // ── 2. Cache ──────────────────────────────────────────────────
        let key = CacheKey { name: name.to_string(), rtype: qtype, dnssec: do_bit };

        if let Some(entry) = self.cache.get(&key) {
            self.metrics.queries_cached();
            self.metrics.cache_hits();

            let remaining = entry.remaining_ttl();
            let mut cached = entry.message.clone();
            cached.set_id(msg.id());
            patch_ttls(&mut cached, remaining);

            return self.encode_and_emit(cached);
        }

        self.metrics.cache_misses();

        // ── 3. Upstream forwarding ────────────────────────────────────
        self.metrics.queries_upstream();

        let fwd_bytes = if self.cfg.dnssec.enabled {
            ensure_do_bit(raw, self.cfg.server.max_udp_payload)
        } else {
            raw.to_vec()
        };

        match self.pool.query(&fwd_bytes, msg.id()).await {
            Ok(resp_bytes) => {
                self.metrics.upstream_ok();
                if let Ok(resp_msg) = Message::from_vec(&resp_bytes) {
                    let neg = matches!(
                        resp_msg.response_code(),
                        ResponseCode::NXDomain | ResponseCode::ServFail
                    );
                    self.cache.insert(key, resp_msg, neg);
                }
                self.metrics.add_bytes_tx(resp_bytes.len() as u64);
                Some(resp_bytes)
            }
            Err(e) => {
                warn!(name, "upstream failed: {e}");
                self.metrics.queries_failed();
                self.metrics.upstream_errors();
                let resp = self.servfail(&msg);
                self.metrics.add_bytes_tx(resp.len() as u64);
                Some(resp)
            }
        }
    }

    // ── Response builders ──────────────────────────────────────────────────

    fn build_static_response(
        &self,
        q:        &Message,
        answers:  Vec<Record>,
        nxdomain: bool,
        do_bit:   bool,
    ) -> Message {
        let mut r = Message::new();
        r.set_id(q.id());
        r.set_message_type(MessageType::Response);
        r.set_op_code(OpCode::Query);
        r.set_authoritative(self.cfg.static_records.authoritative);
        r.set_recursion_desired(q.recursion_desired());
        r.set_recursion_available(true);
        r.set_response_code(
            if nxdomain { ResponseCode::NXDomain } else { ResponseCode::NoError }
        );

        for query in q.queries() { r.add_query(query.clone()); }
        for ans in answers        { r.add_answer(ans); }

        let mut edns = Edns::new();
        edns.set_dnssec_ok(do_bit && self.cfg.dnssec.enabled);
        edns.set_max_payload(self.cfg.server.max_udp_payload);
        r.set_edns(edns);
        r
    }

    fn servfail(&self, q: &Message) -> Vec<u8> {
        let mut r = Message::new();
        r.set_id(q.id());
        r.set_message_type(MessageType::Response);
        r.set_op_code(OpCode::Query);
        r.set_recursion_available(true);
        r.set_recursion_desired(q.recursion_desired());
        r.set_response_code(ResponseCode::ServFail);
        for query in q.queries() { r.add_query(query.clone()); }
        r.to_vec().unwrap_or_default()
    }

    fn notimp(&self, q: &Message) -> Vec<u8> {
        let mut r = Message::new();
        r.set_id(q.id());
        r.set_message_type(MessageType::Response);
        r.set_response_code(ResponseCode::NotImp);
        r.to_vec().unwrap_or_default()
    }

    #[inline]
    fn encode_and_emit(&self, msg: Message) -> Option<Vec<u8>> {
        let bytes = msg.to_vec().ok()?;
        self.metrics.add_bytes_tx(bytes.len() as u64);
        Some(bytes)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Free helpers
// ─────────────────────────────────────────────────────────────────────────────

fn patch_ttls(msg: &mut Message, remaining: u32) {
    for r in msg.answers_mut()      { r.set_ttl(r.ttl().min(remaining)); }
    for r in msg.name_servers_mut() { r.set_ttl(r.ttl().min(remaining)); }
    for r in msg.additionals_mut()  { r.set_ttl(r.ttl().min(remaining)); }
}

fn ensure_do_bit(raw: &[u8], payload: u16) -> Vec<u8> {
    match Message::from_vec(raw) {
        Ok(mut msg) => {
            let mut edns = msg.extensions().clone().unwrap_or_else(Edns::new);
            edns.set_dnssec_ok(true);
            if edns.max_payload() < payload {
                edns.set_max_payload(payload);
            }
            msg.set_edns(edns);
            msg.to_vec().unwrap_or_else(|_| raw.to_vec())
        }
        Err(_) => raw.to_vec(),
    }
}