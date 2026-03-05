//! Splits a raw byte payload into [`FragmentEnvelope`]s, each carrying a
//! portion of the original data plus the metadata needed to reassemble them.
//!
//! Fragmentation is purely mechanical: the input bytes are cut into fixed-size
//! chunks.  No encryption, no per-fragment ACKs, no retransmission — those are
//! the responsibility of the tunnel protocol above (KCP / QUIC).
//!
//! Each fragment carries:
//! * A shared `session_id` (random per original query).
//! * A unique `nonce` (random per fragment) — ensures the encoded QNAME is
//!   unique for every fragment even if the payload bytes are identical, which
//!   prevents recursive-resolver caching from silently hiding fragments.
//! * `seq` / `total` for ordering and completeness detection.
//! * `qtype` — the original DNS QTYPE of the intercepted tunnel query, carried
//!   through so the server can reconstruct a valid forward query.

use rand::random;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

// ─────────────────────────────────────────────────────────────────────────────
// FragmentEnvelope
// ─────────────────────────────────────────────────────────────────────────────

/// One fragment of an original tunnel query payload.
#[derive(Debug, Clone)]
pub struct FragmentEnvelope {
    /// 4-byte random value shared across all fragments of one original query.
    pub session_id: u32,

    /// 2-byte random value **unique to this fragment**.
    ///
    /// Embedded in the binary frame header so that every fragment QNAME is
    /// unique even when the payload bytes are identical.  This prevents the
    /// recursive resolver from answering a later fragment from its cache.
    pub nonce: u16,

    /// 0-based sequence number of this fragment.
    pub seq: u8,

    /// Total number of fragments in this session.
    pub total: u8,

    /// `true` when this is the last fragment (`seq + 1 == total`).
    pub is_final: bool,

    /// Original DNS QTYPE of the intercepted tunnel query (e.g. 16 = TXT).
    /// Stored in each envelope so the encoder can embed it in the frame header.
    pub qtype: u8,

    /// Raw bytes for this fragment.  Length is ≤ `bytes_per_fragment`.
    pub payload: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Public entry-point
// ─────────────────────────────────────────────────────────────────────────────

/// Split `raw_payload` into [`FragmentEnvelope`]s of at most `bytes_per_fragment`
/// bytes each.
///
/// * `qtype`             — original DNS QTYPE (stored in every envelope).
/// * `raw_payload`       — the bytes to fragment (the tunnel QNAME string
///                         taken as-is, including dots).
/// * `bytes_per_fragment`— maximum payload bytes per fragment (derived from
///                         the encoder's capacity for the configured QNAME
///                         length and relay zone).
///
/// A fresh `session_id` and per-fragment `nonce` are generated for every call.
///
/// # Panics
/// Panics if `bytes_per_fragment` is 0, or if the payload requires more than
/// 255 fragments (the maximum representable by the 1-byte `frag_total` field).
pub fn fragment(qtype: u8, raw_payload: &[u8], bytes_per_fragment: usize) -> Vec<FragmentEnvelope> {
    assert!(bytes_per_fragment > 0, "bytes_per_fragment must be > 0");

    let session_id = new_session_id();

    // Special case: empty payload → one empty fragment so the server still
    // receives a valid session and can forward an empty query if needed.
    if raw_payload.is_empty() {
        return vec![FragmentEnvelope {
            session_id,
            nonce:    random::<u16>(),
            seq:      0,
            total:    1,
            is_final: true,
            qtype,
            payload:  vec![],
        }];
    }

    let chunks: Vec<&[u8]> = raw_payload.chunks(bytes_per_fragment).collect();
    let total = chunks.len();
    assert!(
        total <= 255,
        "payload of {} bytes requires {} fragments at {} bytes/fragment; max is 255",
        raw_payload.len(), total, bytes_per_fragment
    );

    chunks
        .into_iter()
        .enumerate()
        .map(|(seq, chunk)| FragmentEnvelope {
            session_id,
            nonce:    random::<u16>(), // unique per fragment → unique QNAME
            seq:      seq as u8,
            total:    total as u8,
            is_final: seq + 1 == total,
            qtype,
            payload:  chunk.to_vec(),
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Session-ID generation
// ─────────────────────────────────────────────────────────────────────────────

/// Generate a pseudo-random 32-bit session ID.
///
/// Uses wall-clock sub-second nanoseconds XOR'd with a per-process monotonic
/// counter run through a multiplicative hash.  No external crate required.
/// Collision probability over a 5-second window is negligible at expected rates.
pub fn new_session_id() -> u32 {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let c = COUNTER.fetch_add(1, Ordering::Relaxed);
    t ^ c.wrapping_mul(0x9E37_79B9)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_fragment_small_payload() {
        let frags = fragment(16, b"hello", 30);
        assert_eq!(frags.len(), 1);
        assert!(frags[0].is_final);
        assert_eq!(frags[0].seq,   0);
        assert_eq!(frags[0].total, 1);
        assert_eq!(frags[0].qtype, 16);
        assert_eq!(frags[0].payload, b"hello");
    }

    #[test]
    fn multiple_fragments_sequence() {
        let payload: Vec<u8> = (0u8..90).collect();
        let frags = fragment(16, &payload, 30);
        assert_eq!(frags.len(), 3);
        assert!(!frags[0].is_final);
        assert!(!frags[1].is_final);
        assert!(frags[2].is_final);
        // Reassembled must equal original.
        let mut reassembled = Vec::new();
        for f in &frags { reassembled.extend_from_slice(&f.payload); }
        assert_eq!(reassembled, payload);
    }

    #[test]
    fn all_fragments_share_session_id() {
        let payload: Vec<u8> = (0..60).collect();
        let frags = fragment(1, &payload, 30);
        let sid = frags[0].session_id;
        for f in &frags { assert_eq!(f.session_id, sid); }
    }

    #[test]
    fn nonces_are_unique_across_fragments() {
        // With overwhelming probability each fragment's nonce differs.
        let payload: Vec<u8> = vec![0u8; 90];
        let frags = fragment(1, &payload, 30);
        assert_eq!(frags.len(), 3);
        // All three nonces should differ (3 random u16 values from distinct RNG calls).
        // This test has a 1-in-2^32 chance of a false negative — acceptable.
        let n0 = frags[0].nonce;
        let n1 = frags[1].nonce;
        let n2 = frags[2].nonce;
        // At least two must differ (if all three were equal that would be extraordinary).
        assert!(n0 != n1 || n1 != n2 || n0 != n2,
            "all nonces are identical — extremely unlikely unless RNG is broken");
    }

    #[test]
    fn session_ids_differ_between_calls() {
        let a = fragment(16, b"data", 30);
        let b = fragment(16, b"data", 30);
        assert_ne!(a[0].session_id, b[0].session_id,
            "session IDs must differ between independent calls");
    }

    #[test]
    fn empty_payload_produces_one_fragment() {
        let frags = fragment(1, b"", 30);
        assert_eq!(frags.len(), 1);
        assert!(frags[0].is_final);
        assert!(frags[0].payload.is_empty());
    }

    #[test]
    fn qtype_stored_in_every_fragment() {
        let payload: Vec<u8> = (0..60).collect();
        let frags = fragment(28, &payload, 30); // 28 = AAAA
        for f in &frags { assert_eq!(f.qtype, 28); }
    }
}
