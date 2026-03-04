//! Splits a raw payload into sized fragments with per-fragment headers.

use super::encoder::{FrameHeader, HEADER_LEN};
use rand::Rng;

/// One fragment ready to be encoded into a masked DNS query.
pub struct FragmentEnvelope {
    pub session_id: u32,
    pub nonce: u16,
    pub seq: u8,
    pub total: u8,
    pub qtype: u8,
    pub is_final: bool,
    pub payload: Vec<u8>,
}

impl FragmentEnvelope {
    /// Serialize into a binary frame (header + payload) for the encoder.
    pub fn to_frame(&self) -> Vec<u8> {
        let header = FrameHeader {
            session_id: self.session_id,
            nonce: self.nonce,
            frag_idx: self.seq,
            frag_total: self.total,
            qtype: self.qtype,
        };
        let hdr = header.encode();
        let mut frame = Vec::with_capacity(HEADER_LEN + self.payload.len());
        frame.extend_from_slice(&hdr);
        frame.extend_from_slice(&self.payload);
        frame
    }
}

/// Fragment `raw_payload` into chunks of at most `bytes_per_fragment` bytes.
///
/// Each fragment gets a random `nonce` to ensure every query name is unique
/// (prevents resolver caching even on retransmission).
pub fn fragment(
    session_id: u32,
    qtype: u8,
    raw_payload: &[u8],
    bytes_per_fragment: usize,
) -> Vec<FragmentEnvelope> {
    let mut rng = rand::thread_rng();

    if raw_payload.is_empty() || bytes_per_fragment == 0 {
        return vec![FragmentEnvelope {
            session_id,
            nonce: rng.gen(),
            seq: 0,
            total: 1,
            qtype,
            is_final: true,
            payload: raw_payload.to_vec(),
        }];
    }

    let chunks: Vec<&[u8]> = raw_payload.chunks(bytes_per_fragment).collect();
    let total = chunks.len().min(255) as u8;

    chunks
        .iter()
        .enumerate()
        .map(|(i, chunk)| FragmentEnvelope {
            session_id,
            nonce: rng.gen(),
            seq: i as u8,
            total,
            qtype,
            is_final: (i as u8) + 1 == total,
            payload: chunk.to_vec(),
        })
        .collect()
}
