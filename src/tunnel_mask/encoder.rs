//! Encodes / decodes binary frames (header + payload) into DNS query name
//! labels that look like plausible CDN hash lookups.

/// Fixed header size in bytes.
pub const HEADER_LEN: usize = 10;

// ─────────────────────────────────────────────────────────────────────────────
// Frame header
// ─────────────────────────────────────────────────────────────────────────────

/// Upstream fragment header (10 bytes).
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       session_id (4 B)                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         nonce (2 B)           |  frag_idx     |  frag_total   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    qtype      |   reserved    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone)]
pub struct FrameHeader {
    pub session_id: u32,
    pub nonce:      u16,
    pub frag_idx:   u8,
    pub frag_total: u8,
    pub qtype:      u8,
}

impl FrameHeader {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[0..4].copy_from_slice(&self.session_id.to_be_bytes());
        buf[4..6].copy_from_slice(&self.nonce.to_be_bytes());
        buf[6] = self.frag_idx;
        buf[7] = self.frag_total;
        buf[8] = self.qtype;
        buf[9] = 0; // reserved
        buf
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < HEADER_LEN {
            return None;
        }
        Some(Self {
            session_id: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
            nonce:      u16::from_be_bytes([data[4], data[5]]),
            frag_idx:   data[6],
            frag_total: data[7],
            qtype:      data[8],
        })
    }

    /// True when this fragment is the last one in the message.
    pub fn is_final(&self) -> bool {
        self.frag_total > 0 && self.frag_idx + 1 == self.frag_total
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Encoder trait
// ─────────────────────────────────────────────────────────────────────────────

/// Encodes binary frames into DNS query names and back.
pub trait MaskEncoder: Send + Sync {
    /// Produce a QNAME string (without trailing dot) from a binary frame.
    fn encode_qname(&self, frame: &[u8], relay_zone: &str) -> String;

    /// Decode a QNAME back into the binary frame bytes.
    fn decode_qname(&self, qname: &str, relay_zone: &str) -> Option<Vec<u8>>;

    /// Maximum payload bytes (excluding header) that fit in one query.
    fn payload_capacity(&self, max_qname_len: usize, relay_zone: &str) -> usize;
}

// ─────────────────────────────────────────────────────────────────────────────
// Hex encoder (default – maximum stealth)
// ─────────────────────────────────────────────────────────────────────────────

/// Encodes the entire binary frame as a lowercase hex string and splits it
/// into DNS labels of fixed length.
///
/// # Example
///
/// ```text
/// 4fa20b91a7c2.030207100ae7.c4a9b2c1d3e5.relay.example.net
/// └──────────── hex-encoded frame ──────────┘
/// ```
///
/// The server decodes by stripping the relay zone, concatenating labels,
/// and hex-decoding.  The first 10 bytes are always the header.
pub struct HexEncoder {
    pub label_len: usize,
}

impl MaskEncoder for HexEncoder {
    fn encode_qname(&self, frame: &[u8], relay_zone: &str) -> String {
        let hex_str = hex_encode(frame);
        let mut labels = Vec::new();
        let mut pos = 0;
        while pos < hex_str.len() {
            let end = (pos + self.label_len).min(hex_str.len());
            labels.push(&hex_str[pos..end]);
            pos = end;
        }
        if labels.is_empty() {
            labels.push("00");
        }
        format!("{}.{}", labels.join("."), relay_zone)
    }

    fn decode_qname(&self, qname: &str, relay_zone: &str) -> Option<Vec<u8>> {
        let rz = relay_zone.to_lowercase();
        let q = qname.to_lowercase();
        let suffix = format!(".{rz}");
        let prefix = q.strip_suffix(&suffix)?;
        let hex_str: String = prefix.split('.').collect();
        hex_decode(&hex_str)
    }

    fn payload_capacity(&self, max_qname_len: usize, relay_zone: &str) -> usize {
        // Available characters = max_qname_len - relay_zone - 1 (dot separator)
        let available = max_qname_len.saturating_sub(relay_zone.len() + 1);
        // Each label takes label_len chars + 1 dot (except the last, but
        // counting the leading dot before relay_zone covers it).
        let num_labels = if self.label_len == 0 {
            0
        } else {
            available / (self.label_len + 1)
        };
        let hex_chars = num_labels * self.label_len;
        // 2 hex chars = 1 byte; subtract the 10-byte header
        (hex_chars / 2).saturating_sub(HEADER_LEN)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Hex helpers (no external crate needed)
// ─────────────────────────────────────────────────────────────────────────────

fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push(HEX_CHARS[(b >> 4) as usize] as char);
        s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
    }
    s
}

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut result = Vec::with_capacity(s.len() / 2);
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        result.push((hi << 4) | lo);
    }
    Some(result)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_hex() {
        let data = b"hello world!";
        let encoded = hex_encode(data);
        assert_eq!(encoded, "68656c6c6f20776f726c6421");
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn roundtrip_qname() {
        let encoder = HexEncoder { label_len: 12 };
        let relay = "relay.example.net";

        // Build frame
        let header = FrameHeader {
            session_id: 0x4fa20b91,
            nonce: 0xa7c2,
            frag_idx: 2,
            frag_total: 7,
            qtype: 16,
        };
        let payload = b"test payload";
        let mut frame = Vec::from(header.encode());
        frame.extend_from_slice(payload);

        let qname = encoder.encode_qname(&frame, relay);
        assert!(qname.ends_with(relay));

        let decoded = encoder.decode_qname(&qname, relay).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn payload_capacity() {
        let encoder = HexEncoder { label_len: 12 };
        let cap = encoder.payload_capacity(120, "relay.example.net");
        // available = 120 - 18 - 1 = 101
        // labels = 101 / 13 = 7
        // hex_chars = 84 → 42 bytes − 10 header = 32
        assert_eq!(cap, 32);
    }
}