//! DNS-tunnel fragment encoding: `MaskEncoder` trait + `HexEncoder` (default)
//! + `SyllableEncoder` (optional).
//!
//! ## Binary frame format (shared by both encoders)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                       session_id (4 bytes)                    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |           nonce (2 bytes)     |  frag_idx     |  frag_total   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |    qtype      |   reserved    |          payload ...          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! The first **10 bytes** are always the frame header.  Everything after is the
//! raw payload for this fragment.
//!
//! ## HexEncoder (default, maximum stealth)
//!
//! The entire frame (header + payload) is hex-encoded to a lowercase string,
//! then split into fixed-length labels (default 12 chars) that look exactly
//! like CDN content hashes.  No structural markers, no prefix.
//!
//! Example (relay_zone = "relay.example.net", label_len = 12):
//! ```
//! 4fa20b91a7c2.030207100ae7.c4a9b2c1d3e5.relay.example.net
//! ```
//!
//! ## SyllableEncoder (optional)
//!
//! Uses a human-readable metadata label (`tm<8hex>-<seq>-<total>-<qtype>-<pad>`)
//! followed by CVC word-pair labels for the payload.  More legible but carries
//! a detectable `tm` prefix.

use std::collections::HashMap;
use std::sync::Arc;

// ─────────────────────────────────────────────────────────────────────────────
// FrameHeader
// ─────────────────────────────────────────────────────────────────────────────

/// Decoded header of one tunnel fragment frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameHeader {
    /// 4-byte random value shared by all fragments of one original query.
    pub session_id: u32,
    /// 2-byte random value unique to this fragment (cache-busting).
    /// Set to 0 when decoded from syllable mode (not present in that format).
    pub nonce: u16,
    /// 0-based fragment index.
    pub frag_idx: u8,
    /// Total fragment count for this session.
    pub frag_total: u8,
    /// Original DNS QTYPE (e.g. 16 for TXT, 1 for A).
    pub qtype: u8,
    /// Reserved; always 0.
    pub reserved: u8,
}

impl FrameHeader {
    /// Serialize to the 10-byte wire representation.
    pub fn to_bytes(&self) -> [u8; 10] {
        let sid = self.session_id.to_be_bytes();
        let n   = self.nonce.to_be_bytes();
        [
            sid[0], sid[1], sid[2], sid[3],
            n[0],   n[1],
            self.frag_idx,
            self.frag_total,
            self.qtype,
            self.reserved,
        ]
    }

    /// Parse from the first 10 bytes of a frame.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 10 { return None; }
        Some(Self {
            session_id: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
            nonce:      u16::from_be_bytes([b[4], b[5]]),
            frag_idx:   b[6],
            frag_total: b[7],
            qtype:      b[8],
            reserved:   b[9],
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MaskEncoder trait
// ─────────────────────────────────────────────────────────────────────────────

/// Encode / decode tunnel fragment frames into DNS QNAMEs and back.
///
/// `frame` passed to `encode` is `[10-byte FrameHeader][payload bytes]`.
/// `decode` returns `(FrameHeader, payload_bytes)` on success.
pub trait MaskEncoder: Send + Sync {
    /// Encode a binary frame into a full QNAME string (no trailing dot).
    fn encode(&self, frame: &[u8], relay_zone: &str) -> String;

    /// Decode a QNAME back into a `(FrameHeader, payload)` pair.
    /// Returns `None` if the QNAME does not conform to this encoder's format.
    fn decode(&self, qname: &str, relay_zone: &str) -> Option<(FrameHeader, Vec<u8>)>;

    /// Maximum raw payload bytes that can be carried in one fragment for the
    /// given `max_qname_len` and `relay_zone`.
    fn payload_capacity(&self, max_qname_len: usize, relay_zone: &str) -> usize;
}

// ─────────────────────────────────────────────────────────────────────────────
// HexEncoder
// ─────────────────────────────────────────────────────────────────────────────

/// The default, maximum-stealth encoder.
///
/// Encodes the entire binary frame as a lowercase hex string, then splits it
/// into DNS labels of `label_len` characters each.  The result looks like a
/// CDN content-hash lookup: `d111111abcdef8.cloudfront.net`-style.
///
/// No structural markers.  No prefix.  No decimal numbers.
pub struct HexEncoder {
    /// Number of hex characters per DNS label (default 12).
    pub label_len: usize,
}

impl MaskEncoder for HexEncoder {
    fn encode(&self, frame: &[u8], relay_zone: &str) -> String {
        let hex = hex_encode(frame);
        let zone = relay_zone.trim_matches('.');

        // Split hex string into fixed-length labels.
        // The last label may be shorter than label_len — that is fine; decoding
        // concatenates labels and hex-decodes, so label boundaries don't matter.
        let labels: Vec<&str> = hex
            .as_bytes()
            .chunks(self.label_len)
            .map(|c| {
                // Safety: hex_encode always produces valid ASCII.
                std::str::from_utf8(c).expect("hex is ASCII")
            })
            .collect();

        format!("{}.{}", labels.join("."), zone)
    }

    fn decode(&self, qname: &str, relay_zone: &str) -> Option<(FrameHeader, Vec<u8>)> {
        let qname = qname.trim_end_matches('.');
        let zone  = relay_zone.trim_matches('.');

        // Strip the relay zone suffix.
        let without_zone = strip_zone_suffix(qname, zone)?;

        // Concatenate all labels (remove the dots between them).
        let hex_str: String = without_zone.replace('.', "");

        // Hex-decode the concatenated string.
        let bytes = hex_decode(&hex_str)?;

        // First 10 bytes are the header; the rest is payload.
        let header  = FrameHeader::from_bytes(&bytes)?;
        let payload = bytes[10..].to_vec();

        Some((header, payload))
    }

    fn payload_capacity(&self, max_qname_len: usize, relay_zone: &str) -> usize {
        let zone_len       = relay_zone.trim_matches('.').len();
        let label_with_dot = self.label_len + 1;
        let available      = max_qname_len.saturating_sub(zone_len + 1);
        let n_labels       = available / label_with_dot;
        if n_labels == 0 { return 1; }
        let hex_chars   = n_labels * self.label_len;
        let total_bytes = hex_chars / 2;
        total_bytes.saturating_sub(10).max(1)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SyllableEncoder
// ─────────────────────────────────────────────────────────────────────────────

/// Optional CVC-word encoder.
///
/// Encodes the frame header into a structured metadata label
/// (`tm<session_8hex>-<seq_02d>-<total_02d>-<qtype_02d>-<pad>`) and the
/// payload into CVC word-pair data labels (`cdn0042-img1337`).
///
/// The word table (4 096 entries) can be overridden by a plain-text file
/// (one word per line).  If the file is absent or has fewer than 4 096 entries
/// the built-in table fills the remainder.
pub struct SyllableEncoder {
    words:      Vec<String>,
    word_index: HashMap<String, u32>,
}

impl SyllableEncoder {
    /// Construct a new encoder.
    ///
    /// `syllable_file` — optional path to a file with one CVC word per line.
    /// Falls back to the built-in table when `None` or when the file cannot be
    /// read / does not contain enough entries.
    pub fn new(syllable_file: Option<&str>) -> Self {
        let words = load_word_table(syllable_file);
        let word_index = words
            .iter()
            .enumerate()
            .map(|(i, w)| (w.clone(), i as u32))
            .collect();
        Self { words, word_index }
    }
}

impl MaskEncoder for SyllableEncoder {
    fn encode(&self, frame: &[u8], relay_zone: &str) -> String {
        if frame.len() < 10 {
            // Malformed frame — return a best-effort placeholder.
            return format!("tm00000000-00-01-00-0.{}", relay_zone.trim_matches('.'));
        }

        let header  = FrameHeader::from_bytes(frame).unwrap();
        let payload = &frame[10..];
        let zone    = relay_zone.trim_matches('.');

        // Encode the payload bytes into pair labels; record padding needed.
        let (pair_labels, padding) = syllable_encode_labels(payload, &self.words);

        // Structured metadata label.
        // Format: tm<session_8hex>-<seq_02d>-<total_02d>-<qtype_02d>-<pad>
        let meta = format!(
            "tm{:08x}-{:02}-{:02}-{:02}-{}",
            header.session_id,
            header.frag_idx,
            header.frag_total,
            header.qtype,
            padding
        );

        if pair_labels.is_empty() {
            format!("{}.{}", meta, zone)
        } else {
            format!("{}.{}.{}", meta, pair_labels.join("."), zone)
        }
    }

    fn decode(&self, qname: &str, relay_zone: &str) -> Option<(FrameHeader, Vec<u8>)> {
        let qname = qname.trim_end_matches('.');
        let zone  = relay_zone.trim_matches('.');

        let without_zone = strip_zone_suffix(qname, zone)?;
        let labels: Vec<&str> = without_zone.split('.').collect();
        if labels.is_empty() { return None; }

        // Parse the metadata label.
        let meta_label = labels[0];
        if !meta_label.starts_with("tm") { return None; }

        // Split: ["tm4fa20b91", "02", "07", "16", "1"]
        let parts: Vec<&str> = meta_label.splitn(5, '-').collect();
        if parts.len() < 5 { return None; }

        let tm = parts[0]; // "tm" + 8 hex chars
        if tm.len() != 10 { return None; }
        let session_id = u32::from_str_radix(&tm[2..], 16).ok()?;
        let frag_idx:   u8  = parts[1].parse().ok()?;
        let frag_total: u8  = parts[2].parse().ok()?;
        let qtype:      u8  = parts[3].parse().ok()?;
        let padding:    u8  = parts[4].parse().ok()?;
        if frag_total == 0 { return None; }

        // Decode payload pair labels.
        let pair_label_refs: Vec<&str> = labels[1..].iter().copied().collect();
        let payload = syllable_decode_labels(&pair_label_refs, padding, &self.word_index)?;

        let header = FrameHeader {
            session_id,
            nonce:      0, // not present in syllable metadata
            frag_idx,
            frag_total,
            qtype,
            reserved:   0,
        };

        Some((header, payload))
    }

    fn payload_capacity(&self, max_qname_len: usize, relay_zone: &str) -> usize {
        // metadata label: 22 chars + dot = 23
        // each pair label: ≤ 21 chars + dot = 22
        // relay zone: zone.len() + 1 dot prefix
        const METADATA_WITH_DOT: usize = 23;
        const PAIR_WITH_DOT:     usize = 22;
        const BYTES_PER_PAIR:    usize = 6;

        let zone_len = relay_zone.trim_matches('.').len();
        let fixed    = METADATA_WITH_DOT + zone_len + 1;
        if max_qname_len <= fixed { return BYTES_PER_PAIR; }
        let available = max_qname_len - fixed;
        let n_pairs   = (available / PAIR_WITH_DOT).max(1);
        n_pairs * BYTES_PER_PAIR
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Encoder factory
// ─────────────────────────────────────────────────────────────────────────────

/// Create the appropriate encoder for the given configuration.
pub fn make_encoder(
    encoding:       &crate::tunnel_mask::config::EncodingMode,
    label_len:      usize,
    syllable_file:  Option<&str>,
) -> Arc<dyn MaskEncoder> {
    use crate::tunnel_mask::config::EncodingMode;
    match encoding {
        EncodingMode::Hex      => Arc::new(HexEncoder { label_len }),
        EncodingMode::Syllable => Arc::new(SyllableEncoder::new(syllable_file)),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Word table (syllable mode)
// ─────────────────────────────────────────────────────────────────────────────

const TARGET_WORDS: usize = 4096;

/// Load the 4 096-entry CVC word table.
///
/// If `file` is `Some` and the file can be read, its words are used first.
/// Any shortfall is filled from the built-in generated table.
fn load_word_table(file: Option<&str>) -> Vec<String> {
    let mut words: Vec<String> = Vec::with_capacity(TARGET_WORDS);

    // Attempt file load.
    if let Some(path) = file {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                let word = line.trim().to_lowercase();
                if word.is_empty() { continue; }
                // Accept only ASCII-alphabetic words (no digits, no symbols).
                if word.chars().all(|c| c.is_ascii_lowercase()) {
                    words.push(word);
                    if words.len() >= TARGET_WORDS { break; }
                }
            }
            if words.len() >= TARGET_WORDS {
                return words;
            }
            // File loaded but insufficient entries — fill from built-in table.
            let file_set: std::collections::HashSet<String> =
                words.iter().cloned().collect();
            for w in build_builtin_word_table() {
                if words.len() >= TARGET_WORDS { break; }
                if !file_set.contains(&w) {
                    words.push(w);
                }
            }
            return words;
        }
        // File specified but could not be read — fall through to built-in.
        tracing::warn!(
            path,
            "tunnel_mask: syllable_list_file not readable, using built-in word table"
        );
    }

    build_builtin_word_table()
}

/// Generate the deterministic built-in 4 096-entry CVC word table.
///
/// 41 starters × 13 vowels × 14 enders = 7 462 combinations → first 4 096 taken.
fn build_builtin_word_table() -> Vec<String> {
    const STARTERS: &[&str] = &[
        "b",  "bl", "br", "c",  "ch", "cl", "cr",
        "d",  "dr", "f",  "fl", "fr", "g",  "gl", "gr",
        "h",  "j",  "k",  "l",  "m",  "n",  "p",  "pl", "pr",
        "r",  "s",  "sc", "sk", "sl", "sm", "sn", "sp",
        "st", "str","sw", "t",  "th", "tr", "v",  "w",  "wr",
    ];
    const VOWELS: &[&str] = &[
        "a", "ai", "au", "e", "ea", "ee", "i", "ie", "o", "oa", "oo", "ou", "u",
    ];
    const ENDERS: &[&str] = &[
        "b", "d", "f", "g", "k", "l", "m", "n", "p", "r", "s", "t", "v", "x",
    ];

    let mut words = Vec::with_capacity(TARGET_WORDS);
    'outer: for s in STARTERS {
        for v in VOWELS {
            for e in ENDERS {
                words.push(format!("{}{}{}", s, v, e));
                if words.len() >= TARGET_WORDS { break 'outer; }
            }
        }
    }
    debug_assert_eq!(
        words.len(), TARGET_WORDS,
        "built-in word table must have exactly {TARGET_WORDS} entries"
    );
    words
}

// ─────────────────────────────────────────────────────────────────────────────
// Syllable encode / decode helpers (used by SyllableEncoder)
// ─────────────────────────────────────────────────────────────────────────────

/// Encode `data` bytes into a list of DNS label strings using the CVC word table.
///
/// Returns `(labels, padding)` where `padding` bytes (0–5) were appended to
/// `data` to reach a multiple of 6.
fn syllable_encode_labels(data: &[u8], words: &[String]) -> (Vec<String>, u8) {
    let mut buf: Vec<u8> = data.to_vec();
    let rem     = buf.len() % 6;
    let padding = if rem == 0 { 0 } else { 6 - rem } as u8;
    buf.extend(std::iter::repeat(0u8).take(padding as usize));

    let mut labels = Vec::with_capacity(buf.len() / 6);
    for chunk in buf.chunks_exact(6) {
        let t1 = encode_syllable_token(&chunk[0..3], words);
        let t2 = encode_syllable_token(&chunk[3..6], words);
        labels.push(format!("{}-{}", t1, t2));
    }
    (labels, padding)
}

/// Decode a slice of syllable pair-label strings back to the original bytes.
fn syllable_decode_labels(
    labels:     &[&str],
    padding:    u8,
    word_index: &HashMap<String, u32>,
) -> Option<Vec<u8>> {
    let mut result = Vec::with_capacity(labels.len() * 6);
    for &label in labels {
        // A pair label has exactly one '-' separating two tokens.
        let dash = label.find('-').ok_or(()).ok()?;
        let t1   = &label[..dash];
        let t2   = &label[dash + 1..];
        result.extend_from_slice(&decode_syllable_token(t1, word_index)?);
        result.extend_from_slice(&decode_syllable_token(t2, word_index)?);
    }
    let trimmed = result.len().checked_sub(padding as usize)?;
    result.truncate(trimmed);
    Some(result)
}

/// Encode 3 bytes as a single syllable token: `word + 4-digit-suffix`.
///
/// 24 bits = high-12 (word index 0–4095) + low-12 (numeric suffix 0–4095).
#[inline]
fn encode_syllable_token(bytes: &[u8], words: &[String]) -> String {
    debug_assert_eq!(bytes.len(), 3);
    let v          = ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32);
    let word_idx   = (v >> 12) as usize;
    let suffix     = v & 0xFFF;
    format!("{}{:04}", words[word_idx], suffix)
}

/// Decode a single syllable token back to 3 bytes.
#[inline]
fn decode_syllable_token(token: &str, index: &HashMap<String, u32>) -> Option<[u8; 3]> {
    // Token = word (≥1 char) + 4-digit suffix.
    if token.len() < 5 { return None; }
    let suffix_start = token.len() - 4;
    let word_part    = &token[..suffix_start];
    let suffix_part  = &token[suffix_start..];

    let word_idx: u32 = *index.get(word_part)?;
    let suffix:   u32 = suffix_part.parse().ok()?;
    if suffix > 0xFFF { return None; }

    let v = (word_idx << 12) | suffix;
    Some([
        ((v >> 16) & 0xFF) as u8,
        ((v >>  8) & 0xFF) as u8,
        ( v        & 0xFF) as u8,
    ])
}

// ─────────────────────────────────────────────────────────────────────────────
// Hex encode / decode (no external crate)
// ─────────────────────────────────────────────────────────────────────────────

/// Encode bytes to a lowercase hex string.
#[inline]
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

/// Decode a lowercase (or uppercase) hex string to bytes.
/// Returns `None` if the string has odd length or contains non-hex characters.
#[inline]
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 { return None; }
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let hi = hex_nibble(pair[0])?;
            let lo = hex_nibble(pair[1])?;
            Some((hi << 4) | lo)
        })
        .collect()
}

#[inline]
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _           => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared utility
// ─────────────────────────────────────────────────────────────────────────────

/// Strip the relay-zone suffix and return everything before it.
///
/// Handles three cases:
/// * `qname` == `zone`          → returns `None` (bare zone, no data labels)
/// * `qname` ends with `.zone`  → returns the prefix
/// * otherwise                  → returns `None`
fn strip_zone_suffix<'a>(qname: &'a str, zone: &str) -> Option<&'a str> {
    if qname == zone {
        return None; // bare zone apex — no fragment data
    }
    let suffix = format!(".{}", zone);
    qname.strip_suffix(suffix.as_str())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const ZONE: &str = "relay.example.net";

    fn make_frame(session: u32, nonce: u16, idx: u8, total: u8, qtype: u8, payload: &[u8]) -> Vec<u8> {
        let hdr = FrameHeader { session_id: session, nonce, frag_idx: idx, frag_total: total, qtype, reserved: 0 };
        let mut f = hdr.to_bytes().to_vec();
        f.extend_from_slice(payload);
        f
    }

    // ── HexEncoder ───────────────────────────────────────────────────────────

    #[test]
    fn hex_roundtrip() {
        let enc   = HexEncoder { label_len: 12 };
        let frame = make_frame(0xDEAD_BEEF, 0xCAFE, 2, 5, 16, b"hello world!");
        let qname = enc.encode(&frame, ZONE);
        assert!(qname.ends_with(&format!(".{}", ZONE)), "should end with relay zone");
        // No structural markers in hex mode
        assert!(!qname.starts_with("tm"), "hex mode must not have tm prefix");
        let (hdr, payload) = enc.decode(&qname, ZONE).expect("decode must succeed");
        assert_eq!(hdr.session_id, 0xDEAD_BEEF);
        assert_eq!(hdr.nonce,      0xCAFE);
        assert_eq!(hdr.frag_idx,   2);
        assert_eq!(hdr.frag_total, 5);
        assert_eq!(hdr.qtype,      16);
        assert_eq!(payload,        b"hello world!");
    }

    #[test]
    fn hex_capacity_matches_spec() {
        // Spec example: max_qname_len=120, relay_zone=18 chars, label_len=12 → 32 bytes
        let enc = HexEncoder { label_len: 12 };
        let cap = enc.payload_capacity(120, ZONE); // relay.example.net = 18 chars
        assert_eq!(cap, 32, "spec example must produce 32 bytes payload capacity");
    }

    #[test]
    fn hex_qname_length_within_budget() {
        let enc     = HexEncoder { label_len: 12 };
        let payload = vec![0u8; enc.payload_capacity(120, ZONE)];
        let frame   = make_frame(1, 2, 0, 1, 1, &payload);
        let qname   = enc.encode(&frame, ZONE);
        assert!(
            qname.len() <= 120,
            "encoded QNAME {} chars exceeds max_qname_len 120",
            qname.len()
        );
    }

    #[test]
    fn hex_binary_all_values() {
        let enc     = HexEncoder { label_len: 12 };
        let payload: Vec<u8> = (0..=255u8).collect();
        let frame   = make_frame(0, 0, 0, 1, 16, &payload);
        let qname   = enc.encode(&frame, ZONE);
        let (_, dec) = enc.decode(&qname, ZONE).unwrap();
        assert_eq!(dec, payload);
    }

    // ── SyllableEncoder ───────────────────────────────────────────────────────

    #[test]
    fn syllable_roundtrip() {
        let enc   = SyllableEncoder::new(None);
        let frame = make_frame(0xABCD_1234, 0, 1, 3, 16, b"syllable payload test");
        let qname = enc.encode(&frame, ZONE);
        assert!(qname.starts_with("tm"), "syllable mode must have tm prefix");
        assert!(qname.ends_with(&format!(".{}", ZONE)));
        let (hdr, payload) = enc.decode(&qname, ZONE).expect("syllable decode");
        assert_eq!(hdr.session_id, 0xABCD_1234);
        assert_eq!(hdr.frag_idx,   1);
        assert_eq!(hdr.frag_total, 3);
        assert_eq!(hdr.qtype,      16);
        assert_eq!(payload, b"syllable payload test");
    }

    #[test]
    fn syllable_builtin_table_size() {
        let enc = SyllableEncoder::new(None);
        assert_eq!(enc.words.len(), TARGET_WORDS);
    }

    #[test]
    fn syllable_builtin_table_unique() {
        let enc = SyllableEncoder::new(None);
        let mut set = std::collections::HashSet::new();
        for w in &enc.words {
            assert!(set.insert(w.as_str()), "duplicate word: {w}");
        }
    }

    // ── Hex utilities ─────────────────────────────────────────────────────────

    #[test]
    fn hex_encode_decode_roundtrip() {
        let data: Vec<u8> = (0..=255u8).collect();
        let enc = hex_encode(&data);
        let dec = hex_decode(&enc).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn hex_decode_rejects_odd_length() {
        assert!(hex_decode("abc").is_none());
    }

    #[test]
    fn hex_decode_rejects_invalid_chars() {
        assert!(hex_decode("gg").is_none());
    }
}
