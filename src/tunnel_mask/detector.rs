//! Heuristic classifier that decides whether an incoming DNS query is
//! a tunnel query (dnstt / slipstream).
//!
//! Scoring: each rule contributes 1 point.  `score >= 2` → tunnel query.

use super::config::TunnelMaskConfig;

/// Subset of config fields used by the detector.
pub struct DetectorConfig {
    pub known_tunnel_zones: Vec<String>,
    pub auto_detect: bool,
    pub qname_len_threshold: usize,
    pub label_len_threshold: usize,
    pub entropy_threshold: f64,
    pub base32_fraction_threshold: f64,
}

impl From<&TunnelMaskConfig> for DetectorConfig {
    fn from(c: &TunnelMaskConfig) -> Self {
        Self {
            known_tunnel_zones: c.known_tunnel_zones.clone(),
            auto_detect: c.auto_detect,
            qname_len_threshold: c.qname_len_threshold,
            label_len_threshold: c.label_len_threshold,
            entropy_threshold: c.entropy_threshold,
            base32_fraction_threshold: c.base32_fraction_threshold,
        }
    }
}

/// Returns `true` if the query looks like a DNS tunnel query.
pub fn is_tunnel_query(qname: &str, qtype: u16, cfg: &DetectorConfig) -> bool {
    let mut score: u32 = 0;
    let qname_lower = qname.to_lowercase();

    // ── Rule: known tunnel zone suffix ────────────────────────────────
    for zone in &cfg.known_tunnel_zones {
        let z = zone.to_lowercase();
        let suffix = if z.starts_with('.') {
            z.clone()
        } else {
            format!(".{z}")
        };
        if qname_lower.ends_with(&suffix) || qname_lower == z.trim_start_matches('.') {
            score += 1;
            break;
        }
    }

    if !cfg.auto_detect {
        // Without auto-detect, only known-zone matches count.
        return score >= 1;
    }

    // ── Rule: long QNAME ──────────────────────────────────────────────
    if qname.len() > cfg.qname_len_threshold {
        score += 1;
    }

    let labels: Vec<&str> = qname.split('.').collect();

    // ── Rule: any label too long ──────────────────────────────────────
    if labels.iter().any(|l| l.len() > cfg.label_len_threshold) {
        score += 1;
    }

    // ── Rule: high Shannon entropy in any label ───────────────────────
    if labels
        .iter()
        .filter(|l| l.len() >= 10)
        .any(|l| shannon_entropy(l) > cfg.entropy_threshold)
    {
        score += 1;
    }

    // ── Rule: high base-32 character fraction ─────────────────────────
    if labels
        .iter()
        .filter(|l| l.len() >= 10)
        .any(|l| base32_fraction(l) > cfg.base32_fraction_threshold)
    {
        score += 1;
    }

    // ── Rule: TXT query type (QTYPE 16) ──────────────────────────────
    if qtype == 16 {
        score += 1;
    }

    score >= 2
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Shannon entropy H = −Σ p(c) log₂ p(c)  over distinct bytes in `s`.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    let len = s.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Fraction of characters in `s` that belong to the base-32 alphabet
/// `[a-z2-7]` (RFC 4648, case-insensitive).
fn base32_fraction(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let count = s
        .bytes()
        .filter(|b| b.is_ascii_lowercase() || matches!(b, b'2'..=b'7'))
        .count();
    count as f64 / s.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_uniform() {
        // 4 distinct chars, each appearing once → H = log₂(4) = 2.0
        let h = shannon_entropy("abcd");
        assert!((h - 2.0).abs() < 0.01);
    }

    #[test]
    fn test_base32_fraction() {
        assert!((base32_fraction("abcdefg234567") - 1.0).abs() < 0.01);
        assert!(base32_fraction("0189ABCXYZ") < 0.5);
    }
}
