//! Heuristic classifier: is this DNS query a tunnel query?
//!
//! Scores each query on 6 independent rules; a score ≥ 2 is treated as a
//! tunnel query.  This two-point threshold avoids false-positives from
//! legitimate long labels (e.g. DKIM, SRV, DNSSD) while still catching all
//! common dnstt / slipstream query shapes.

use crate::tunnel_mask::config::TunnelMaskConfig;

// ─────────────────────────────────────────────────────────────────────────────
// Public classifier
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` if the query looks like a tunnel query that should be
/// intercepted and forwarded through the masking layer.
///
/// `qname` should be the full QNAME string (lowercase, no trailing dot).
/// `qtype` is the raw 16-bit record type value.
pub fn is_tunnel_query(qname: &str, qtype: u16, cfg: &TunnelMaskConfig) -> bool {
    // Fast-path: QNAME suffix matches a known tunnel zone.
    for zone in &cfg.known_tunnel_zones {
        let zone_lc = zone.trim_end_matches('.').to_lowercase();
        let qname_lc = qname.trim_end_matches('.');
        if qname_lc == zone_lc
            || qname_lc.ends_with(&format!(".{}", zone_lc))
        {
            return true;
        }
    }

    // Skip auto-detection if disabled.
    if !cfg.auto_detect {
        return false;
    }

    let mut score: u8 = 0;
    let qname_clean = qname.trim_end_matches('.');

    // Rule 1 – Long QNAME
    if qname_clean.len() > cfg.qname_len_threshold {
        score += 1;
    }

    // Analyse individual labels.
    let labels: Vec<&str> = qname_clean.split('.').collect();
    for label in &labels {
        // Rule 2 – Long label
        if label.len() > cfg.label_len_threshold {
            score += 1;
        }

        // Rule 3 – High Shannon entropy
        if shannon_entropy(label) > cfg.entropy_threshold {
            score += 1;
        }

        // Rule 4 – Base32 saturation  (chars [a-z2-7])
        if base32_fraction(label) > cfg.base32_fraction_threshold {
            score += 1;
        }

        if score >= 2 { break; } // early exit
    }

    // Rule 5 – TXT query type
    if qtype == 16 {
        score += 1;
    }

    score >= 2
}

// ─────────────────────────────────────────────────────────────────────────────
// Scoring helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Shannon entropy H = -Σ p(c) * log₂(p(c)) over distinct characters in
/// `s`.  Returns 0.0 for empty strings.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let len = s.len() as f64;
    let mut counts = [0u32; 128];
    for b in s.bytes() {
        if (b as usize) < 128 {
            counts[b as usize] += 1;
        }
    }
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Returns the fraction of characters in `s` that belong to the base32
/// alphabet `[a-z2-7]`.  Returns 0.0 for empty strings.
fn base32_fraction(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let count = s.bytes()
        .filter(|&b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
        .count();
    count as f64 / s.len() as f64
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel_mask::config::TunnelMaskConfig;

    fn default_cfg() -> TunnelMaskConfig {
        TunnelMaskConfig::default()
    }

    #[test]
    fn detects_known_zone() {
        let mut cfg = default_cfg();
        cfg.known_tunnel_zones = vec!["t.example.com".into()];
        // Exact zone match
        assert!(is_tunnel_query("t.example.com", 16, &cfg));
        // Subdomain match
        assert!(is_tunnel_query(
            "abcdefghijklmnop.t.example.com",
            16,
            &cfg
        ));
        // Unrelated zone – should not match purely on zone
        assert!(!is_tunnel_query("google.com", 1, &cfg));
    }

    #[test]
    fn scores_high_entropy_label() {
        let cfg = default_cfg();
        // Typical dnstt label: long base32-looking string
        let qname = "abcdefghijklmnopqrstuvwxyz234567abcdef.ns.example.com";
        assert!(is_tunnel_query(qname, 16, &cfg));
    }

    #[test]
    fn normal_query_not_flagged() {
        let cfg = default_cfg();
        assert!(!is_tunnel_query("www.google.com", 1, &cfg));
        assert!(!is_tunnel_query("mail.example.com", 28, &cfg));
    }
}
