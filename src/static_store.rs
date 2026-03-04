use anyhow::{Context, Result};
use dashmap::DashMap;
use hickory_proto::rr::{
    rdata::{A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT},
    DNSClass, Name, RData, Record, RecordType,
};
use serde::Deserialize;
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
    sync::Arc,
};
use tracing::{info, warn};

// ─────────────────────────────────────────────────────────────────────────────
// CSV row definition
// ─────────────────────────────────────────────────────────────────────────────

/// One row in the static-records CSV file.
///
/// Format:
///   domain,type,ttl,value
///
/// Value format per type:
///   A      → IPv4 address                               e.g.  192.168.1.1
///   AAAA   → IPv6 address                               e.g.  ::1
///   CNAME  → target FQDN (trailing dot optional)        e.g.  www.example.com.
///   NS     → name server FQDN                           e.g.  ns1.example.com.
///   PTR    → pointer FQDN                               e.g.  host.example.com.
///   MX     → "priority exchange"                        e.g.  10 mail.example.com.
///   TXT    → text; separate multiple strings with |     e.g.  v=spf1 ~all
///   SRV    → "priority weight port target"              e.g.  10 20 443 svc.example.com.
///   SOA    → "mname rname serial refresh retry expire minimum"
#[derive(Debug, Deserialize)]
struct CsvRow {
    domain: String,
    #[serde(rename = "type")]
    rtype: String,
    ttl: u32,
    value: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Static store
// ─────────────────────────────────────────────────────────────────────────────

/// Thread-safe store of statically configured DNS records.
///
/// Lookups are O(1) via two DashMaps:
///   `records`    – (name_lower, RecordType) → Vec<Record>
///   `domain_set` – name_lower              → ()   (for "domain exists?" checks)
pub struct StaticStore {
    records:    DashMap<(String, RecordType), Vec<Record>>,
    domain_set: DashMap<String, ()>,
}

impl StaticStore {
    // ── Construction ──────────────────────────────────────────────────────

    pub fn load(path: &str) -> Result<Arc<Self>> {
        let records:    DashMap<(String, RecordType), Vec<Record>> = DashMap::new();
        let domain_set: DashMap<String, ()>                        = DashMap::new();
        let mut count = 0usize;

        if !std::path::Path::new(path).exists() {
            warn!("Static records file '{}' not found – running without static overrides", path);
            return Ok(Arc::new(Self { records, domain_set }));
        }

        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(true)
            .trim(csv::Trim::All)
            .comment(Some(b'#'))
            .from_path(path)
            .with_context(|| format!("Cannot open '{}'", path))?;

        for (line_idx, result) in rdr.deserialize::<CsvRow>().enumerate() {
            let row = match result {
                Ok(r)  => r,
                Err(e) => { warn!("CSV line {}: {e}", line_idx + 2); continue; }
            };

            let rtype = match parse_rtype(&row.rtype) {
                Some(t) => t,
                None => {
                    warn!("CSV line {}: unknown record type '{}'", line_idx + 2, row.rtype);
                    continue;
                }
            };

            let name_norm = normalize(&row.domain);

            match build_record(&name_norm, rtype, row.ttl, &row.value) {
                Ok(rec) => {
                    records.entry((name_norm.clone(), rtype))
                           .or_insert_with(Vec::new)
                           .push(rec);
                    domain_set.insert(name_norm, ());
                    count += 1;
                }
                Err(e) => warn!("CSV line {}: {e}", line_idx + 2),
            }
        }

        info!("Loaded {count} static DNS records from '{path}'");
        Ok(Arc::new(Self { records, domain_set }))
    }

    // ── Public API ────────────────────────────────────────────────────────

    /// Return the records for `(name, rtype)`, or `None` if no exact match.
    pub fn lookup(&self, name: &str, rtype: RecordType) -> Option<Vec<Record>> {
        let key = (normalize(name), rtype);
        self.records.get(&key).map(|v| v.clone())
    }

    /// Return true if the store has *any* record for this name (any type).
    /// Used to distinguish NOERROR-empty from NXDOMAIN for unknown record types.
    pub fn has_domain(&self, name: &str) -> bool {
        self.domain_set.contains_key(&normalize(name))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Lowercase and strip a trailing dot so all keys are in canonical form.
fn normalize(name: &str) -> String {
    name.to_lowercase().trim_end_matches('.').to_string()
}

/// Ensure a domain name string ends with a dot (absolute FQDN).
fn ensure_fqdn(s: &str) -> String {
    if s.ends_with('.') { s.to_string() } else { format!("{s}.") }
}

fn parse_rtype(s: &str) -> Option<RecordType> {
    match s.to_uppercase().as_str() {
        "A"     => Some(RecordType::A),
        "AAAA"  => Some(RecordType::AAAA),
        "CNAME" => Some(RecordType::CNAME),
        "MX"    => Some(RecordType::MX),
        "NS"    => Some(RecordType::NS),
        "PTR"   => Some(RecordType::PTR),
        "TXT"   => Some(RecordType::TXT),
        "SRV"   => Some(RecordType::SRV),
        "SOA"   => Some(RecordType::SOA),
        _       => None,
    }
}

fn build_record(name: &str, rtype: RecordType, ttl: u32, value: &str) -> Result<Record> {
    let dns_name = Name::from_str(&ensure_fqdn(name))
        .with_context(|| format!("Invalid domain name '{name}'"))?;

    let rdata: RData = match rtype {
        // ── A ─────────────────────────────────────────────────────────────
        RecordType::A => {
            let ip: Ipv4Addr = value.trim().parse()
                .with_context(|| format!("Invalid IPv4 address '{value}'"))?;
            RData::A(A(ip))
        }

        // ── AAAA ──────────────────────────────────────────────────────────
        RecordType::AAAA => {
            let ip: Ipv6Addr = value.trim().parse()
                .with_context(|| format!("Invalid IPv6 address '{value}'"))?;
            RData::AAAA(AAAA(ip))
        }

        // ── CNAME ─────────────────────────────────────────────────────────
        RecordType::CNAME => {
            let target = Name::from_str(&ensure_fqdn(value.trim()))
                .context("CNAME: invalid target name")?;
            RData::CNAME(CNAME(target))
        }

        // ── NS ────────────────────────────────────────────────────────────
        RecordType::NS => {
            let ns = Name::from_str(&ensure_fqdn(value.trim()))
                .context("NS: invalid name server name")?;
            RData::NS(NS(ns))
        }

        // ── PTR ───────────────────────────────────────────────────────────
        RecordType::PTR => {
            let ptr = Name::from_str(&ensure_fqdn(value.trim()))
                .context("PTR: invalid pointer name")?;
            RData::PTR(PTR(ptr))
        }

        // ── MX ────────────────────────────────────────────────────────────
        // Value format: "priority exchange"  e.g.  "10 mail.example.com."
        RecordType::MX => {
            let mut parts = value.splitn(2, ' ');
            let prio: u16 = parts.next()
                .context("MX: missing priority")?
                .trim().parse()
                .context("MX: priority must be a u16")?;
            let exchange = parts.next().context("MX: missing exchange")?.trim();
            let exchange_name = Name::from_str(&ensure_fqdn(exchange))
                .context("MX: invalid exchange name")?;
            RData::MX(MX::new(prio, exchange_name))
        }

        // ── TXT ───────────────────────────────────────────────────────────
        // Separate multiple strings with '|'
        // e.g.  "v=spf1 include:example.com ~all"
        //        or with two strings: "v=spf1 ~all|another string"
        RecordType::TXT => {
            let strings: Vec<String> = value.split('|')
                .map(|s| s.trim().to_string())
                .collect();
            RData::TXT(TXT::new(strings))
        }

        // ── SRV ───────────────────────────────────────────────────────────
        // Value format: "priority weight port target"
        RecordType::SRV => {
            let mut parts = value.splitn(4, ' ');
            let priority: u16 = parts.next().context("SRV: missing priority")?.trim().parse()
                .context("SRV: priority must be u16")?;
            let weight:   u16 = parts.next().context("SRV: missing weight")?.trim().parse()
                .context("SRV: weight must be u16")?;
            let port:     u16 = parts.next().context("SRV: missing port")?.trim().parse()
                .context("SRV: port must be u16")?;
            let target_str = parts.next().context("SRV: missing target")?.trim();
            let target = Name::from_str(&ensure_fqdn(target_str))
                .context("SRV: invalid target name")?;
            RData::SRV(SRV::new(priority, weight, port, target))
        }

        // ── SOA ───────────────────────────────────────────────────────────
        // Value format: "mname rname serial refresh retry expire minimum"
        RecordType::SOA => {
            let p: Vec<&str> = value.split_whitespace().collect();
            anyhow::ensure!(p.len() >= 7,
                "SOA: expected 7 fields (mname rname serial refresh retry expire minimum), got {}",
                p.len());
            let mname   = Name::from_str(&ensure_fqdn(p[0])).context("SOA: invalid mname")?;
            let rname   = Name::from_str(&ensure_fqdn(p[1])).context("SOA: invalid rname")?;
            let serial:  u32 = p[2].parse().context("SOA: serial must be u32")?;
            let refresh: i32 = p[3].parse().context("SOA: refresh must be i32")?;
            let retry:   i32 = p[4].parse().context("SOA: retry must be i32")?;
            let expire:  i32 = p[5].parse().context("SOA: expire must be i32")?;
            let minimum: u32 = p[6].parse().context("SOA: minimum must be u32")?;
            RData::SOA(SOA::new(mname, rname, serial, refresh, retry, expire, minimum))
        }

        t => anyhow::bail!(
            "Record type {t:?} is not supported in static records. \
             Supported: A, AAAA, CNAME, MX, NS, PTR, TXT, SRV, SOA"
        ),
    };

    // We must explicitly set the record type because Record::new() initialises
    // rr_type to RecordType::NULL and set_data() alone does not update it.
    let mut rec = Record::new();
    rec.set_name(dns_name)
       .set_ttl(ttl)
       .set_dns_class(DNSClass::IN)
       .set_rr_type(rtype)
       .set_data(Some(rdata));
    Ok(rec)
}
