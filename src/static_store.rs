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
///   A      → IPv4 address          e.g.  192.168.1.1
///   AAAA   → IPv6 address          e.g.  ::1
///   CNAME  → target FQDN           e.g.  www.example.com.
///   NS     → name server FQDN      e.g.  ns1.example.com.
///   PTR    → pointer FQDN          e.g.  host.example.com.
///   MX     → priority SP exchange  e.g.  10 mail.example.com.
///   TXT    → text (| separates multiple strings)  e.g.  v=spf1 ~all
///   SRV    → priority SP weight SP port SP target  e.g.  10 20 443 svc.example.com.
///   SOA    → mname SP rname SP serial SP refresh SP retry SP expire SP minimum
///   CAA    → flags SP tag SP value  e.g.  0 issue "letsencrypt.org"
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
    count:      usize,
}

impl StaticStore {
    // ── Construction ──────────────────────────────────────────────────────

    pub fn load(path: &str) -> Result<Arc<Self>> {
        let records:    DashMap<(String, RecordType), Vec<Record>> = DashMap::new();
        let domain_set: DashMap<String, ()>                        = DashMap::new();
        let mut count = 0usize;

        if !std::path::Path::new(path).exists() {
            warn!("Static records file '{}' not found – running without static overrides", path);
            return Ok(Arc::new(Self { records, domain_set, count: 0 }));
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
                None    => { warn!("CSV line {}: unknown type '{}'", line_idx + 2, row.rtype); continue; }
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
        Ok(Arc::new(Self { records, domain_set, count }))
    }

    // ── Public API ────────────────────────────────────────────────────────

    /// Return the records for `(name, rtype)`, or `None` if no exact match.
    pub fn lookup(&self, name: &str, rtype: RecordType) -> Option<Vec<Record>> {
        let key = (normalize(name), rtype);
        self.records.get(&key).map(|v| v.clone())
    }

    /// Return true if the store has *any* record for this name (any type).
    /// Used to distinguish NOERROR-empty from NXDOMAIN.
    pub fn has_domain(&self, name: &str) -> bool {
        self.domain_set.contains_key(&normalize(name))
    }

    pub fn len(&self) -> usize {
        self.count
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn normalize(name: &str) -> String {
    name.to_lowercase().trim_end_matches('.').to_string()
}

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
        "CAA"   => Some(RecordType::CAA),
        "NAPTR" => Some(RecordType::NAPTR),
        _       => None,
    }
}

fn build_record(name: &str, rtype: RecordType, ttl: u32, value: &str) -> Result<Record> {
    let dns_name = Name::from_str(&ensure_fqdn(name))
        .with_context(|| format!("Invalid domain '{name}'"))?;

    let rdata: RData = match rtype {
        // ── A ─────────────────────────────────────────────────────────────
        RecordType::A => {
            let ip: Ipv4Addr = value.trim().parse()
                .with_context(|| format!("Invalid IPv4 '{value}'"))?;
            RData::A(A(ip))
        }

        // ── AAAA ──────────────────────────────────────────────────────────
        RecordType::AAAA => {
            let ip: Ipv6Addr = value.trim().parse()
                .with_context(|| format!("Invalid IPv6 '{value}'"))?;
            RData::AAAA(AAAA(ip))
        }

        // ── CNAME ─────────────────────────────────────────────────────────
        RecordType::CNAME => {
            let target = Name::from_str(&ensure_fqdn(value.trim()))
                .with_context(|| "Invalid CNAME target")?;
            RData::CNAME(CNAME(target))
        }

        // ── NS ────────────────────────────────────────────────────────────
        RecordType::NS => {
            let ns = Name::from_str(&ensure_fqdn(value.trim()))
                .with_context(|| "Invalid NS name")?;
            RData::NS(NS(ns))
        }

        // ── PTR ───────────────────────────────────────────────────────────
        RecordType::PTR => {
            let ptr = Name::from_str(&ensure_fqdn(value.trim()))
                .with_context(|| "Invalid PTR name")?;
            RData::PTR(PTR(ptr))
        }

        // ── MX ────────────────────────────────────────────────────────────
        // Value: "priority exchange"  e.g.  "10 mail.example.com."
        RecordType::MX => {
            let mut parts = value.splitn(2, ' ');
            let prio: u16 = parts.next().context("MX: missing priority")?
                .trim().parse().context("MX: invalid priority")?;
            let exchange = parts.next().context("MX: missing exchange")?.trim();
            let name = Name::from_str(&ensure_fqdn(exchange))
                .context("MX: invalid exchange name")?;
            RData::MX(MX::new(prio, name))
        }

        // ── TXT ───────────────────────────────────────────────────────────
        // Multiple strings separated by '|'
        RecordType::TXT => {
            let strings: Vec<String> = value.split('|')
                .map(|s| s.trim().to_string())
                .collect();
            RData::TXT(TXT::new(strings))
        }

        // ── SRV ───────────────────────────────────────────────────────────
        // Value: "priority weight port target"
        RecordType::SRV => {
            let mut parts = value.splitn(4, ' ');
            let prio:   u16 = parts.next().context("SRV: missing priority")?.trim().parse()?;
            let weight: u16 = parts.next().context("SRV: missing weight")?.trim().parse()?;
            let port:   u16 = parts.next().context("SRV: missing port")?.trim().parse()?;
            let target = parts.next().context("SRV: missing target")?.trim();
            let target = Name::from_str(&ensure_fqdn(target)).context("SRV: invalid target")?;
            RData::SRV(SRV::new(prio, weight, port, target))
        }

        // ── SOA ───────────────────────────────────────────────────────────
        // Value: "mname rname serial refresh retry expire minimum"
        RecordType::SOA => {
            let p: Vec<&str> = value.split_whitespace().collect();
            anyhow::ensure!(p.len() >= 7, "SOA: expected 7 fields");
            let mname   = Name::from_str(&ensure_fqdn(p[0]))?;
            let rname   = Name::from_str(&ensure_fqdn(p[1]))?;
            let serial:  u32 = p[2].parse()?;
            let refresh: i32 = p[3].parse()?;
            let retry:   i32 = p[4].parse()?;
            let expire:  i32 = p[5].parse()?;
            let minimum: u32 = p[6].parse()?;
            RData::SOA(SOA::new(mname, rname, serial, refresh, retry, expire, minimum))
        }

        t => anyhow::bail!("Record type {t:?} is not yet supported in static records"),
    };

    // Build the record.  We must set the type explicitly because Record::new()
    // initialises rr_type to RecordType::NULL and set_data() does not update it.
    let mut rec = Record::new();
    rec.set_name(dns_name)
       .set_ttl(ttl)
       .set_dns_class(DNSClass::IN)
       .set_rr_type(rtype)     // <-- must match the RData variant
       .set_data(Some(rdata));
    Ok(rec)
}
