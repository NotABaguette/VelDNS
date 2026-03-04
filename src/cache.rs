use crate::config::CacheConfig;
use dashmap::DashMap;
use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;
use std::time::{Duration, Instant};
use tracing::trace;

// ─────────────────────────────────────────────────────────────────────────────
// Key & Entry
// ─────────────────────────────────────────────────────────────────────────────

/// Cache lookup key.  Domains are stored lowercase without a trailing dot.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct CacheKey {
    pub name:   String,
    pub rtype:  RecordType,
    /// Keep separate cache entries for DO-bit vs non-DO queries so DNSSEC
    /// records are never served to a client that didn't ask for them.
    pub dnssec: bool,
}

#[derive(Clone)]
pub struct CacheEntry {
    /// Parsed DNS response (we store as Message so TTL patching is easy).
    pub message: Message,
    /// Minimum TTL from the answer section at insertion time.
    pub original_ttl: u32,
    /// Wall-clock time of insertion.
    pub inserted_at: Instant,
    /// Wall-clock expiry.
    pub expires_at: Instant,
    /// True for NXDOMAIN / SERVFAIL entries.
    pub negative: bool,
}

impl CacheEntry {
    /// How many seconds remain before this entry expires (clamped to 0).
    pub fn remaining_ttl(&self) -> u32 {
        let elapsed = self.inserted_at.elapsed().as_secs() as u32;
        self.original_ttl.saturating_sub(elapsed)
    }

    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cache
// ─────────────────────────────────────────────────────────────────────────────

pub struct DnsCache {
    entries: DashMap<CacheKey, CacheEntry>,
    cfg:     CacheConfig,
}

impl DnsCache {
    pub fn new(cfg: CacheConfig) -> Self {
        let cap = cfg.max_entries.next_power_of_two();
        Self {
            entries: DashMap::with_capacity(cap),
            cfg,
        }
    }

    // ── Read ──────────────────────────────────────────────────────────────

    /// Returns a cloned entry if it exists and has not yet expired.
    pub fn get(&self, key: &CacheKey) -> Option<CacheEntry> {
        if !self.cfg.enabled {
            return None;
        }
        let entry = self.entries.get(key)?;
        if entry.is_expired() {
            drop(entry);
            self.entries.remove(key);
            return None;
        }
        Some(entry.clone())
    }

    // ── Write ─────────────────────────────────────────────────────────────

    /// Cache a DNS response message.  Negative entries (NXDOMAIN / SERVFAIL)
    /// use `cfg.negative_ttl`; all other entries use the minimum record TTL
    /// clamped to [min_ttl, max_ttl].
    pub fn insert(&self, key: CacheKey, msg: Message, negative: bool) {
        if !self.cfg.enabled {
            return;
        }

        let ttl = if negative {
            self.cfg.negative_ttl
        } else {
            self.compute_ttl(&msg)
        };

        if ttl == 0 {
            return;
        }

        // Soft capacity enforcement: attempt a light sweep before inserting
        // rather than maintaining an expensive LRU list.
        if self.entries.len() >= self.cfg.max_entries {
            self.evict();
            if self.entries.len() >= self.cfg.max_entries {
                trace!("cache full, dropping entry for {:?}", key.name);
                return;
            }
        }

        let entry = CacheEntry {
            message:      msg,
            original_ttl: ttl,
            inserted_at:  Instant::now(),
            expires_at:   Instant::now() + Duration::from_secs(ttl as u64),
            negative,
        };

        self.entries.insert(key, entry);
    }

    // ── Maintenance ───────────────────────────────────────────────────────

    /// Remove all expired entries.  Called periodically from a background task.
    pub fn purge_expired(&self) {
        self.entries.retain(|_, v| !v.is_expired());
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    // ── Private ───────────────────────────────────────────────────────────

    fn compute_ttl(&self, msg: &Message) -> u32 {
        // Use the minimum TTL across all answer records.
        let min = msg.answers()
            .iter()
            .map(|r| r.ttl())
            .min()
            .unwrap_or(self.cfg.min_ttl);
        min.max(self.cfg.min_ttl).min(self.cfg.max_ttl)
    }

    /// Evict ~1 % of entries, preferring expired ones first.
    fn evict(&self) {
        let target = (self.cfg.max_entries / 100).max(64);
        let expired: Vec<_> = self.entries
            .iter()
            .filter(|e| e.is_expired())
            .map(|e| e.key().clone())
            .take(target)
            .collect();

        let removed = expired.len();
        for k in expired {
            self.entries.remove(&k);
        }

        // If we didn't find enough expired entries, evict arbitrary live ones.
        if removed < target {
            let extra: Vec<_> = self.entries
                .iter()
                .map(|e| e.key().clone())
                .take(target - removed)
                .collect();
            for k in extra {
                self.entries.remove(&k);
            }
        }
    }
}
