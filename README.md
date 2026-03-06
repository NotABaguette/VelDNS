<div align="center">

# 🌐 VelDNS

**High-performance, concurrent DNS server written in Rust**

[![Build](https://github.com/your-org/veldns/actions/workflows/release.yml/badge.svg)](https://github.com/your-org/veldns/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

</div>

---

## ✨ Features

| Feature | Details |
|---------|---------|
| **Static record overrides** | Serve hand-crafted records from a CSV file; those domains are *never* forwarded upstream |
| **Upstream mirroring** | Forward everything else to configurable primary + fallback resolvers |
| **Parallel upstream** | Query all primary servers simultaneously; return the fastest response |
| **In-memory TTL cache** | Lock-free `DashMap` cache; configurable size, min/max TTL, negative TTL |
| **DNSSEC-aware** | Sets DO bit, passes RRSIG / DNSKEY / DS / NSEC / NSEC3 records transparently |
| **SO_REUSEPORT workers** | One UDP socket per CPU core; kernel distributes packets (RSS-like) |
| **TCP DNS** | RFC 1035 TCP support for large responses and zone transfers |
| **High throughput** | Designed for millions of queries/second on modern hardware |
| **Split-horizon DNS** | Same domain can resolve differently inside vs. outside your network |
| **Blocklist / sinkhole** | Return `0.0.0.0` for ad/tracker domains |

---

## 🚀 Quick start

### Download a pre-built binary

Visit the [Releases](https://github.com/your-org/veldns/releases) page and download the archive for your platform.  Each archive contains the binary, a sample config, and a sample static-records CSV.

```bash
tar -xzf veldns-*-x86_64-unknown-linux-musl.tar.gz
cd veldns-*/
sudo cp veldns /usr/local/bin/
veldns --help
```

### Build from source

```bash
# Prerequisites: Rust 1.75+ (https://rustup.rs)
git clone https://github.com/your-org/veldns.git
cd veldns
cargo build --release
./target/release/veldns --config config.toml
```

---

## ⚙️ Configuration

VelDNS is configured through a [TOML](https://toml.io) file.  Copy `config.toml.example` and edit to taste.

```bash
cp config.toml.example /etc/veldns/config.toml
veldns --config /etc/veldns/config.toml
```

The config path can also be supplied via the `VELDNS_CONFIG` environment variable.

### Full annotated example

```toml
[server]
bind        = ["0.0.0.0:53"]   # also "[::]:53" for IPv6
workers     = 0                 # 0 = auto (one per CPU core)
max_udp_payload = 4096
tcp         = true

[upstream]
primary  = ["8.8.8.8:53", "8.8.4.4:53"]
fallback = ["1.1.1.1:53", "9.9.9.9:53"]
timeout_ms = 3000
retries    = 2
parallel   = true   # race all primaries; return fastest

[cache]
enabled     = true
max_entries = 1_000_000
min_ttl     = 30
max_ttl     = 86400
negative_ttl = 300

[dnssec]
enabled  = true    # forward DNSSEC records + set DO bit
validate = false   # full chain-of-trust validation (adds latency)

[static_records]
file          = "/etc/veldns/static_records.csv"
authoritative = true

[logging]
level       = "info"
log_queries = false   # set true for per-query debug logging
```

---

## 📄 Static records CSV

The CSV file lets you override DNS for any domain.  Responses are served directly—upstream servers are **never** consulted for these names.

### Format

```
domain,type,ttl,value
```

### Supported record types

| Type  | Value format | Example |
|-------|-------------|---------|
| `A`   | IPv4 address | `192.168.1.10` |
| `AAAA`| IPv6 address | `fd00::10` |
| `CNAME`| FQDN | `target.example.com.` |
| `MX`  | `priority exchange` | `10 mail.example.com.` |
| `NS`  | FQDN | `ns1.example.com.` |
| `PTR` | FQDN | `host.example.com.` |
| `TXT` | text; `\|` separates multiple strings | `v=spf1 ~all` |
| `SRV` | `priority weight port target` | `10 20 443 svc.example.com.` |
| `SOA` | `mname rname serial refresh retry expire minimum` | see example file |

### Example entries

```csv
domain,type,ttl,value

# Internal host
nas.home,A,300,192.168.1.20
nas.home,AAAA,300,fd00::20

# CNAME alias
files.home,CNAME,300,nas.home.

# Block ads (sinkhole)
ads.tracker.com,A,60,0.0.0.0

# Split-horizon – return internal IP for an otherwise-public domain
api.mycompany.com,A,60,10.0.0.5
```

Lines starting with `#` are comments.  Blank lines are ignored.

---

## 🏗 Architecture

```
                  ┌─────────────────────────────────────────────┐
                  │                  VelDNS                      │
    UDP packets   │                                              │
   ──────────────▶│  SO_REUSEPORT UDP socket × N workers         │
                  │  (kernel fan-out → one socket per CPU core)  │
                  │                  │                           │
                  │          tokio::spawn per query              │
                  │                  │                           │
                  │     ┌────────────▼─────────────┐            │
                  │     │       Handler              │            │
                  │     │                            │            │
                  │     │  1. Parse DNS message      │            │
                  │     │  2. Lookup static store ───┼──▶ AA=1   │
                  │     │     (DashMap, O(1))         │    resp   │
                  │     │  3. Lookup cache ───────────┼──▶ TTL-  │
                  │     │     (DashMap, O(1))         │    patched│
                  │     │  4. Forward upstream ───────┼──▶ cache │
                  │     │     (parallel UDP race)     │    + resp │
                  │     └────────────────────────────┘            │
                  │                                              │
                  │  TCP listener (RFC 1035 §4.2.2)              │
                  └─────────────────────────────────────────────┘
```

### Why it's fast

- **Zero shared mutable state on the hot path** – static store and cache are `DashMap` (shard-locked concurrent hash maps); no global lock is ever held while handling a query.
- **SO_REUSEPORT** – multiple sockets bound to the same port; the OS kernel distributes incoming packets without any userspace coordination.
- **One tokio task per query** – the receive loop never blocks; slow upstream I/O runs concurrently in the async work-stealing scheduler.
- **Parallel upstream** – all primary servers are raced; the median latency replaces the worst-case.
- **No unnecessary copies** – upstream responses are forwarded as raw bytes; only the 2-byte ID field is patched.

---

## 📦 Supported platforms

| Platform | Target triple |
|----------|--------------|
| Linux x86-64 (glibc)       | `x86_64-unknown-linux-gnu`      |
| Linux x86-64 (static musl) | `x86_64-unknown-linux-musl`     |
| Linux ARM64 (glibc)        | `aarch64-unknown-linux-gnu`     |
| Linux ARM64 (static musl)  | `aarch64-unknown-linux-musl`    |
| Linux ARMv7                | `armv7-unknown-linux-gnueabihf` |
| Linux i686                 | `i686-unknown-linux-gnu`        |
| macOS Intel                | `x86_64-apple-darwin`           |
| macOS Apple Silicon        | `aarch64-apple-darwin`          |
| Windows x86-64             | `x86_64-pc-windows-msvc`        |
| Windows i686               | `i686-pc-windows-msvc`          |
| Windows ARM64              | `aarch64-pc-windows-msvc`       |
| FreeBSD x86-64             | `x86_64-unknown-freebsd`        |

---

## 🔒 Running on port 53

Port 53 requires elevated privileges on most systems.

```bash
# Linux – grant cap_net_bind_service instead of running as root
sudo setcap cap_net_bind_service=+ep /usr/local/bin/veldns
veldns --config /etc/veldns/config.toml

# macOS
sudo veldns --config /etc/veldns/config.toml
```

### systemd service

```ini
# /etc/systemd/system/veldns.service
[Unit]
Description=VelDNS
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=veldns
ExecStart=/usr/local/bin/veldns --config /etc/veldns/config.toml
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/etc/veldns

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now veldns
```

---

## 📊 Observability

VelDNS logs a one-liner stats summary every 30 seconds:

```
INFO stats qps=85420 total=1254891 static=12041 cached=1108230 upstream=134620
          failed=0 cache_hit=94.2% up_err=0 up_to=0 rx_mb=48.12 tx_mb=91.67
```

For per-query logging set `logging.log_queries = true` (verbose; development only).

The log level can be overridden at runtime without restarting:

```bash
VELDNS_LOG=debug veldns --config config.toml
```

---

## 🛠 Development

```bash
# Run tests
cargo test

# Run with debug logging
VELDNS_LOG=debug cargo run -- --config config.toml

# Build optimised release binary
cargo build --release
```

### Cross-compilation with `cross`

```bash
cargo install cross
cross build --release --target aarch64-unknown-linux-musl
```

---

## 📝 License

MIT – see [LICENSE](LICENSE).

---

## 🕵️ tunnel_mask — DNS Tunnel Traffic Masking

`tunnel_mask` lets VelDNS relay [dnstt](https://www.bamsoftware.com/software/dnstt/) or [slipstream](https://github.com/the-tcpdump-group/slipstream) tunnel traffic through any recursive resolver on port 53 as innocent-looking AAAA queries. No DoH, no HTTP, no direct connection to the server node — pure DNS the entire way.

### How it works

```
RESTRICTED NETWORK                        OPEN NETWORK
─────────────────────────────────────     ────────────────────────────────────
dnstt-client / slipstream-client          real dnstt / slipstream server
    │  long TXT query                         ▲  original query reconstructed
    ▼                                         │
VelDNS CLIENT NODE                        VelDNS SERVER NODE
(mode = "client")                         (mode = "server", auth NS for relay zone)
  1. Detect tunnel query                    1. Receive AAAA query from resolver
  2. Extract QNAME as raw payload           2. Decode fragment, buffer it
  3. Split into N fragments (~32 B each)    3. Non-final → dummy AAAA response
  4. Encode each as hex hash-looking QNAME  4. Final → wait for stragglers
  5. Send N AAAA queries to RESOLVER ──────▶   reassemble → forward upstream
  6. Wait for final AAAA response           5. Encode tunnel response into AAAA
  7. Decode AAAA records → tunnel response  6. Return AAAA data response
    │  AAAA queries via normal DNS:
    │  client → censoring resolver → NS lookup → VelDNS server node
    ▼
CENSORING RECURSIVE RESOLVER (e.g. 8.8.8.8)
  - Sees only ordinary AAAA queries for *.relay.example.net
  - Routes them to VelDNS server (authoritative NS for relay zone)
  - Receives valid AAAA responses — nothing appears broken
```

The client never connects to the server node directly. Every query looks like a CDN hash lookup (hex mode): `4fa20b91a7c2.030207100ae7.c4a9b2c1d3e5.relay.example.net`.

### Prerequisites

**1. DNS zone delegation** (at your registrar, before enabling):

```
A    ns1.relay.example.net   <your-server-public-IP>
NS   relay.example.net       ns1.relay.example.net
```

Replace `relay.example.net` with your chosen relay zone. All `*.relay.example.net` queries will now be routed to your server node by any recursive resolver in the world.

**2. Two VelDNS instances:**

| Instance | Network | `mode` | Also runs |
|----------|---------|--------|-----------|
| Client node | Restricted (censored) | `"client"` | dnstt-client / slipstream-client |
| Server node | Open (uncensored) | `"server"` | dnstt-server / slipstream-server |

### Configuration

**Client node** (`/etc/veldns/config.toml`):

```toml
[tunnel_mask]
enabled    = true
mode       = "client"
relay_zone = "relay.example.net"
encoding   = "hex"

# Send masked queries through the local recursive resolver, NOT directly
# to the server node.
resolver       = ["8.8.8.8:53"]
session_ttl_ms = 5000
max_qname_len  = 120
label_len      = 12
send_jitter_ms = [3, 15]

# Tell the detector about your tunnel zone for instant recognition
known_tunnel_zones = ["t.tunnel.example.com"]
auto_detect        = true
```

**Server node** (`/etc/veldns/config.toml`):

```toml
[server]
# Must be reachable as the authoritative NS for relay_zone.
bind = ["0.0.0.0:53"]

[tunnel_mask]
enabled    = true
mode       = "server"
relay_zone = "relay.example.net"
encoding   = "hex"          # must match client

upstream_addr        = "127.0.0.1:5353"  # real dnstt/slipstream server port
max_response_records = 10
dummy_ttl            = 60
response_ttl         = 30
final_spin_wait_ms   = 1200  # tolerate resolver/path jitter
```

### Capacity

With the default settings (`max_qname_len = 120`, `label_len = 12`, `relay_zone` = 18 chars):

| Direction | Per exchange | At 100 req/s |
|-----------|-------------|--------------|
| Upstream (client→server) | 32 B/fragment × 6 fragments = 192 B | ~3.2 KB/s |
| Downstream (server→client) | 10 × 16 B − 2 B = 158 B/response | ~15.8 KB/s |

A typical dnstt exchange (180 B query, 150 B response) uses **6 queries** through the resolver.

### Encoding modes

| Mode | QNAME looks like | Stealth |
|------|-----------------|---------|
| `hex` (default) | `4fa20b91a7c2.030207100ae7.relay.example.net` | ★★★ Indistinguishable from CDN hash lookups |
| `syllable` | `tm4fa20b91-02-07-16.cdn0042-img1337.relay.example.net` | ★★ Readable but has detectable `tm` prefix |

Use `hex` unless you have a specific reason not to.

### Compatibility with slipstream

Slipstream encodes QUIC payloads as base32 subdomains (e.g. `MFRA2YLNMFRA2YLN.t.example.com`). The detector scores these queries highly (long QNAME + high entropy + base32 saturation + TXT type) and intercepts them automatically. The QNAME bytes — already lowercased by the resolver — are carried through as-is; slipstream's base32 decoder is case-insensitive so this is transparent.

For high-latency links with slipstream, consider:

```toml
send_jitter_ms = [1, 5]
session_ttl_ms = 8000
```

### Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| Tunnel queries not intercepted on client | `auto_detect = false` and zone not in `known_tunnel_zones` | Add zone to `known_tunnel_zones` |
| Server returns SERVFAIL on final fragment | Earlier fragments arrived after the server wait window | Increase `final_spin_wait_ms` (server) and/or reduce `send_jitter_ms` spread (client) |
| Timeout on client | Relay zone NS delegation not working | Verify `dig NS relay.example.net` resolves to your server |
| Resolver caches dummy responses | Shouldn't happen — each query has a unique nonce in the QNAME | Verify `encoding = "hex"` on both nodes |

