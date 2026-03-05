<div align="center">

# 🌐 VelDNS

**High-performance, concurrent DNS server written in Rust**

[![Build](https://github.com/notABaguette/veldns/actions/workflows/build-cross-release.yml/badge.svg)](https://github.com/notABaguette/veldns/actions)
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
| **Tunnel mask relay** | Optional client/server mode that disguises tunnel traffic as AAAA lookups routed through a recursive resolver |

---

## 🚀 Quick start

### Download a pre-built binary

Visit the [Releases](https://github.com/notABaguette/veldns/releases) page and download the archive for your platform.  Each archive contains the binary, a sample config, and a sample static-records CSV.

```bash
tar -xzf veldns-*-x86_64-unknown-linux-musl.tar.gz
cd veldns-*/
sudo cp veldns /usr/local/bin/
sudo mkdir /etc/veldns
veldns --help
```

### Build from source

```bash
# Prerequisites: Rust 1.75+ (https://rustup.rs)
git clone https://github.com/notABaguette/veldns.git
cd veldns
cargo build --release
./target/release/veldns --config config.toml
```

---

## ⚙️ Configuration

VelDNS is configured through a [TOML](https://toml.io) file.  Start from the repository's `config.toml` and edit to taste.

```bash
cp config.toml /etc/veldns/config.toml
veldns --config /etc/veldns/config.toml
```

The config path can also be supplied via the `VELDNS_CONFIG` environment variable.



### Tunnel mask mode (optional)

VelDNS can run in an optional `tunnel_mask` mode for dnstt/slipstream-style traffic shaping:

- **client mode** intercepts suspicious tunnel queries locally, fragments them, and emits masked `AAAA` queries to a normal recursive resolver.
- **server mode** (authoritative for your relay zone) reassembles fragments, forwards to your local tunnel server, and encodes the tunnel response back into `AAAA` answers.

Both sides stay on plain DNS/53 traffic patterns (no DoH/HTTP in this layer).

```toml
[tunnel_mask]
enabled    = true
mode       = "client"                # or "server"
relay_zone = "relay.example.net"
encoding   = "hex"                   # recommended

# client mode
resolver       = ["8.8.8.8:53"]
session_ttl_ms = 5000
max_qname_len  = 120
label_len      = 12
send_jitter_ms = [3, 15]

# server mode
upstream_addr        = "127.0.0.1:5353"
max_response_records = 10
dummy_ttl            = 60
response_ttl         = 30
```

Use this only when your DNS zone delegation is set so the server node is authoritative for `relay_zone`.

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
| Linux x86-64 (glibc) (Typical Linux VM)       | `x86_64-unknown-linux-gnu`      |
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
Just make sure to copy modified config.toml and static_records.csv into /etc/veldns before starting the service.

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

Use, modify and distribute as you like :)
