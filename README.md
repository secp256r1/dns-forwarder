# dns-forwarder

[中文](README.zh.md)

A high-performance DNS forwarder with rule-based routing, written in Rust.

## Features

- **Typed rules** — Each rule has a `type` that determines its behavior: `forward` (upstream routing), `block` (NXDOMAIN), `local` (static mapping), or `cname` (server-side CNAME chasing).
- **Rule-based upstream routing** — Route DNS queries to different upstream servers based on domain suffix matching. Perfect for split-horizon DNS or directing specific domains through specific resolvers.
- **Domain blocking** — Return NXDOMAIN for domains matched by `block` rules. Private suffixes (`.lan`, `.local`, `.home.arpa`, `.corp`, `.internal`) are blocked by default.
- **CNAME chasing** — The `cname` rule type resolves queries by forwarding a rewritten query (targeting a domain from `cname_list`) to the default server, returning the final A/AAAA response directly.
- **AAAA record blocking** — Optionally block IPv6 (AAAA) responses for domains matched by a `forward` rule, returning an SOA response instead. Useful in IPv4-only networks.
- **nftables integration** — Automatically add resolved A-record IP addresses to nftables sets, enabling dynamic firewall or policy-routing rules that track DNS resolution results.
- **DNS caching** — In-memory TTL cache that respects upstream TTL values, with a configurable `max_ttl` cap.
- **Local domain resolution** — Static host-like mappings for local domains without needing an upstream query.
- **Fast suffix matching** — Uses a trie data structure for efficient domain suffix lookup, handling large domain lists with minimal overhead.
- **Async I/O** — Built on Tokio for high-concurrency UDP processing.

## Why dns-forwarder

- **Minimal and focused** — A single binary with no scripting engines or plugin systems. Just DNS forwarding done well.
- **Rust performance** — Predictable latency and low memory footprint, with no garbage collection pauses.
- **Simple TOML configuration** — Rules, upstreams, and options are defined in a single, easy-to-read config file.
- **Composable with nftables** — The nftables integration turns DNS responses into actionable firewall rules, enabling workflows like geo-based policy routing or dynamic IP allowlisting.

## Usage

### Configuration

Create a `config.toml`:

```toml
listen = "127.0.0.1:5354"
default_server = ["8.8.8.8", "114.114.114.114"]

[cache]
max_entries = 100000
max_ttl = 3600

# Forward matching domains to specific upstreams
[[rules]]
name = "gfw"
type = "forward"
domain_files = ["domains/gfw.txt"]
upstreams = ["1.1.1.1"]
block_aaaa = true
nft_set = "inet fw xip"

# Return NXDOMAIN for matching domains
[[rules]]
name = "ads"
type = "block"
domain_files = ["domains/ads.txt"]

# Static local domain resolution
[[rules]]
name = "internal"
type = "local"
domain_files = ["domains/local.txt"]

# CNAME chasing: resolve queries by rewriting to a target domain
[[rules]]
name = "alias"
type = "cname"
domain_files = ["domains/alias.txt"]
cname_list = ["real-server.example.com"]
```

#### Field reference

| Field | Applies to | Description |
|---|---|---|
| `listen` | global | Address and port the forwarder binds to. |
| `default_server` | global | Default upstream DNS servers (used when no forward rule matches). |
| `cache.max_entries` | global | Maximum number of cached responses. |
| `cache.max_ttl` | global | Maximum TTL (seconds) for cached responses. |
| `rules[].name` | all | Optional rule name for logging. |
| `rules[].type` | all | Rule type: `forward`, `block`, `local`, or `cname`. |
| `rules[].domain_files` | all | Files containing domain suffixes (one per line), e.g. `google.com` matches `www.google.com`. |
| `rules[].upstreams` | `forward` | Upstream servers for domains matching this rule. |
| `rules[].block_aaaa` | `forward` | If `true`, AAAA responses are replaced with an SOA response for matched domains. |
| `rules[].nft_set` | `forward` | Optional nftables set spec (`family table set`). A-record IPs from matching domains are added to this set. |
| `rules[].cname_list` | `cname` | Target domains to rewrite queries to. One is chosen at random per match. |

#### Private domain blocking

The following private-use domain suffixes are blocked (return NXDOMAIN) by default without any configuration:
`.lan`, `.local`, `.home.arpa`, `.corp`, `.internal`

### Running

```bash
cargo build --release
./target/release/dns-forwarder config.toml
```

Configure your system or application to use `127.0.0.1:5354` as the DNS server.

## License

MIT

## Acknowledgments

This project was inspired by:

- [smartdns](https://github.com/pymumu/smartdns) — A local DNS server that returns the fastest IP for the best experience.
- [chinadns-ng](https://github.com/zfl9/chinadns-ng) — A next-generation ChinaDNS with domain-based routing and chnroute-based split resolution.
