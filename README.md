# dns-forwarder

[中文](README.zh.md)

A high-performance DNS forwarder with rule-based routing, written in Rust (v0.2.0).

## Features

- **Typed rules** — Each rule has a `type` that determines its behavior: `forward` (upstream routing), `block` (NXDOMAIN), or `local` (static mapping).
- **Rule-based upstream routing** — Route DNS queries to different upstream servers based on domain suffix matching. Perfect for split-horizon DNS or directing specific domains through specific resolvers.
- **Domain blocking** — Return NXDOMAIN for domains matched by `block` rules. Private suffixes (`.lan`, `.local`, `.home.arpa`, `.corp`, `.internal`) are blocked by default.
- **Automatic CNAME chasing** — All `forward` rules automatically follow CNAME chains (up to 10 deep, with loop detection) and return the final A/AAAA response.
- **Dynamic CNAME domain learning** — CNAME targets discovered at runtime are dynamically associated with their `forward` rule, so subsequent queries to those targets are routed directly without explicit configuration.
- **AAAA record blocking** — Optionally block IPv6 (AAAA) responses for domains matched by a `forward` rule, returning an empty response instead. Useful in IPv4-only networks.
- **nftables integration** — Automatically add resolved A-record IP addresses to nftables sets, enabling dynamic firewall or policy-routing rules. IPs are added with a timeout of `TTL × 2`.
- **DNS caching** — In-memory LRU cache with configurable `max_entries`, `min_ttl` (floor), and `max_ttl` (cap).
- **Local domain resolution** — Static host-like mappings for local domains without needing an upstream query. Domain files use `domain = ip` format.
- **Fast suffix matching** — Uses a trie data structure for efficient domain suffix lookup, handling large domain lists with minimal overhead.
- **Random upstream selection** — Each query picks a random upstream from the rule's server list, improving load distribution.
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
min_ttl = 60
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

# Static local domain resolution (domain files use "domain = ip" format)
[[rules]]
name = "internal"
type = "local"
domain_files = ["domains/local.txt"]
```

#### Field reference

| Field | Applies to | Description |
|---|---|---|
| `listen` | global | Address and port the forwarder binds to. |
| `default_server` | global | Default upstream DNS servers (used when no forward rule matches). |
| `cache.max_entries` | global | Maximum number of cached responses. |
| `cache.min_ttl` | global | Minimum TTL (seconds) for cached responses. Upstream TTLs below this value are raised to this floor. |
| `cache.max_ttl` | global | Maximum TTL (seconds) for cached responses. Upstream TTLs above this value are capped. |
| `rules[].name` | all | Optional rule name for logging. |
| `rules[].type` | all | Rule type: `forward`, `block`, or `local`. |
| `rules[].domain_files` | all | Files containing domain suffixes (one per line, `#` for comments). For `local` rules, use `domain = ip` format per line. |
| `rules[].upstreams` | `forward` | Upstream servers for domains matching this rule. |
| `rules[].block_aaaa` | `forward` | If `true`, AAAA responses are replaced with an empty response for matched domains. |
| `rules[].nft_set` | `forward` | Optional nftables set spec (`family table set`). A-record IPs from matching domains are added to this set with timeout `TTL × 2`. |

#### Domain file formats

Domain files use plain text (one entry per line, `#` for comments):

- **`forward` / `block` rules** — One domain suffix per line:
  ```
  example.com
  google.com
  # this is a comment
  ```

- **`local` rules** — `domain = ip` format (spaces around `=` optional):
  ```
  router.lan = 192.168.1.1
  nas.lan = 192.168.1.100
  ```

#### CNAME chasing behavior

All `forward` rules automatically follow CNAME chains. When a CNAME response is received, the forwarder:
1. Follows the CNAME chain up to 10 levels deep (with loop detection).
2. Returns the final A/AAAA response directly, with the full CNAME chain included.
3. **Dynamically learns** the CNAME target domain — it is added to a runtime trie and associated with the same `forward` rule. Subsequent queries to that target are routed without needing to appear in any domain file.

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
