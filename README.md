# dns-forwarder

[中文](README.zh.md)

A high-performance DNS forwarder with rule-based routing, written in Rust.

## Features

- **Rule-based upstream routing** — Route DNS queries to different upstream servers based on domain suffix matching. Perfect for split-horizon DNS or directing specific domains through specific resolvers.
- **AAAA record blocking** — Optionally block IPv6 (AAAA) responses for domains matched by a rule, returning an SOA (Start of Authority) response instead. Useful in IPv4-only networks.
- **nftables integration** — Automatically add resolved A-record IP addresses to nftables sets, enabling dynamic firewall or policy-routing rules that track DNS resolution results.
- **DNS caching** — In-memory TTL cache with configurable capacity and TTL, reducing upstream latency for frequently queried domains.
- **Local domain resolution** — Static host-like mappings for local domains without needing an upstream query.
- **Fast suffix matching** — Uses a trie data structure for efficient domain suffix lookup, handling large domain lists with minimal overhead.
- **Async I/O** — Built on Tokio for high-concurrency UDP processing.

## Why dns-forwarder

- **Minimal and focused** — A single ~600 line binary. No scripting engines, no plugin systems. Just DNS forwarding done well.
- **Rust performance** — Predictable latency and low memory footprint, with no garbage collection pauses.
- **Simple TOML configuration** — Rules, upstreams, and options are defined in a single, easy-to-read config file.
- **Composable with nftables** — The nftables integration turns DNS responses into actionable firewall rules, enabling workflows like geo-based policy routing or dynamic IP allowlisting.

## Usage

### Configuration

Create a `config.toml`:

```toml
listen = "127.0.0.1:5354"
upstream = ["8.8.8.8", "114.114.114.114"]

[[rules]]
domain_files = ["domains/gfw.txt"]
upstreams = ["1.1.1.1"]
block_aaaa = true
nft_set = "inet fw xip"

[[rules]]
domain_files = ["domains/internal.txt"]
upstreams = ["10.0.0.1"]
```

- **listen** — Address and port the forwarder binds to.
- **upstream** — Default upstream DNS servers (used when no rule matches).
- **rules[].domain_files** — Files containing domain suffixes (one per line), e.g. `google.com` matches `www.google.com`.
- **rules[].upstreams** — Upstream servers for domains matching this rule.
- **rules[].block_aaaa** — If `true`, AAAA responses are replaced with an SOA response, effectively disabling IPv6 for matched domains.
- **rules[].nft_set** — Optional nftables set spec (`family table set`). A-record IPs from matching domains are added to this set.
- **local_domain** — Optional path to a file with `domain=ip` lines for local resolution.

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
