# dns-forwarder

[English](README.md)

一个用 Rust 编写的高性能 DNS 转发器，支持基于规则的域名分流。

## 功能

- **带类型的规则** — 每条规则都有 `type` 字段决定其行为：`forward`（上游转发）、`block`（NXDOMAIN 拦截）、`local`（静态映射）或 `cname`（服务端 CNAME 追踪）。
- **基于规则的上游分流** — 根据域名后缀匹配，将 DNS 查询路由到不同的上游服务器。适合分流解析或为特定域名指定专用解析器。
- **域名拦截** — 对 `block` 规则匹配的域名返回 NXDOMAIN。私有后缀（`.lan`、`.local`、`.home.arpa`、`.corp`、`.internal`）默认被拦截。
- **CNAME 追踪** — `cname` 规则将查询重写到 `cname_list` 中的目标域名，通过 `default_server` 解析后直接返回最终的 A/AAAA 结果。
- **AAAA 记录屏蔽** — 可对 `forward` 规则匹配的域名屏蔽 IPv6（AAAA）响应，返回 SOA 记录。适用于纯 IPv4 网络环境。
- **nftables 集成** — 自动将解析得到的 A 记录 IP 地址添加到 nftables 集合中，实现基于 DNS 解析结果的动态防火墙或策略路由规则。
- **DNS 缓存** — 内存 TTL 缓存，使用上游返回的 TTL 值，支持可配置的 `max_ttl` 上限。
- **本地域名解析** — 支持静态 hosts 式映射，无需上游查询即可解析本地域名。
- **高效后缀匹配** — 使用 trie 数据结构进行域名后缀查找，即使是大规模域名列表也能保持低开销。
- **异步 I/O** — 基于 Tokio 构建，支持高并发 UDP 处理。

## 优势

- **极简专注** — 单个二进制程序，没有脚本引擎或插件系统，只做好 DNS 转发这一件事。
- **Rust 性能** — 可预测的低延迟和低内存占用，无垃圾回收停顿。
- **简洁的 TOML 配置** — 规则、上游服务器和选项都定义在一个易于阅读的配置文件中。
- **与 nftables 协同** — nftables 集成将 DNS 响应转化为可操作的防火墙规则，可实现基于地域的策略路由或动态 IP 白名单等工作流。

## 使用说明

### 配置

创建 `config.toml`：

```toml
listen = "127.0.0.1:5354"
default_server = ["8.8.8.8", "114.114.114.114"]

[cache]
max_entries = 100000
max_ttl = 3600

# 将匹配的域名转发到特定上游
[[rules]]
name = "gfw"
type = "forward"
domain_files = ["domains/gfw.txt"]
upstreams = ["1.1.1.1"]
block_aaaa = true
nft_set = "inet fw xip"

# 对匹配的域名返回 NXDOMAIN
[[rules]]
name = "ads"
type = "block"
domain_files = ["domains/ads.txt"]

# 静态本地域名解析
[[rules]]
name = "internal"
type = "local"
domain_files = ["domains/local.txt"]

# CNAME 追踪：将查询重写到目标域名
[[rules]]
name = "alias"
type = "cname"
domain_files = ["domains/alias.txt"]
cname_list = ["real-server.example.com"]
```

#### 字段说明

| 字段 | 适用类型 | 说明 |
|---|---|---|
| `listen` | 全局 | 转发器绑定的地址和端口。 |
| `default_server` | 全局 | 默认上游 DNS 服务器（无 forward 规则匹配时使用）。 |
| `cache.max_entries` | 全局 | 最大缓存条目数。 |
| `cache.max_ttl` | 全局 | 缓存 TTL 上限（秒）。 |
| `rules[].name` | 全部 | 可选规则名称，用于日志。 |
| `rules[].type` | 全部 | 规则类型：`forward`、`block`、`local` 或 `cname`。 |
| `rules[].domain_files` | 全部 | 域名后缀文件（每行一个），例如 `google.com` 匹配 `www.google.com`。 |
| `rules[].upstreams` | `forward` | 匹配该规则的域名使用的上游服务器。 |
| `rules[].block_aaaa` | `forward` | 若为 `true`，对匹配的域名将 AAAA 响应替换为 SOA 响应。 |
| `rules[].nft_set` | `forward` | 可选的 nftables 集合描述（格式为 `family table set`）。匹配域名的 A 记录 IP 会被添加到该集合中。 |
| `rules[].cname_list` | `cname` | 目标域名列表，匹配时随机选择一个进行查询重写。 |

#### 私有域名拦截

以下私有域名后缀默认被拦截（返回 NXDOMAIN），无需任何配置：
`.lan`、`.local`、`.home.arpa`、`.corp`、`.internal`

### 运行

```bash
cargo build --release
./target/release/dns-forwarder config.toml
```

将系统或应用的 DNS 服务器设置为 `127.0.0.1:5354` 即可。

## 许可证

MIT

## 致谢

本项目受以下工具启发：

- [smartdns](https://github.com/pymumu/smartdns) — 一个能够返回最快 IP 的本地 DNS 服务器，提供最佳上网体验。
- [chinadns-ng](https://github.com/zfl9/chinadns-ng) — 下一代 ChinaDNS，支持基于域名的分流和 chnroute 分流解析。
