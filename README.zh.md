# dns-forwarder

[English](README.md)

一个用 Rust 编写的高性能 DNS 转发器，支持基于规则的域名分流。

## 功能

- **基于规则的上游分流** — 根据域名后缀匹配，将 DNS 查询路由到不同的上游服务器。适合分流解析或为特定域名指定专用解析器。
- **AAAA 记录屏蔽** — 可对匹配规则的域名屏蔽 IPv6（AAAA）响应，返回 SOA 记录。适用于纯 IPv4 网络环境。
- **nftables 集成** — 自动将解析得到的 A 记录 IP 地址添加到 nftables 集合中，实现基于 DNS 解析结果的动态防火墙或策略路由规则。
- **DNS 缓存** — 内存 TTL 缓存，容量和过期时间可配置，减少常用域名的上游查询延迟。
- **本地域名解析** — 支持静态 hosts 式映射，无需上游查询即可解析本地域名。
- **高效后缀匹配** — 使用 trie 数据结构进行域名后缀查找，即使是大规模域名列表也能保持低开销。
- **异步 I/O** — 基于 Tokio 构建，支持高并发 UDP 处理。

## 优势

- **极简专注** — 仅约 600 行代码的二进制程序。没有脚本引擎，没有插件系统，只做好 DNS 转发这一件事。
- **Rust 性能** — 可预测的低延迟和低内存占用，无垃圾回收停顿。
- **简洁的 TOML 配置** — 规则、上游服务器和选项都定义在一个易于阅读的配置文件中。
- **与 nftables 协同** — nftables 集成将 DNS 响应转化为可操作的防火墙规则，可实现基于地域的策略路由或动态 IP 白名单等工作流。

## 使用说明

### 配置

创建 `config.toml`：

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

- **listen** — 转发器绑定的地址和端口。
- **upstream** — 默认上游 DNS 服务器（无规则匹配时使用）。
- **rules[].domain_files** — 域名后缀文件（每行一个），例如 `google.com` 会匹配 `www.google.com`。
- **rules[].upstreams** — 匹配该规则的域名使用的上游服务器。
- **rules[].block_aaaa** — 若为 `true`，AAAA 响应会被替换为 SOA 响应，从而对匹配的域名禁用 IPv6。
- **rules[].nft_set** — 可选的 nftables 集合描述（格式为 `family table set`）。匹配域名的 A 记录 IP 会被添加到该集合中。
- **local_domain** — 可选的本地解析文件路径，格式为 `域名=IP`。

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
