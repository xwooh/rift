# rift

`rift` 是一个 Rust CLI 工具，用于从 VPS 的网络视角发现“附近域名”，并基于 TLS 能力、延迟和 CDN 信号进行排名。

## 功能

- 通过附近 IPv4 网络动态扫描自动收集候选域名。
- 检测 TLS 指标：证书可用性、TLS 1.3、X25519、SNI/域名匹配。
- 检测 HTTP 指标：HTTP/2 支持与状态码探测。
- 检测 CDN 指标：证书签发者、HTTP 头、DNS CNAME 链与 IP/ASN 启发式信号。
- 统计延迟指标：TCP RTT 与 TLS 握手 RTT。
- 输出终端排名表，并支持导出 CSV。

## 构建

```bash
cargo build --release
```

## 工作流程

默认模式（不传 `--domains-file`）会执行：

1. 检测本机 IPv4 锚点（或使用 `--scan-anchor-ip`）。
2. 对附近 IPv4 前缀进行采样并探测 `443` 端口连通性。
3. 从可连通 IP 的证书 SAN/CN 中提取域名。
4. 对提取域名去重后执行完整探测。
5. 排序并输出结果。

如果传入 `--domains-file`，则跳过动态发现，直接使用文件中的域名。

## 快速开始

默认动态发现：

```bash
cargo run --release
```

指定扫描锚点 IP：

```bash
cargo run --release -- \
  --scan-anchor-ip 203.0.113.10 \
  --scan-prefix-len 20 \
  --scan-neighbor-prefixes 1
```

使用自定义域名文件：

```bash
cargo run --release -- \
  --domains-file domains.sample.txt \
  --top 30 \
  --output-csv report.csv
```

## 更多命令示例

快速冒烟验证（小规模扫描 + 短超时）：

```bash
cargo run --release -- \
  --scan-anchor-ip 203.0.113.10 \
  --scan-samples-per-prefix 64 \
  --max-open-ips 20 \
  --max-probe-domains 40 \
  --top 10 \
  --tcp-timeout-ms 500 \
  --tls-timeout-ms 800 \
  --http-timeout-ms 800
```

深度扫描（高覆盖）：

```bash
cargo run --release -- \
  --scan-anchor-ip 203.0.113.10 \
  --scan-prefix-len 20 \
  --scan-neighbor-prefixes 2 \
  --scan-samples-per-prefix 2048 \
  --max-open-ips 500 \
  --discovered-domains-limit 10000 \
  --max-probe-domains 800 \
  --max-nearby-domains 300 \
  --top 100
```

仅导出前 20 名到 CSV：

```bash
cargo run --release -- \
  --top 20 \
  --output-csv report-top20.csv
```

文件模式 + 自定义阈值：

```bash
cargo run --release -- \
  --domains-file domains.sample.txt \
  --nearby-rtt-ms 180 \
  --max-nearby-domains 80 \
  --concurrency 40 \
  --top 30
```

保留非 `200` 域名（默认不保留）：

```bash
cargo run --release -- \
  --include-non-200 \
  --top 50
```

## 域名文件格式

每行一个域名：

```txt
google.com
github.com
cloudflare.com
```

空行和 `#` 注释会被忽略。

## CLI 参数

输入与输出：

- `--domains-file <PATH>`：使用文件作为域名输入源。
- `--output-csv <PATH>`：导出排名结果到 CSV。

动态发现参数：

- `--scan-prefix-len <N>`（默认：`20`）：扫描使用的 IPv4 前缀长度。
- `--scan-anchor-ip <IPV4>`：手动指定扫描锚点，跳过自动检测。
- `--scan-neighbor-prefixes <N>`（默认：`1`）：左右两侧相邻前缀数量。
- `--scan-samples-per-prefix <N>`（默认：`1024`）：每个前缀采样 IP 数量。
- `--max-open-ips <N>`（默认：`260`）：证书提取阶段保留的开放 HTTPS IP 上限。
- `--ip-discovery-rtt-ms <N>`（默认：`1200`）：IP 发现阶段 RTT 阈值。
- `--discovered-domains-limit <N>`（默认：`5000`）：动态发现产出的域名上限。

域名探测与排名参数：

- `--max-probe-domains <N>`（默认：`300`）：进入域名探测阶段的候选域名上限。
- `--max-nearby-domains <N>`（默认：`120`）：附近筛选后保留域名上限。
- `--nearby-rtt-ms <N>`（默认：`250`）：域名附近 RTT 阈值。
- `--top <N>`（默认：`40`）：最终输出前 N 名。
- `--concurrency <N>`（默认：`20`）：异步探测并发数。
- `--tcp-timeout-ms <N>`（默认：`1500`）：TCP 连接超时。
- `--tls-timeout-ms <N>`（默认：`2500`）：TLS 握手超时。
- `--http-timeout-ms <N>`（默认：`3000`）：HTTPS 请求超时。
- `--dns-timeout-ms <N>`（默认：`1500`）：CNAME/ASN 检测相关 DNS 查询超时。
- `--include-non-200`（默认：关闭）：是否在最终结果中保留 HTTP 非 `200` 或 HTTPS 请求失败的域名。

## 输出字段

- `Rank`：排名。
- `Domain`：域名。
- `TCP(ms)`：到 `443` 的最佳 TCP RTT。
- `TLS(ms)`：TLS 握手 RTT。
- `TLS1.3`：是否协商到 TLS 1.3。
- `X25519`：仅 X25519 握手是否成功。
- `H2`：是否支持 HTTP/2。
- `SNI`：证书域名是否匹配 SNI/目标域名。
- `HTTP`：HTTPS 响应状态码是否严格等于 `200`。
- `HTTPCode`：HTTPS 响应状态码。
- `CDN`：是否检测到 CDN 信号。
- `Score`：最终评分（`0..=100`）。

## 排名规则

评分维度包含：

- TLS 证书可用性
- TLS 1.3 支持
- X25519 支持
- HTTP/2 支持
- SNI/域名匹配
- CDN 信号惩罚（检测到 CDN 会扣分）
- TLS 握手延迟得分
- TCP RTT 延迟得分
- HTTP 可用性惩罚（HTTP 非 `200` 或 HTTPS 请求失败会降分）

同分时排序规则：

1. 分数高优先
2. TLS 握手 RTT 低优先
3. TCP RTT 低优先
4. 域名字典序小优先

## 排错指南

- `Failed to detect local IPv4 address`：请手动指定 `--scan-anchor-ip <你的VPS IPv4>`。
- `Dynamic discovery returned no domains`：提高 `--scan-samples-per-prefix`、`--scan-neighbor-prefixes` 或 `--max-open-ips`。
- 结果里 `503` 过多：保持默认过滤（非 `200` 会被过滤），或使用 `--include-non-200` 以便排查这些站点。
- 扫描耗时过长：降低 `--scan-samples-per-prefix`、`--max-probe-domains`、`--top`，并按需调整 `--concurrency`。
- 结果为空：检查本机到外网 `443` 的连通性、DNS 与防火墙策略。

## 注意事项

- 为了覆盖更多端点能力，TLS 探测阶段会关闭证书链校验。
- CDN 判断基于启发式规则（证书、头部、DNS CNAME、IP/ASN），可能误判或漏判。
- ASN 查询依赖 Team Cymru 的 DNS 服务，可能受本地 DNS 策略或网络限制影响。
- 动态发现依赖当前时段与路由状态，多次运行结果可能不同。

## 开源协议

本项目采用 MIT License（`MIT`）。
详见 `LICENSE` 文件。
