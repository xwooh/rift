# rift

`rift` is a Rust CLI that discovers nearby domains from a VPS network view and ranks them with TLS capability, latency, and CDN signals.

> [`中文文档`](README.zh-CN.md)

## Features

- Dynamic candidate discovery from nearby IPv4 network scanning.
- TLS checks: certificate presence, TLS 1.3, X25519, and SNI/domain match.
- HTTP checks: HTTP/2 support and status probing.
- CDN checks: certificate issuer, HTTP headers, DNS CNAME chain, and IP/ASN heuristics.
- Latency checks: TCP RTT and TLS handshake RTT.
- Ranked output in terminal table plus optional CSV export.

## Build

```bash
cargo build --release
```

## How It Works

Default mode (no `--domains-file`) runs this pipeline:

1. Detect local IPv4 anchor (or use `--scan-anchor-ip`).
2. Sample nearby IPv4 prefixes and probe `443` reachability.
3. Read SAN/CN names from peer certificates on reachable IPs.
4. Deduplicate extracted domains and run full domain probing.
5. Rank results and print/export.

If `--domains-file` is provided, dynamic discovery is skipped and file domains are used directly.

## Quick Start

Default dynamic discovery:

```bash
cargo run --release
```

Dynamic discovery with fixed anchor IP:

```bash
cargo run --release -- \
  --scan-anchor-ip 203.0.113.10 \
  --scan-prefix-len 20 \
  --scan-neighbor-prefixes 1
```

Use custom domain list:

```bash
cargo run --release -- \
  --domains-file domains.sample.txt \
  --top 30 \
  --output-csv report.csv
```

## More Command Examples

Quick smoke test (small scan + short timeout):

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

Deep scan (higher coverage):

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

Export only top 20 to CSV:

```bash
cargo run --release -- \
  --top 20 \
  --output-csv report-top20.csv
```

File mode with custom thresholds:

```bash
cargo run --release -- \
  --domains-file domains.sample.txt \
  --nearby-rtt-ms 180 \
  --max-nearby-domains 80 \
  --concurrency 40 \
  --top 30
```

Keep non-`200` domains in output (disabled by default):

```bash
cargo run --release -- \
  --include-non-200 \
  --top 50
```

## Domain File Format

One domain per line:

```txt
google.com
github.com
cloudflare.com
```

Blank lines and `#` comments are ignored.

## CLI Options

Input and output:

- `--domains-file <PATH>`: use file-based domain input.
- `--output-csv <PATH>`: write ranked result to CSV.

Dynamic discovery options:

- `--scan-prefix-len <N>` (default: `20`): IPv4 prefix length for scanning.
- `--scan-anchor-ip <IPV4>`: fixed anchor IP, skip auto detection.
- `--scan-neighbor-prefixes <N>` (default: `1`): adjacent prefixes on each side.
- `--scan-samples-per-prefix <N>` (default: `1024`): sampled IPs per prefix.
- `--max-open-ips <N>` (default: `260`): max reachable HTTPS IPs kept for SAN extraction.
- `--ip-discovery-rtt-ms <N>` (default: `1200`): RTT threshold in IP discovery stage.
- `--discovered-domains-limit <N>` (default: `5000`): max domains produced by discovery.

Domain probing and ranking options:

- `--max-probe-domains <N>` (default: `300`): max candidate domains entering domain probes.
- `--max-nearby-domains <N>` (default: `120`): max domains kept after nearby RTT filtering.
- `--nearby-rtt-ms <N>` (default: `250`): domain nearby RTT threshold.
- `--top <N>` (default: `40`): output top N ranked domains.
- `--concurrency <N>` (default: `20`): async concurrency for probes.
- `--tcp-timeout-ms <N>` (default: `1500`): TCP connect timeout.
- `--tls-timeout-ms <N>` (default: `2500`): TLS handshake timeout.
- `--http-timeout-ms <N>` (default: `3000`): HTTPS request timeout.
- `--dns-timeout-ms <N>` (default: `1500`): DNS query timeout for CNAME/ASN detection.
- `--include-non-200` (default: disabled): keep domains without HTTP `200` in final ranking.

## Output Columns

- `Rank`: rank position.
- `Domain`: domain name.
- `TCP(ms)`: best TCP connect RTT to port `443`.
- `TLS(ms)`: TLS handshake RTT.
- `TLS1.3`: whether TLS 1.3 was negotiated.
- `X25519`: whether X25519-only handshake succeeded.
- `H2`: whether HTTP/2 is supported.
- `SNI`: whether cert names match domain/SNI.
- `HTTP`: whether HTTPS response status is exactly `200`.
- `HTTPCode`: HTTPS response status code.
- `CDN`: whether CDN signals were detected.
- `Score`: final score (`0..=100`).

## Ranking Model

Score combines:

- TLS certificate availability
- TLS 1.3 support
- X25519 support
- HTTP/2 support
- SNI/domain match
- CDN signal penalty (deducts points when CDN is detected)
- TLS handshake latency points
- TCP RTT latency points
- HTTP availability penalty for non-`200` or failed HTTPS response

Tie-break order:

1. Higher score
2. Lower TLS handshake RTT
3. Lower TCP RTT
4. Lexicographically smaller domain

## Troubleshooting

- `Failed to detect local IPv4 address`: set `--scan-anchor-ip <your_vps_ipv4>`.
- `Dynamic discovery returned no domains`: increase `--scan-samples-per-prefix`, `--scan-neighbor-prefixes`, or `--max-open-ips`.
- Too many `503` domains: keep default behavior (filters non-`200`) or pass `--include-non-200` if you need to inspect them.
- Results are too slow: lower `--scan-samples-per-prefix`, `--max-probe-domains`, and `--top`; increase `--concurrency` carefully.
- Results are empty in restricted networks: check outbound access to `443`, DNS, and local firewall policy.

## Notes

- TLS certificate validation is intentionally disabled during probing to collect handshake capabilities from more endpoints.
- CDN detection is heuristic and combines cert issuer, headers, DNS CNAME, and IP/ASN signals.
- ASN lookup uses Team Cymru DNS service and may be limited by local DNS policy or network restrictions.
- Dynamic discovery is route-sensitive and time-sensitive; repeated runs can produce different domain pools.

## License

This project is licensed under the MIT License (`MIT`).
See `LICENSE` for details.
