use crate::cli::Cli;
use crate::models::{DomainCandidate, IpCandidate};
use crate::tls::{build_tls_config, parse_certificate};
use anyhow::{Context, Result};
use futures::stream::{self, StreamExt};
use rustls::{ClientConfig, ServerName};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs;
use tokio::net::{TcpStream, UdpSocket, lookup_host};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

pub(crate) async fn load_domains(cli: &Cli) -> Result<Vec<String>> {
    if let Some(path) = cli.domains_file.as_ref() {
        let content = fs::read_to_string(path)
            .await
            .with_context(|| format!("failed to read domains file {}", path.display()))?;
        let domains = parse_plain_domains(&content, usize::MAX);
        println!(
            "Loaded {} candidate domains from file {}.",
            domains.len(),
            path.display()
        );
        return Ok(domains);
    }

    let domains = discover_domains_dynamically(cli).await;
    if domains.is_empty() {
        println!(
            "Dynamic discovery returned no domains. Increase --scan-samples-per-prefix or --max-open-ips."
        );
    } else {
        println!(
            "Loaded {} candidate domains from dynamic nearby-network discovery.",
            domains.len()
        );
    }
    Ok(domains)
}

pub(crate) async fn discover_nearby_domains(
    domains: Vec<String>,
    tcp_timeout: Duration,
    max_rtt_ms: u64,
    max_nearby_domains: usize,
    concurrency: usize,
) -> Vec<DomainCandidate> {
    let mut candidates = stream::iter(domains.into_iter())
        .map(|domain| async move {
            match measure_tcp_rtt_ms(&domain, tcp_timeout).await {
                Some(tcp_rtt_ms) if tcp_rtt_ms <= max_rtt_ms => {
                    Some(DomainCandidate { domain, tcp_rtt_ms })
                }
                _ => None,
            }
        })
        .buffer_unordered(concurrency.max(1))
        .filter_map(|candidate| async move { candidate })
        .collect::<Vec<_>>()
        .await;

    candidates.sort_by_key(|candidate| candidate.tcp_rtt_ms);
    candidates.truncate(max_nearby_domains);
    candidates
}

async fn discover_domains_dynamically(cli: &Cli) -> Vec<String> {
    let local_ip = if let Some(anchor_ip) = cli.scan_anchor_ip {
        anchor_ip
    } else if let Some(detected) = detect_local_ipv4().await {
        detected
    } else {
        println!("Failed to detect local IPv4 address for dynamic scanning.");
        return Vec::new();
    };
    let prefix_len = cli.scan_prefix_len.clamp(16, 30);
    let prefixes = build_scan_prefixes(local_ip, prefix_len, cli.scan_neighbor_prefixes);
    if prefixes.is_empty() {
        return Vec::new();
    }

    let mut targets = Vec::new();
    let mut target_seen = HashSet::new();
    for prefix_base in prefixes {
        for ip in sample_ips_from_prefix(prefix_base, prefix_len, cli.scan_samples_per_prefix) {
            if target_seen.insert(ip) {
                targets.push(ip);
            }
        }
    }
    println!(
        "Dynamic scan local_ip {} prefixes {} target_ips {}.",
        local_ip,
        (usize::from(cli.scan_neighbor_prefixes) * 2) + 1,
        targets.len()
    );
    if targets.is_empty() {
        return Vec::new();
    }

    let open_ips = discover_open_https_ips(
        targets,
        Duration::from_millis(cli.tcp_timeout_ms),
        cli.ip_discovery_rtt_ms,
        cli.max_open_ips,
        cli.concurrency,
    )
    .await;
    println!(
        "Dynamic scan found {} open HTTPS IPs within {} ms.",
        open_ips.len(),
        cli.ip_discovery_rtt_ms
    );
    if open_ips.is_empty() {
        return Vec::new();
    }

    let tls_timeout = Duration::from_millis(cli.tls_timeout_ms);
    let tls_config = build_tls_config(false);
    let discovered = stream::iter(open_ips.into_iter())
        .map(|candidate| {
            let tls_config = tls_config.clone();
            async move {
                tls_probe_ip_domains(candidate.ip, tls_timeout, tls_config)
                    .await
                    .into_iter()
                    .map(|domain| (domain, candidate.tcp_rtt_ms))
                    .collect::<Vec<_>>()
            }
        })
        .buffer_unordered(cli.concurrency.max(1))
        .collect::<Vec<_>>()
        .await;

    let mut merged = Vec::new();
    let mut seen = HashSet::new();
    for records in discovered {
        for (domain, _ip_rtt) in records {
            if seen.insert(domain.clone()) {
                merged.push(domain);
                if merged.len() >= cli.discovered_domains_limit.max(1) {
                    println!(
                        "Dynamic discovery reached domain limit {}.",
                        cli.discovered_domains_limit
                    );
                    return merged;
                }
            }
        }
    }
    merged
}

async fn detect_local_ipv4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    socket.connect("1.1.1.1:80").await.ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip) if !ip.is_loopback() => Some(ip),
        _ => None,
    }
}

fn build_scan_prefixes(local_ip: Ipv4Addr, prefix_len: u8, neighbor_prefixes: u8) -> Vec<u32> {
    let prefix_len = prefix_len.clamp(16, 30);
    let local_u32 = u32::from(local_ip);
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix_len))
    };
    let base = local_u32 & mask;
    let block_size = 1u64 << (32 - u32::from(prefix_len));

    let mut prefixes = Vec::new();
    let total = i64::from(neighbor_prefixes);
    for offset in -total..=total {
        let candidate = i128::from(base) + i128::from(offset) * i128::from(block_size);
        if (0..=i128::from(u32::MAX)).contains(&candidate) {
            prefixes.push(candidate as u32);
        }
    }
    prefixes
}

fn sample_ips_from_prefix(prefix_base: u32, prefix_len: u8, max_samples: usize) -> Vec<Ipv4Addr> {
    let host_bits = 32 - u32::from(prefix_len);
    let host_count = 1u64 << host_bits;
    if host_count <= 2 {
        return Vec::new();
    }

    let usable = host_count - 2;
    let samples = max_samples.min(usable as usize).max(1);
    let stride = usable.saturating_sub(1);

    let mut ips = Vec::with_capacity(samples);
    for index in 0..samples {
        let offset = 1 + ((index as u64).saturating_mul(stride) % usable);
        let ip_u32 = prefix_base.saturating_add(offset as u32);
        ips.push(Ipv4Addr::from(ip_u32));
    }
    ips
}

async fn discover_open_https_ips(
    ips: Vec<Ipv4Addr>,
    tcp_timeout: Duration,
    max_rtt_ms: u64,
    max_open_ips: usize,
    concurrency: usize,
) -> Vec<IpCandidate> {
    let mut candidates = stream::iter(ips.into_iter())
        .map(|ip| async move {
            let address = (IpAddr::V4(ip), 443);
            let start = Instant::now();
            if let Ok(Ok(stream)) = timeout(tcp_timeout, TcpStream::connect(address)).await {
                let elapsed_ms = duration_to_ms(start.elapsed());
                drop(stream);
                if elapsed_ms <= max_rtt_ms {
                    return Some(IpCandidate {
                        ip,
                        tcp_rtt_ms: elapsed_ms,
                    });
                }
            }
            None
        })
        .buffer_unordered(concurrency.max(1))
        .filter_map(|candidate| async move { candidate })
        .collect::<Vec<_>>()
        .await;

    candidates.sort_by_key(|candidate| candidate.tcp_rtt_ms);
    candidates.truncate(max_open_ips.max(1));
    candidates
}

async fn tls_probe_ip_domains(
    ip: Ipv4Addr,
    timeout_duration: Duration,
    tls_config: Arc<ClientConfig>,
) -> Vec<String> {
    let tcp_stream =
        match timeout(timeout_duration, TcpStream::connect((IpAddr::V4(ip), 443))).await {
            Ok(Ok(stream)) => stream,
            _ => return Vec::new(),
        };

    let server_name = ServerName::IpAddress(IpAddr::V4(ip));
    let connector = TlsConnector::from(tls_config);
    let tls_stream =
        match timeout(timeout_duration, connector.connect(server_name, tcp_stream)).await {
            Ok(Ok(stream)) => stream,
            _ => return Vec::new(),
        };
    let (_, session) = tls_stream.get_ref();

    let mut discovered = Vec::new();
    let mut seen = HashSet::new();
    if let Some(certificates) = session.peer_certificates() {
        if let Some(certificate) = certificates.first() {
            let (names, _) = parse_certificate(&certificate.0);
            for name in names {
                if let Some(domain) = normalize_discovered_domain(&name) {
                    if seen.insert(domain.clone()) {
                        discovered.push(domain);
                    }
                }
            }
        }
    }
    discovered
}

fn parse_plain_domains(content: &str, max_domains: usize) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut domains = Vec::new();
    for line in content.lines() {
        if domains.len() >= max_domains {
            break;
        }
        if let Some(domain) = normalize_domain(line) {
            if seen.insert(domain.clone()) {
                domains.push(domain);
            }
        }
    }
    domains
}

fn normalize_discovered_domain(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let without_wildcard = trimmed.strip_prefix("*.").unwrap_or(trimmed);
    normalize_domain(without_wildcard)
}

fn normalize_domain(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let first = trimmed.split_whitespace().next()?;
    if first.contains('/') {
        return None;
    }
    let cleaned = first.trim_end_matches('.').to_ascii_lowercase();
    if !cleaned.contains('.') {
        return None;
    }
    idna::domain_to_ascii(&cleaned).ok()
}

async fn measure_tcp_rtt_ms(domain: &str, timeout_duration: Duration) -> Option<u64> {
    let addresses = lookup_host((domain, 443)).await.ok()?.collect::<Vec<_>>();
    if addresses.is_empty() {
        return None;
    }

    let mut best: Option<Duration> = None;
    for address in addresses {
        let start = Instant::now();
        if let Ok(Ok(stream)) = timeout(timeout_duration, TcpStream::connect(address)).await {
            let elapsed = start.elapsed();
            drop(stream);
            best = Some(match best {
                Some(current) if current <= elapsed => current,
                _ => elapsed,
            });
        }
    }

    best.map(duration_to_ms)
}

fn duration_to_ms(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}
