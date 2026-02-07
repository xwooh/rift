use anyhow::{Context, Result};
use clap::Parser;
use futures::stream::{self, StreamExt};
use reqwest::header::HeaderMap;
use rustls::client::{ServerCertVerified, ServerCertVerifier};
use rustls::{Certificate, ClientConfig, ServerName};
use serde::Serialize;
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::fs;
use tokio::net::{TcpStream, UdpSocket, lookup_host};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

#[derive(Parser, Debug)]
#[command(
    name = "rift",
    version,
    about = "Discover nearby domains from a VPS and rank them by TLS/CDN quality"
)]
struct Cli {
    #[arg(long, short = 'f')]
    domains_file: Option<PathBuf>,
    #[arg(long, short = 'o')]
    output_csv: Option<PathBuf>,
    #[arg(long, default_value_t = 20)]
    scan_prefix_len: u8,
    #[arg(long)]
    scan_anchor_ip: Option<Ipv4Addr>,
    #[arg(long, default_value_t = 1)]
    scan_neighbor_prefixes: u8,
    #[arg(long, default_value_t = 1024)]
    scan_samples_per_prefix: usize,
    #[arg(long, default_value_t = 260)]
    max_open_ips: usize,
    #[arg(long, default_value_t = 1200)]
    ip_discovery_rtt_ms: u64,
    #[arg(long, default_value_t = 5000)]
    discovered_domains_limit: usize,
    #[arg(long, default_value_t = 300)]
    max_probe_domains: usize,
    #[arg(long, default_value_t = 120)]
    max_nearby_domains: usize,
    #[arg(long, default_value_t = 250)]
    nearby_rtt_ms: u64,
    #[arg(long, default_value_t = 40)]
    top: usize,
    #[arg(long, default_value_t = 20)]
    concurrency: usize,
    #[arg(long, default_value_t = 1500)]
    tcp_timeout_ms: u64,
    #[arg(long, default_value_t = 2500)]
    tls_timeout_ms: u64,
    #[arg(long, default_value_t = 3000)]
    http_timeout_ms: u64,
}

#[derive(Clone, Debug)]
struct DomainCandidate {
    domain: String,
    tcp_rtt_ms: u64,
}

#[derive(Clone, Debug)]
struct IpCandidate {
    ip: Ipv4Addr,
    tcp_rtt_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
struct DomainReport {
    rank: usize,
    domain: String,
    tcp_rtt_ms: u64,
    tls_handshake_ms: Option<u64>,
    has_tls_cert: bool,
    supports_tls13: bool,
    supports_x25519: bool,
    supports_h2: bool,
    sni_matches_domain: bool,
    has_cdn: bool,
    cdn_signals: String,
    score: u32,
}

#[derive(Debug, Default)]
struct TlsProbeResult {
    success: bool,
    handshake_ms: Option<u64>,
    protocol_version: Option<String>,
    alpn: Option<String>,
    cert_dns_names: Vec<String>,
    cert_issuer: Option<String>,
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let domains = load_domains(&cli).await?;
    if domains.is_empty() {
        println!("No valid domains loaded.");
        return Ok(());
    }

    let probe_pool = domains
        .into_iter()
        .take(cli.max_probe_domains)
        .collect::<Vec<_>>();
    println!(
        "Loaded {} domains, probing nearby targets...",
        probe_pool.len()
    );

    let tcp_timeout = Duration::from_millis(cli.tcp_timeout_ms);
    let nearby = discover_nearby_domains(
        probe_pool,
        tcp_timeout,
        cli.nearby_rtt_ms,
        cli.max_nearby_domains,
        cli.concurrency,
    )
    .await;
    if nearby.is_empty() {
        println!("No nearby domains found under {} ms.", cli.nearby_rtt_ms);
        return Ok(());
    }
    println!(
        "Found {} nearby domains, running TLS/CDN analysis...",
        nearby.len()
    );

    let tls_config_default = build_tls_config(false);
    let tls_config_x25519 = build_tls_config(true);
    let http_client = build_http_client(Duration::from_millis(cli.http_timeout_ms))?;
    let tls_timeout = Duration::from_millis(cli.tls_timeout_ms);

    let mut reports = stream::iter(nearby.into_iter())
        .map(|candidate| {
            let tls_config_default = tls_config_default.clone();
            let tls_config_x25519 = tls_config_x25519.clone();
            let http_client = http_client.clone();
            async move {
                analyze_domain(
                    candidate,
                    tls_timeout,
                    tls_config_default,
                    tls_config_x25519,
                    http_client,
                )
                .await
            }
        })
        .buffer_unordered(cli.concurrency)
        .collect::<Vec<_>>()
        .await;

    reports.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| compare_optional_u64(left.tls_handshake_ms, right.tls_handshake_ms))
            .then_with(|| left.tcp_rtt_ms.cmp(&right.tcp_rtt_ms))
            .then_with(|| left.domain.cmp(&right.domain))
    });

    let top_n = cli.top.min(reports.len());
    let mut top_reports = reports.into_iter().take(top_n).collect::<Vec<_>>();
    for (index, report) in top_reports.iter_mut().enumerate() {
        report.rank = index + 1;
    }

    print_reports(&top_reports);
    if let Some(path) = cli.output_csv.as_ref() {
        write_csv(path, &top_reports).await?;
        println!("CSV report written to {}", path.display());
    }

    Ok(())
}

fn build_tls_config(x25519_only: bool) -> Arc<ClientConfig> {
    let verifier = Arc::new(NoCertificateVerification);
    let mut config = if x25519_only {
        ClientConfig::builder()
            .with_safe_default_cipher_suites()
            .with_kx_groups(&[&rustls::kx_group::X25519])
            .with_safe_default_protocol_versions()
            .expect("valid protocol versions")
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth()
    } else {
        ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth()
    };
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(config)
}

fn build_http_client(timeout_duration: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout_duration)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(2))
        .user_agent("rift/0.1")
        .build()
        .context("failed to build HTTP client")
}

async fn load_domains(cli: &Cli) -> Result<Vec<String>> {
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

async fn discover_nearby_domains(
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

async fn analyze_domain(
    candidate: DomainCandidate,
    tls_timeout: Duration,
    tls_config_default: Arc<ClientConfig>,
    tls_config_x25519: Arc<ClientConfig>,
    http_client: reqwest::Client,
) -> DomainReport {
    let baseline = tls_probe(&candidate.domain, tls_timeout, tls_config_default).await;
    let supports_x25519 = if baseline.success {
        tls_probe(&candidate.domain, tls_timeout, tls_config_x25519)
            .await
            .success
    } else {
        false
    };
    let supports_tls13 = baseline.protocol_version.as_deref() == Some("TLSv1_3");
    let mut supports_h2 = baseline.alpn.as_deref() == Some("h2");
    let has_tls_cert = baseline.success;
    let sni_matches_domain = if baseline.success {
        cert_matches_domain(&candidate.domain, &baseline.cert_dns_names)
    } else {
        false
    };

    let (has_cdn, mut cdn_signals, h2_from_http) =
        detect_cdn(&candidate.domain, &baseline, &http_client).await;
    supports_h2 = supports_h2 || h2_from_http;
    cdn_signals.sort();

    let score = compute_score(
        has_tls_cert,
        supports_tls13,
        supports_x25519,
        supports_h2,
        sni_matches_domain,
        candidate.tcp_rtt_ms,
        baseline.handshake_ms,
        has_cdn,
    );

    DomainReport {
        rank: 0,
        domain: candidate.domain,
        tcp_rtt_ms: candidate.tcp_rtt_ms,
        tls_handshake_ms: baseline.handshake_ms,
        has_tls_cert,
        supports_tls13,
        supports_x25519,
        supports_h2,
        sni_matches_domain,
        has_cdn,
        cdn_signals: cdn_signals.join("|"),
        score,
    }
}

async fn tls_probe(
    domain: &str,
    timeout_duration: Duration,
    tls_config: Arc<ClientConfig>,
) -> TlsProbeResult {
    let addresses = match lookup_host((domain, 443)).await {
        Ok(addresses) => addresses.collect::<Vec<_>>(),
        Err(_) => return TlsProbeResult::default(),
    };
    if addresses.is_empty() {
        return TlsProbeResult::default();
    }

    let server_name = match ServerName::try_from(domain) {
        Ok(server_name) => server_name.to_owned(),
        Err(_) => return TlsProbeResult::default(),
    };
    let connector = TlsConnector::from(tls_config);

    for address in addresses {
        let tcp_stream = match timeout(timeout_duration, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => stream,
            _ => continue,
        };

        let start = Instant::now();
        let tls_stream = match timeout(
            timeout_duration,
            connector.connect(server_name.clone(), tcp_stream),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            _ => continue,
        };
        let handshake_ms = duration_to_ms(start.elapsed());

        let (_, session) = tls_stream.get_ref();
        let protocol_version = session.protocol_version().map(|value| format!("{value:?}"));
        let alpn = session
            .alpn_protocol()
            .map(|value| String::from_utf8_lossy(value).to_string());

        let mut cert_dns_names = Vec::new();
        let mut cert_issuer = None;
        if let Some(certificates) = session.peer_certificates() {
            if let Some(certificate) = certificates.first() {
                let (names, issuer) = parse_certificate(&certificate.0);
                cert_dns_names = names;
                cert_issuer = issuer;
            }
        }

        return TlsProbeResult {
            success: true,
            handshake_ms: Some(handshake_ms),
            protocol_version,
            alpn,
            cert_dns_names,
            cert_issuer,
        };
    }

    TlsProbeResult::default()
}

fn parse_certificate(cert_der: &[u8]) -> (Vec<String>, Option<String>) {
    let Ok((_, certificate)) = X509Certificate::from_der(cert_der) else {
        return (Vec::new(), None);
    };

    let mut names = BTreeSet::new();
    if let Ok(Some(san)) = certificate.subject_alternative_name() {
        for name in &san.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                names.insert(dns.to_ascii_lowercase());
            }
        }
    }
    if names.is_empty() {
        for common_name in certificate.subject().iter_common_name() {
            if let Ok(value) = common_name.as_str() {
                names.insert(value.to_ascii_lowercase());
            }
        }
    }

    let issuer = Some(certificate.issuer().to_string().to_ascii_lowercase());
    (names.into_iter().collect(), issuer)
}

fn cert_matches_domain(domain: &str, cert_dns_names: &[String]) -> bool {
    cert_dns_names
        .iter()
        .any(|pattern| wildcard_matches(pattern, domain))
}

fn wildcard_matches(pattern: &str, domain: &str) -> bool {
    if pattern == domain {
        return true;
    }

    let Some(suffix) = pattern.strip_prefix("*.") else {
        return false;
    };
    let full_suffix = format!(".{suffix}");
    if !domain.ends_with(&full_suffix) {
        return false;
    }

    let prefix = &domain[..domain.len() - full_suffix.len()];
    !prefix.is_empty() && !prefix.contains('.')
}

async fn detect_cdn(
    domain: &str,
    tls_probe_result: &TlsProbeResult,
    http_client: &reqwest::Client,
) -> (bool, Vec<String>, bool) {
    let mut signals = BTreeSet::new();
    if let Some(issuer) = tls_probe_result.cert_issuer.as_deref() {
        if let Some(keyword) = find_cdn_keyword(issuer) {
            signals.insert(format!("cert-issuer:{keyword}"));
        }
    }

    let mut h2_from_http = false;
    let url = format!("https://{domain}/");
    if let Ok(response) = http_client.get(url).send().await {
        h2_from_http = response.version() == reqwest::Version::HTTP_2;
        signals.extend(cdn_signals_from_headers(response.headers()));
    }

    let has_cdn = !signals.is_empty();
    (has_cdn, signals.into_iter().collect(), h2_from_http)
}

fn cdn_signals_from_headers(headers: &HeaderMap) -> Vec<String> {
    let mut signals = BTreeSet::new();
    for (name, value) in headers {
        let key = name.as_str().to_ascii_lowercase();
        let val = value.to_str().unwrap_or_default().to_ascii_lowercase();

        if key == "cf-ray" || key == "cf-cache-status" {
            signals.insert("header:cloudflare".to_string());
        }
        if key.starts_with("x-amz-cf-") {
            signals.insert("header:cloudfront".to_string());
        }
        if key == "x-akamai-transformed" || key.starts_with("akamai-") {
            signals.insert("header:akamai".to_string());
        }
        if key == "x-fastly-request-id" || key == "x-served-by" {
            signals.insert("header:fastly".to_string());
        }
        if key == "x-cdn" || key == "via" || key == "server" || key == "x-cache" {
            if let Some(keyword) = find_cdn_keyword(&val) {
                signals.insert(format!("header:{keyword}"));
            }
        }
    }
    signals.into_iter().collect()
}

fn find_cdn_keyword(text: &str) -> Option<&'static str> {
    CDN_KEYWORDS
        .iter()
        .copied()
        .find(|keyword| text.contains(keyword))
}

fn compute_score(
    has_tls_cert: bool,
    supports_tls13: bool,
    supports_x25519: bool,
    supports_h2: bool,
    sni_matches_domain: bool,
    tcp_rtt_ms: u64,
    tls_handshake_ms: Option<u64>,
    has_cdn: bool,
) -> u32 {
    let mut score = 0u32;
    if has_tls_cert {
        score += 15;
    }
    if supports_tls13 {
        score += 15;
    }
    if supports_x25519 {
        score += 15;
    }
    if supports_h2 {
        score += 10;
    }
    if sni_matches_domain {
        score += 15;
    }
    if has_cdn {
        score += 10;
    }

    score += latency_points(tls_handshake_ms, 20);
    score += latency_points(Some(tcp_rtt_ms), 10);
    score.min(100)
}

fn latency_points(latency_ms: Option<u64>, max_score: u32) -> u32 {
    let Some(latency_ms) = latency_ms else {
        return 0;
    };
    if latency_ms <= 50 {
        max_score
    } else if latency_ms <= 100 {
        max_score.saturating_sub(4)
    } else if latency_ms <= 180 {
        max_score.saturating_sub(8)
    } else if latency_ms <= 300 {
        max_score.saturating_sub(13)
    } else {
        0
    }
}

fn print_reports(reports: &[DomainReport]) {
    let headers = vec![
        "Rank".to_string(),
        "Domain".to_string(),
        "TCP(ms)".to_string(),
        "TLS(ms)".to_string(),
        "TLS1.3".to_string(),
        "X25519".to_string(),
        "H2".to_string(),
        "SNI".to_string(),
        "CDN".to_string(),
        "Score".to_string(),
    ];
    let mut rows = Vec::new();
    for report in reports {
        rows.push(vec![
            report.rank.to_string(),
            report.domain.clone(),
            report.tcp_rtt_ms.to_string(),
            report
                .tls_handshake_ms
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string()),
            bool_text(report.supports_tls13),
            bool_text(report.supports_x25519),
            bool_text(report.supports_h2),
            bool_text(report.sni_matches_domain),
            bool_text(report.has_cdn),
            report.score.to_string(),
        ]);
    }

    let mut widths = headers.iter().map(String::len).collect::<Vec<_>>();
    for row in &rows {
        for (index, value) in row.iter().enumerate() {
            widths[index] = widths[index].max(value.len());
        }
    }

    let separator = format_separator(&widths);
    println!("{separator}");
    println!("{}", format_row(&headers, &widths));
    println!("{separator}");
    for row in rows {
        println!("{}", format_row(&row, &widths));
    }
    println!("{separator}");
}

fn format_separator(widths: &[usize]) -> String {
    let mut output = String::new();
    for (index, width) in widths.iter().enumerate() {
        if index == 0 {
            output.push('+');
        }
        output.push_str(&"-".repeat(*width + 2));
        output.push('+');
    }
    output
}

fn format_row(row: &[String], widths: &[usize]) -> String {
    let mut output = String::new();
    for (index, value) in row.iter().enumerate() {
        if index == 0 {
            output.push('|');
        }
        output.push(' ');
        output.push_str(value);
        output.push_str(&" ".repeat(widths[index].saturating_sub(value.len())));
        output.push(' ');
        output.push('|');
    }
    output
}

async fn write_csv(path: &PathBuf, reports: &[DomainReport]) -> Result<()> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    for report in reports {
        writer.serialize(report)?;
    }
    let bytes = writer.into_inner()?;
    fs::write(path, bytes)
        .await
        .with_context(|| format!("failed to write CSV file {}", path.display()))?;
    Ok(())
}

fn bool_text(value: bool) -> String {
    if value {
        "yes".to_string()
    } else {
        "no".to_string()
    }
}

fn compare_optional_u64(left: Option<u64>, right: Option<u64>) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => left.cmp(&right),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

fn duration_to_ms(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

const CDN_KEYWORDS: &[&str] = &[
    "cloudflare",
    "cloudfront",
    "akamai",
    "fastly",
    "edgecast",
    "stackpath",
    "cdn77",
    "cachefly",
    "imperva",
    "incapsula",
    "bunnycdn",
    "gcore",
    "sucuri",
    "chinacache",
    "quantil",
    "azure front door",
    "azurefd",
];
