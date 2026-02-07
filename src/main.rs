use anyhow::{Context, Result};
use futures::stream::{self, StreamExt};
use hickory_resolver::TokioAsyncResolver;
use rustls::ClientConfig;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

mod cdn;
mod cli;
mod discovery;
mod models;
mod output;
mod tls;

use cdn::detect_cdn;
use clap::Parser;
use discovery::{discover_nearby_domains, load_domains};
use models::{AsnCache, DomainCandidate, DomainReport};
use output::{print_reports, write_csv};
use tls::{build_tls_config, cert_matches_domain, tls_probe};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = cli::Cli::parse();
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
    let dns_resolver = build_dns_resolver()?;
    let asn_cache: AsnCache = Arc::new(Mutex::new(HashMap::new()));
    let tls_timeout = Duration::from_millis(cli.tls_timeout_ms);
    let dns_timeout = Duration::from_millis(cli.dns_timeout_ms);

    let mut reports = stream::iter(nearby.into_iter())
        .map(|candidate| {
            let tls_config_default = tls_config_default.clone();
            let tls_config_x25519 = tls_config_x25519.clone();
            let http_client = http_client.clone();
            let dns_resolver = dns_resolver.clone();
            let asn_cache = asn_cache.clone();
            async move {
                analyze_domain(
                    candidate,
                    tls_timeout,
                    dns_timeout,
                    tls_config_default,
                    tls_config_x25519,
                    http_client,
                    dns_resolver,
                    asn_cache,
                )
                .await
            }
        })
        .buffer_unordered(cli.concurrency)
        .collect::<Vec<_>>()
        .await;

    if !cli.include_non_200 {
        let before_filter = reports.len();
        reports.retain(|report| report.http_ok);
        let filtered = before_filter.saturating_sub(reports.len());
        if filtered > 0 {
            println!(
                "Filtered {} domains without HTTP 200. Use --include-non-200 to keep them.",
                filtered
            );
        }
        if reports.is_empty() {
            println!("No domains left after HTTP 200 filtering.");
            return Ok(());
        }
    }

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

fn build_http_client(timeout_duration: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout_duration)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(2))
        .user_agent("rift/0.1")
        .build()
        .context("failed to build HTTP client")
}

fn build_dns_resolver() -> Result<TokioAsyncResolver> {
    TokioAsyncResolver::tokio_from_system_conf().context("failed to build DNS resolver")
}

async fn analyze_domain(
    candidate: DomainCandidate,
    tls_timeout: Duration,
    dns_timeout: Duration,
    tls_config_default: Arc<ClientConfig>,
    tls_config_x25519: Arc<ClientConfig>,
    http_client: reqwest::Client,
    dns_resolver: TokioAsyncResolver,
    asn_cache: AsnCache,
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

    let http_probe = detect_cdn(
        &candidate.domain,
        &baseline,
        &http_client,
        &dns_resolver,
        dns_timeout,
        &asn_cache,
    )
    .await;
    supports_h2 = supports_h2 || http_probe.supports_h2;
    let http_ok = http_probe.is_available();
    let http_status_code = http_probe.status_code;
    let mut cdn_signals = http_probe.cdn_signals;
    cdn_signals.sort();
    let has_cdn = !cdn_signals.is_empty();

    let score = compute_score(
        has_tls_cert,
        supports_tls13,
        supports_x25519,
        supports_h2,
        sni_matches_domain,
        candidate.tcp_rtt_ms,
        baseline.handshake_ms,
        has_cdn,
        http_ok,
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
        http_ok,
        http_status_code,
        has_cdn,
        cdn_signals: cdn_signals.join("|"),
        score,
    }
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
    http_ok: bool,
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
        score = score.saturating_sub(20);
    }

    score += latency_points(tls_handshake_ms, 20);
    score += latency_points(Some(tcp_rtt_ms), 10);
    if !http_ok {
        score = score.saturating_sub(30);
    }
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

fn compare_optional_u64(left: Option<u64>, right: Option<u64>) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => left.cmp(&right),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}
