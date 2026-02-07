use crate::models::{AsnCache, AsnLookupResult, DnsProbeResult, HttpProbeResult, TlsProbeResult};
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::proto::rr::{Name, RData, RecordType};
use reqwest::header::HeaderMap;
use std::collections::{BTreeSet, HashSet};
use std::net::IpAddr;
use std::time::Duration;
use tokio::time::timeout;

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

const CDN_ASN_NUMBERS: &[u32] = &[
    13335, // Cloudflare
    20940, // Akamai
    16625, // Akamai
    54113, // Fastly
    16509, // Amazon
    14618, // Amazon
    15133, // Edgecast
    8075,  // Microsoft
];

const MAX_CNAME_CHAIN_DEPTH: usize = 8;
const MAX_ASN_LOOKUPS_PER_DOMAIN: usize = 3;

pub(crate) async fn detect_cdn(
    domain: &str,
    tls_probe_result: &TlsProbeResult,
    http_client: &reqwest::Client,
    dns_resolver: &TokioAsyncResolver,
    dns_timeout: Duration,
    asn_cache: &AsnCache,
) -> HttpProbeResult {
    let mut signals = BTreeSet::new();
    if let Some(issuer) = tls_probe_result.cert_issuer.as_deref() {
        if let Some(keyword) = find_cdn_keyword(issuer) {
            signals.insert(format!("cert-issuer:{keyword}"));
        }
    }

    let dns_probe = probe_dns(domain, dns_resolver, dns_timeout).await;
    for cname in &dns_probe.cname_chain {
        if let Some(keyword) = find_cdn_keyword(cname) {
            signals.insert(format!("dns-cname:{keyword}"));
        }
    }
    for ip in dns_probe.ips.into_iter().take(MAX_ASN_LOOKUPS_PER_DOMAIN) {
        if let Some(asn_info) = lookup_asn_info(ip, dns_resolver, dns_timeout, asn_cache).await {
            signals.extend(cdn_signals_from_asn(&asn_info));
        }
    }

    let mut h2_from_http = false;
    let mut status_code = None;
    let url = format!("https://{domain}/");
    if let Ok(response) = http_client.get(url).send().await {
        status_code = Some(response.status().as_u16());
        h2_from_http = response.version() == reqwest::Version::HTTP_2;
        signals.extend(cdn_signals_from_headers(response.headers()));
    }

    HttpProbeResult {
        status_code,
        supports_h2: h2_from_http,
        cdn_signals: signals.into_iter().collect(),
    }
}

async fn probe_dns(
    domain: &str,
    resolver: &TokioAsyncResolver,
    dns_timeout: Duration,
) -> DnsProbeResult {
    let cname_chain = resolve_cname_chain(domain, resolver, dns_timeout).await;

    let mut ips = Vec::new();
    if let Ok(Ok(lookup)) = timeout(dns_timeout, resolver.lookup_ip(domain)).await {
        let mut seen = HashSet::new();
        for ip in lookup.iter() {
            if seen.insert(ip) {
                ips.push(ip);
            }
        }
    }

    DnsProbeResult { cname_chain, ips }
}

async fn resolve_cname_chain(
    domain: &str,
    resolver: &TokioAsyncResolver,
    dns_timeout: Duration,
) -> Vec<String> {
    let mut chain = Vec::new();
    let mut current = domain.trim_end_matches('.').to_ascii_lowercase();
    let mut seen = HashSet::new();

    for _ in 0..MAX_CNAME_CHAIN_DEPTH {
        if !seen.insert(current.clone()) {
            break;
        }

        let Ok(name) = Name::from_ascii(&current) else {
            break;
        };
        let lookup = match timeout(dns_timeout, resolver.lookup(name, RecordType::CNAME)).await {
            Ok(Ok(lookup)) => lookup,
            _ => break,
        };

        let mut next = None;
        for record in lookup.iter() {
            if let RData::CNAME(cname) = record {
                let candidate = cname.to_utf8().trim_end_matches('.').to_ascii_lowercase();
                if !candidate.is_empty() {
                    next = Some(candidate);
                    break;
                }
            }
        }

        let Some(next_domain) = next else {
            break;
        };
        chain.push(next_domain.clone());
        current = next_domain;
    }

    chain
}

async fn lookup_asn_info(
    ip: IpAddr,
    resolver: &TokioAsyncResolver,
    dns_timeout: Duration,
    asn_cache: &AsnCache,
) -> Option<AsnLookupResult> {
    if let Ok(cache) = asn_cache.lock() {
        if let Some(cached) = cache.get(&ip) {
            return cached.clone();
        }
    }

    let query_name = cymru_origin_query_name(ip);
    let origin_record = lookup_txt_record(resolver, &query_name, dns_timeout).await;
    let asn_number = origin_record
        .as_deref()
        .and_then(parse_origin_asn_from_record);

    let result = if let Some(number) = asn_number {
        let asn_name_query = format!("AS{number}.asn.cymru.com");
        let asn_name = lookup_txt_record(resolver, &asn_name_query, dns_timeout)
            .await
            .and_then(|record| parse_asn_name_from_record(&record));
        Some(AsnLookupResult {
            number,
            name: asn_name,
        })
    } else {
        None
    };

    if let Ok(mut cache) = asn_cache.lock() {
        cache.insert(ip, result.clone());
    }

    result
}

async fn lookup_txt_record(
    resolver: &TokioAsyncResolver,
    query_name: &str,
    dns_timeout: Duration,
) -> Option<String> {
    let Ok(name) = Name::from_ascii(query_name) else {
        return None;
    };
    let lookup = match timeout(dns_timeout, resolver.txt_lookup(name)).await {
        Ok(Ok(lookup)) => lookup,
        _ => return None,
    };

    for record in lookup.iter() {
        let joined = record
            .txt_data()
            .iter()
            .map(|part| String::from_utf8_lossy(part).into_owned())
            .collect::<Vec<_>>()
            .join("");
        let normalized = joined.trim().trim_matches('"').to_ascii_lowercase();
        if !normalized.is_empty() {
            return Some(normalized);
        }
    }

    None
}

fn cymru_origin_query_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            format!(
                "{}.{}.{}.{}.origin.asn.cymru.com",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        IpAddr::V6(v6) => {
            let hex = v6
                .octets()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let nibbles = hex
                .chars()
                .rev()
                .map(|ch| ch.to_string())
                .collect::<Vec<_>>()
                .join(".");
            format!("{nibbles}.origin6.asn.cymru.com")
        }
    }
}

fn parse_origin_asn_from_record(record: &str) -> Option<u32> {
    let first_column = record.split('|').next()?.trim();
    let asn_token = first_column.split_whitespace().next()?;
    asn_token.parse::<u32>().ok()
}

fn parse_asn_name_from_record(record: &str) -> Option<String> {
    let parts = record
        .split('|')
        .map(|part| part.trim())
        .collect::<Vec<_>>();
    let as_name = parts.last()?.to_ascii_lowercase();
    if as_name.is_empty() || as_name.chars().all(|ch| ch.is_ascii_digit() || ch == '-') {
        return None;
    }
    Some(as_name)
}

fn cdn_signals_from_asn(asn_info: &AsnLookupResult) -> Vec<String> {
    let mut signals = BTreeSet::new();
    if CDN_ASN_NUMBERS.contains(&asn_info.number) {
        signals.insert(format!("asn:as{}", asn_info.number));
    }
    if let Some(as_name) = asn_info.name.as_deref() {
        if let Some(keyword) = find_cdn_keyword(as_name) {
            signals.insert(format!("asn-name:{keyword}"));
        }
    }
    signals.into_iter().collect()
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
