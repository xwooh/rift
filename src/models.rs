use serde::Serialize;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
pub(crate) struct DomainCandidate {
    pub(crate) domain: String,
    pub(crate) tcp_rtt_ms: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct IpCandidate {
    pub(crate) ip: Ipv4Addr,
    pub(crate) tcp_rtt_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DomainReport {
    pub(crate) rank: usize,
    pub(crate) domain: String,
    pub(crate) tcp_rtt_ms: u64,
    pub(crate) tls_handshake_ms: Option<u64>,
    pub(crate) has_tls_cert: bool,
    pub(crate) supports_tls13: bool,
    pub(crate) supports_x25519: bool,
    pub(crate) supports_h2: bool,
    pub(crate) sni_matches_domain: bool,
    pub(crate) http_ok: bool,
    pub(crate) http_status_code: Option<u16>,
    pub(crate) has_cdn: bool,
    pub(crate) cdn_signals: String,
    pub(crate) score: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct AsnLookupResult {
    pub(crate) number: u32,
    pub(crate) name: Option<String>,
}

#[derive(Debug, Default)]
pub(crate) struct TlsProbeResult {
    pub(crate) success: bool,
    pub(crate) handshake_ms: Option<u64>,
    pub(crate) protocol_version: Option<String>,
    pub(crate) alpn: Option<String>,
    pub(crate) cert_dns_names: Vec<String>,
    pub(crate) cert_issuer: Option<String>,
}

#[derive(Debug, Default)]
pub(crate) struct HttpProbeResult {
    pub(crate) status_code: Option<u16>,
    pub(crate) supports_h2: bool,
    pub(crate) cdn_signals: Vec<String>,
}

#[derive(Debug, Default)]
pub(crate) struct DnsProbeResult {
    pub(crate) cname_chain: Vec<String>,
    pub(crate) ips: Vec<IpAddr>,
}

impl HttpProbeResult {
    pub(crate) fn is_available(&self) -> bool {
        self.status_code == Some(200)
    }
}

pub(crate) type AsnCache = Arc<Mutex<HashMap<IpAddr, Option<AsnLookupResult>>>>;
