use crate::models::TlsProbeResult;
use rustls::client::{ServerCertVerified, ServerCertVerifier};
use rustls::{Certificate, ClientConfig, ServerName};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::net::{TcpStream, lookup_host};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

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

pub(crate) fn build_tls_config(x25519_only: bool) -> Arc<ClientConfig> {
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

pub(crate) async fn tls_probe(
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

pub(crate) fn parse_certificate(cert_der: &[u8]) -> (Vec<String>, Option<String>) {
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

pub(crate) fn cert_matches_domain(domain: &str, cert_dns_names: &[String]) -> bool {
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

fn duration_to_ms(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}
