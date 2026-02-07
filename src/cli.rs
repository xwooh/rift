use clap::Parser;
use std::net::Ipv4Addr;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "rift",
    version,
    about = "Discover nearby domains from a VPS and rank them by TLS/CDN quality"
)]
pub(crate) struct Cli {
    #[arg(long, short = 'f')]
    pub(crate) domains_file: Option<PathBuf>,
    #[arg(long, short = 'o')]
    pub(crate) output_csv: Option<PathBuf>,
    #[arg(long, default_value_t = 20)]
    pub(crate) scan_prefix_len: u8,
    #[arg(long)]
    pub(crate) scan_anchor_ip: Option<Ipv4Addr>,
    #[arg(long, default_value_t = 1)]
    pub(crate) scan_neighbor_prefixes: u8,
    #[arg(long, default_value_t = 1024)]
    pub(crate) scan_samples_per_prefix: usize,
    #[arg(long, default_value_t = 260)]
    pub(crate) max_open_ips: usize,
    #[arg(long, default_value_t = 1200)]
    pub(crate) ip_discovery_rtt_ms: u64,
    #[arg(long, default_value_t = 5000)]
    pub(crate) discovered_domains_limit: usize,
    #[arg(long, default_value_t = 300)]
    pub(crate) max_probe_domains: usize,
    #[arg(long, default_value_t = 120)]
    pub(crate) max_nearby_domains: usize,
    #[arg(long, default_value_t = 250)]
    pub(crate) nearby_rtt_ms: u64,
    #[arg(long, default_value_t = 40)]
    pub(crate) top: usize,
    #[arg(long, default_value_t = 20)]
    pub(crate) concurrency: usize,
    #[arg(long, default_value_t = 1500)]
    pub(crate) tcp_timeout_ms: u64,
    #[arg(long, default_value_t = 2500)]
    pub(crate) tls_timeout_ms: u64,
    #[arg(long, default_value_t = 3000)]
    pub(crate) http_timeout_ms: u64,
    #[arg(long, default_value_t = 1500)]
    pub(crate) dns_timeout_ms: u64,
    #[arg(
        long,
        default_value_t = false,
        help = "Keep domains without HTTP 200 in final output"
    )]
    pub(crate) include_non_200: bool,
}
