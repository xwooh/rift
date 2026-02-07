use crate::models::DomainReport;
use anyhow::{Context, Result};
use std::path::PathBuf;
use tokio::fs;

pub(crate) fn print_reports(reports: &[DomainReport]) {
    let headers = vec![
        "Rank".to_string(),
        "Domain".to_string(),
        "TCP(ms)".to_string(),
        "TLS(ms)".to_string(),
        "TLS1.3".to_string(),
        "X25519".to_string(),
        "H2".to_string(),
        "SNI".to_string(),
        "HTTP".to_string(),
        "HTTPCode".to_string(),
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
            bool_text(report.http_ok),
            report
                .http_status_code
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string()),
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

pub(crate) async fn write_csv(path: &PathBuf, reports: &[DomainReport]) -> Result<()> {
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

fn bool_text(value: bool) -> String {
    if value {
        "yes".to_string()
    } else {
        "no".to_string()
    }
}
