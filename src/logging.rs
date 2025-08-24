use anyhow::Result;
use std::path::Path;
use tracing_appender::{non_blocking, rolling};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub fn init_logging(log_level: &str, log_file: Option<&str>) -> Result<()> {
    // Check if user specifically wants to see dependency logs
    let show_deps = std::env::var("RRPROXY_SHOW_DEPS_LOG").is_ok();

    let filter = if show_deps {
        // Show all logs if user explicitly requested
        EnvFilter::try_new(log_level).expect("invalid log level")
    } else {
        // Filter out dependency crate logs, only show our own
        let base_filter =
            EnvFilter::try_new(format!("rrproxy={log_level},info")).expect("invalid log level");
        base_filter
    };

    // Configure stdout layer based on build mode
    let stdout_layer = if cfg!(debug_assertions) {
        // Debug mode: show file/line info with compact format for single-line output
        fmt::layer()
            .with_target(true)
            .with_thread_ids(true)
            .with_file(true)
            .with_line_number(true)
            .compact()
    } else {
        // Release mode: hide file/line info
        fmt::layer()
            .with_target(true)
            .with_thread_ids(true)
            .with_file(false)
            .with_line_number(false)
            .compact()
    };

    match log_file {
        Some(file_path) => {
            // Create logs directory if it doesn't exist
            let log_dir = Path::new(file_path).parent().unwrap_or(Path::new("."));
            std::fs::create_dir_all(log_dir)?;

            // Set up daily rotating file appender
            let file_appender = rolling::daily(log_dir, "rrproxy.log");
            let (non_blocking_file, _guard) = non_blocking(file_appender);

            // Configure file layer based on build mode
            let file_layer = if cfg!(debug_assertions) {
                // Debug mode: show file/line info
                fmt::layer()
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_file(true)
                    .with_line_number(true)
                    .json()
                    .with_writer(non_blocking_file)
            } else {
                // Release mode: hide file/line info
                fmt::layer()
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_file(false)
                    .with_line_number(false)
                    .json()
                    .with_writer(non_blocking_file)
            };

            tracing_subscriber::registry()
                .with(filter)
                .with(stdout_layer)
                .with(file_layer)
                .init();

            // Prevent the guard from being dropped
            std::mem::forget(_guard);
        }
        None => {
            tracing_subscriber::registry()
                .with(filter)
                .with(stdout_layer)
                .init();
        }
    }

    Ok(())
}

/// Helper function to format body information
pub fn format_body_info(body: &[u8]) -> String {
    if body.is_empty() {
        return "empty".to_string();
    }

    // Try to detect if it's text
    if is_likely_text(body) {
        // Limit text output to reasonable size
        let text = String::from_utf8_lossy(body);
        if text.len() <= 1000 {
            format!("text({} bytes): {}", body.len(), text)
        } else {
            format!("text({} bytes): {}...", body.len(), &text[..1000])
        }
    } else {
        format!("binary({} bytes)", body.len())
    }
}

/// Simple heuristic to detect if bytes are likely text
fn is_likely_text(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }

    // Check if mostly printable ASCII or common UTF-8 patterns
    let printable_count = bytes
        .iter()
        .filter(|&&b| (32..=126).contains(&b) || b == 9 || b == 10 || b == 13)
        .count();

    let printable_ratio = printable_count as f64 / bytes.len() as f64;
    printable_ratio > 0.7 // Consider text if >70% printable
}
