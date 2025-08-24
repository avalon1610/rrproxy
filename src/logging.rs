use anyhow::Result;
use std::path::Path;
use tracing_appender::{non_blocking, rolling};
use tracing_subscriber::{
    fmt,
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
};

pub fn init_logging(log_level: &str, log_file: Option<&str>) -> Result<()> {
    // Check if user specifically wants to see dependency logs
    let show_deps = std::env::var("RRPROXY_SHOW_DEPS").is_ok();
    
    let filter = if show_deps {
        // Show all logs if user explicitly requested
        EnvFilter::try_new(log_level)
            .or_else(|_| EnvFilter::try_new("info"))
            .unwrap()
    } else {
        // Filter out dependency crate logs, only show our own
        let base_filter = EnvFilter::try_new(log_level)
            .or_else(|_| EnvFilter::try_new("info"))
            .unwrap()
            .add_directive("rrproxy=trace".parse().unwrap())
            .add_directive("hyper=warn".parse().unwrap())
            .add_directive("reqwest=warn".parse().unwrap())
            .add_directive("tokio=warn".parse().unwrap())
            .add_directive("rustls=warn".parse().unwrap())
            .add_directive("h2=warn".parse().unwrap())
            .add_directive("tower=warn".parse().unwrap())
            .add_directive("tracing=warn".parse().unwrap());
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

#[macro_export]
macro_rules! log_request_start {
    ($method:expr, $uri:expr, $headers:expr) => {
        tracing::info!(
            method = %$method,
            uri = %$uri,
            headers = ?$headers,
            "Request started"
        );
    };
}

#[macro_export]
macro_rules! log_request_success {
    ($method:expr, $uri:expr, $status:expr, $duration:expr, $response_size:expr) => {
        tracing::info!(
            method = %$method,
            uri = %$uri,
            status = %$status,
            duration_ms = %$duration.as_millis(),
            response_size = %$response_size,
            result = "success",
            "Request completed successfully"
        );
    };
}

#[macro_export]
macro_rules! log_request_error {
    ($method:expr, $uri:expr, $error:expr, $duration:expr) => {
        tracing::error!(
            method = %$method,
            uri = %$uri,
            error = %$error,
            duration_ms = %$duration.as_millis(),
            result = "error",
            "Request failed"
        );
    };
}

#[macro_export]
macro_rules! log_chunk_info {
    ($transaction_id:expr, $chunk_index:expr, $total_chunks:expr, $chunk_size:expr, $is_last:expr) => {
        tracing::debug!(
            transaction_id = %$transaction_id,
            chunk_index = %$chunk_index,
            total_chunks = %$total_chunks,
            chunk_size = %$chunk_size,
            is_last = %$is_last,
            "Processing chunk"
        );
    };
}

#[macro_export]
macro_rules! log_assembly_complete {
    ($transaction_id:expr, $total_size:expr, $chunk_count:expr) => {
        tracing::info!(
            transaction_id = %$transaction_id,
            total_size = %$total_size,
            chunk_count = %$chunk_count,
            "Request assembly completed"
        );
    };
}

#[macro_export]
macro_rules! log_debug_request {
    ($method:expr, $uri:expr, $headers:expr, $body:expr) => {
        tracing::debug!(
            method = %$method,
            uri = %$uri,
            headers = ?$headers,
            body_info = %crate::logging::format_body_info(&$body),
            "Full request details"
        );
    };
}

#[macro_export]
macro_rules! log_debug_response {
    ($method:expr, $uri:expr, $status:expr, $headers:expr, $body:expr) => {
        tracing::debug!(
            method = %$method,
            uri = %$uri,
            status = %$status,
            headers = ?$headers,
            body_info = %crate::logging::format_body_info(&$body),
            "Full response details"
        );
    };
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
    let printable_count = bytes.iter()
        .filter(|&&b| b >= 32 && b <= 126 || b == 9 || b == 10 || b == 13)
        .count();
    
    let printable_ratio = printable_count as f64 / bytes.len() as f64;
    printable_ratio > 0.7 // Consider text if >70% printable
}
