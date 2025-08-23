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
    let filter = EnvFilter::try_new(log_level)
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    let stdout_layer = fmt::layer()
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .pretty();

    match log_file {
        Some(file_path) => {
            // Create logs directory if it doesn't exist
            let log_dir = Path::new(file_path).parent().unwrap_or(Path::new("."));
            std::fs::create_dir_all(log_dir)?;

            // Set up daily rotating file appender
            let file_appender = rolling::daily(log_dir, "rrproxy.log");
            let (non_blocking_file, _guard) = non_blocking(file_appender);
            
            let file_layer = fmt::layer()
                .with_target(true)
                .with_thread_ids(true)
                .with_file(true)
                .with_line_number(true)
                .json()
                .with_writer(non_blocking_file);

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
