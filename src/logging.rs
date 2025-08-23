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
