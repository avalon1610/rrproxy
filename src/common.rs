pub const TRANSACTION_ID_HEADER: &str = "X-Transaction-Id";
pub const CHUNK_INDEX_HEADER: &str = "X-Chunk-Index";
pub const TOTAL_CHUNKS_HEADER: &str = "X-Total-Chunks";
pub const IS_LAST_CHUNK_HEADER: &str = "X-Is-Last-Chunk";
pub const ORIGINAL_URL_HEADER: &str = "X-Original-Url";

pub fn is_reserved_header(header: &str) -> bool {
    let header_lower = header.to_ascii_lowercase();
    header_lower == TRANSACTION_ID_HEADER.to_ascii_lowercase()
        || header_lower == CHUNK_INDEX_HEADER.to_ascii_lowercase()
        || header_lower == TOTAL_CHUNKS_HEADER.to_ascii_lowercase()
        || header_lower == IS_LAST_CHUNK_HEADER.to_ascii_lowercase()
        || header_lower == ORIGINAL_URL_HEADER.to_ascii_lowercase()
}