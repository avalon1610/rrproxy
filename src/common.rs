pub const TRANSACTION_ID_HEADER: &str = "X-Transaction-Id";
pub const CHUNK_INDEX_HEADER: &str = "X-Chunk-Index";
pub const TOTAL_CHUNKS_HEADER: &str = "X-Total-Chunks";
pub const IS_LAST_CHUNK_HEADER: &str = "X-Is-Last-Chunk";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_constants() {
        assert_eq!(TRANSACTION_ID_HEADER, "X-Transaction-Id");
        assert_eq!(CHUNK_INDEX_HEADER, "X-Chunk-Index");
        assert_eq!(TOTAL_CHUNKS_HEADER, "X-Total-Chunks");
        assert_eq!(IS_LAST_CHUNK_HEADER, "X-Is-Last-Chunk");
    }
}
