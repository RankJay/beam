//! Fixed-size chunk boundaries (ADR 0061, 0062).

/// Default plain fixed chunk size for v1 tuning (~4 MiB). Sessions record the chosen size on the manifest; this is not a fixed protocol constant.
pub const DEFAULT_CHUNK_SIZE: u64 = 4 * 1024 * 1024;

/// Number of fixed-size chunks covering `file_size` bytes.
///
/// An empty file yields `0` chunks.
#[must_use]
pub fn chunk_count_for_size(file_size: u64, chunk_size: u64) -> u32 {
    assert!(chunk_size > 0, "chunk_size must be positive");
    if file_size == 0 {
        return 0;
    }
    let n = 1 + (file_size - 1) / chunk_size;
    u32::try_from(n).expect("chunk count fits u32 for supported file sizes")
}

/// Byte offset and length for chunk `index`, or `None` if `index` is out of range.
#[must_use]
pub fn chunk_span(file_size: u64, chunk_size: u64, index: u32) -> Option<(u64, u64)> {
    let total_chunks = chunk_count_for_size(file_size, chunk_size);
    if index >= total_chunks {
        return None;
    }
    let start = u64::from(index).saturating_mul(chunk_size);
    let remaining = file_size.saturating_sub(start);
    let len = remaining.min(chunk_size);
    Some((start, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_count_empty() {
        assert_eq!(chunk_count_for_size(0, 1024), 0);
    }

    #[test]
    fn chunk_count_rounds_up() {
        assert_eq!(chunk_count_for_size(1, 10), 1);
        assert_eq!(chunk_count_for_size(10, 10), 1);
        assert_eq!(chunk_count_for_size(11, 10), 2);
    }

    #[test]
    fn chunk_span_matches_count() {
        let size = 25;
        let c = 10;
        let n = chunk_count_for_size(size, c);
        for i in 0..n {
            let (off, len) = chunk_span(size, c, i).unwrap();
            assert!(len > 0);
            if i + 1 == n {
                assert_eq!(off + len, size);
            }
        }
        assert!(chunk_span(size, c, n).is_none());
    }
}
