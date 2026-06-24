//! Parse the Solidity compiler's source map JSON.
//!
//! Each entry maps a bytecode byte range to a source location:
//! `s:l:f:j` where:
//!   - `s` = source byte offset
//!   - `l` = source byte length
//!   - `f` = file index (into the `sourceList` array)
//!   - `j` = jump type: `i`=into, `o`=return, `-`=regular
//!
//! The source map is compressed: empty fields inherit from the previous entry.

/// A single source-map entry correlating a bytecode byte to a Solidity source range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceMapEntry {
    /// Source file byte offset (start of the mapped range).
    pub src_offset: usize,
    /// Source range length in bytes.
    pub src_length: usize,
    /// Index into the compiler's `sourceList` array.  `-1` means "no source".
    pub file_index: i32,
    /// Jump type annotation: `'i'`, `'o'`, or `'-'`.
    pub jump: char,
}

/// Parse a Solidity compiler source-map string into per-bytecode-byte entries.
///
/// The output `Vec` has one entry per bytecode byte (after the deployment preamble),
/// not one per instruction. Pass the bytecode length to know how many bytes to decode.
pub fn parse_source_map(source_map: &str) -> Vec<SourceMapEntry> {
    let mut entries = Vec::new();
    let mut prev = SourceMapEntry {
        src_offset: 0,
        src_length: 0,
        file_index: -1,
        jump: '-',
    };

    for chunk in source_map.split(';') {
        let fields: Vec<&str> = chunk.split(':').collect();

        let src_offset = fields
            .first()
            .and_then(|s| if s.is_empty() { None } else { s.parse().ok() })
            .unwrap_or(prev.src_offset);

        let src_length = fields
            .get(1)
            .and_then(|s| if s.is_empty() { None } else { s.parse().ok() })
            .unwrap_or(prev.src_length);

        let file_index = fields
            .get(2)
            .and_then(|s| if s.is_empty() { None } else { s.parse().ok() })
            .unwrap_or(prev.file_index);

        let jump = fields
            .get(3)
            .and_then(|s| s.chars().next())
            .unwrap_or(prev.jump);

        let entry = SourceMapEntry {
            src_offset,
            src_length,
            file_index,
            jump,
        };

        prev = entry.clone();
        entries.push(entry);
    }

    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_source_map() {
        // "s:l:f:j" format
        let sm = "0:10:0:i;20:5:0:-;::-1:-";
        let entries = parse_source_map(sm);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0], SourceMapEntry { src_offset: 0, src_length: 10, file_index: 0, jump: 'i' });
        assert_eq!(entries[1], SourceMapEntry { src_offset: 20, src_length: 5, file_index: 0, jump: '-' });
        // Third entry: all fields empty → inherit from prev, except file_index=-1
        assert_eq!(entries[2].src_offset, 20);
        assert_eq!(entries[2].file_index, -1);
    }

    #[test]
    fn empty_source_map() {
        let entries = parse_source_map("");
        assert_eq!(entries.len(), 1); // one empty chunk
    }
}
