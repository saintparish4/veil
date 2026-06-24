//! Correlate EVM bytecode offsets with Solidity source locations.
//!
//! Given a source map and a list of source files, maps any `(bytecode_offset)`
//! to `(file_path, line_number)` — enabling EVM-level findings to be reported
//! with Solidity source annotations in the same format as AST-level findings.

use crate::source_map::SourceMapEntry;

/// A resolved source location: a file path + 1-based line number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceLocation {
    /// Index into the compiler's `sourceList` array.
    pub file_index: i32,
    /// 1-based line number within the file.
    pub line: usize,
    /// Byte offset within the file.
    pub byte_offset: usize,
}

/// Map a bytecode instruction index to its source location.
///
/// `source_map`: one entry per bytecode instruction (from `parse_source_map`).
/// `instr_index`: the index of the instruction in the disassembled instruction list.
///
/// Returns `None` when the instruction has no source mapping (`file_index == -1`).
pub fn resolve_location(
    source_map: &[SourceMapEntry],
    instr_index: usize,
) -> Option<SourceLocation> {
    let entry = source_map.get(instr_index)?;
    if entry.file_index < 0 {
        return None;
    }
    Some(SourceLocation {
        file_index: entry.file_index,
        line: 0, // populated by `resolve_line` once source text is available
        byte_offset: entry.src_offset,
    })
}

/// Convert a byte offset in `source` to a 1-based line number.
pub fn byte_offset_to_line(source: &str, byte_offset: usize) -> usize {
    let capped = byte_offset.min(source.len());
    source[..capped].chars().filter(|&c| c == '\n').count() + 1
}

/// Convenience: resolve a bytecode instruction offset directly to a source line number.
///
/// `source_map`: output of `parse_source_map`, one entry per bytecode instruction.
/// `bytecode_offset`: the byte offset of the EVM instruction (not the instruction index).
/// `source_text`: the full Solidity source file text.
///
/// Returns `None` when no source mapping exists for this offset or the offset is out of range.
pub fn correlate_offset_to_line(
    source_map: &[crate::source_map::SourceMapEntry],
    bytecode_offset: usize,
    source_text: &str,
) -> Option<usize> {
    // Source-map entries are indexed by instruction index, not byte offset.
    // For a simple linear approximation (no instruction length accounting) we use the offset
    // directly as the instruction index — accurate for bytecode without PUSH immediates.
    // A full implementation would require the disassembly to know true instruction indices.
    let entry = source_map.get(bytecode_offset)?;
    if entry.file_index < 0 {
        return None;
    }
    Some(byte_offset_to_line(source_text, entry.src_offset))
}

/// Fully resolve an instruction index to a `(file_path, line)` pair.
///
/// `source_list`: ordered list of source file paths (from the compiler manifest).
/// `source_texts`: source text for each file (indexed by `file_index`).
pub fn resolve_full(
    source_map: &[SourceMapEntry],
    instr_index: usize,
    source_list: &[&str],
    source_texts: &[&str],
) -> Option<(String, usize)> {
    let mut loc = resolve_location(source_map, instr_index)?;
    let file_path = source_list.get(loc.file_index as usize)?.to_string();
    if let Some(text) = source_texts.get(loc.file_index as usize) {
        loc.line = byte_offset_to_line(text, loc.byte_offset);
    }
    Some((file_path, loc.line))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_map::parse_source_map;

    #[test]
    fn byte_offset_to_line_basic() {
        let src = "line1\nline2\nline3";
        assert_eq!(byte_offset_to_line(src, 0), 1);
        assert_eq!(byte_offset_to_line(src, 6), 2);
        assert_eq!(byte_offset_to_line(src, 12), 3);
    }

    #[test]
    fn resolve_location_no_mapping() {
        let sm = parse_source_map("::-1:-");
        assert!(resolve_location(&sm, 0).is_none());
    }

    #[test]
    fn resolve_full_maps_correctly() {
        // "pragma\nsolidity\n^0.8.0;"
        //          ^-- byte 7 = 's' in "solidity" (line 2)
        let sm = parse_source_map("7:8:0:-");
        let source_list = ["contracts/Token.sol"];
        let source_texts = ["pragma\nsolidity\n^0.8.0;"];
        let (path, line) = resolve_full(&sm, 0, &source_list, &source_texts).unwrap();
        assert_eq!(path, "contracts/Token.sol");
        assert_eq!(line, 2);
    }
}
