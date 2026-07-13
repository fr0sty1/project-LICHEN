#![no_main]

use libfuzzer_sys::fuzz_target;
use lichen_link::frame::{AddrMode, FrameHeader, FrameParser};

fuzz_target!(|data: &[u8]| {
    // Fuzz frame header parsing
    // The parser should never panic, only return errors

    if data.is_empty() {
        return;
    }

    // Try to parse as a frame
    let mut parser = FrameParser::new();
    let _ = parser.parse(data);

    // Try to parse frame header directly
    let _ = FrameHeader::parse(data);

    // Try address mode parsing
    if !data.is_empty() {
        let _ = AddrMode::from_u8(data[0] & 0x03);
    }

    // Try to parse with various assumed lengths
    for assumed_len in [0usize, 10, 50, 100, 200, 255] {
        if data.len() >= assumed_len {
            let _ = FrameHeader::parse(&data[..assumed_len]);
        }
    }
});
