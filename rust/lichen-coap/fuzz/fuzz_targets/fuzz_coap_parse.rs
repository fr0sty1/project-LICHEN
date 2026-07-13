#![no_main]

use libfuzzer_sys::fuzz_target;
use lichen_coap::{CoapPacket, CoapBuilder, MessageType, MessageCode};

fuzz_target!(|data: &[u8]| {
    // Fuzz CoAP packet parsing
    // The parser should never panic

    if data.len() < 4 {
        return;  // CoAP header is 4 bytes minimum
    }

    // Try to parse as CoAP packet
    let _ = CoapPacket::parse(data);

    // If we can parse it, try to access all fields
    if let Ok(packet) = CoapPacket::parse(data) {
        let _ = packet.version();
        let _ = packet.msg_type();
        let _ = packet.code();
        let _ = packet.message_id();
        let _ = packet.token();
        let _ = packet.payload();

        // Iterate all options
        for option in packet.options() {
            let _ = option.number();
            let _ = option.value();
        }
    }

    // Try building and parsing round-trip
    if data.len() >= 10 && data.len() <= 100 {
        let mut builder = CoapBuilder::new();
        builder
            .msg_type(MessageType::Confirmable)
            .code(MessageCode::Get)
            .message_id(u16::from_be_bytes([data[0], data[1]]))
            .token(&data[2..6.min(data.len())]);

        if let Ok(built) = builder.build() {
            let _ = CoapPacket::parse(&built);
        }
    }
});
