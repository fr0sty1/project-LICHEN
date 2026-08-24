#![no_main]

use libfuzzer_sys::fuzz_target;
use lichen_coap::{CoapBuilder, CoapPacket, MessageCode, MessageType};

fuzz_target!(|data: &[u8]| {
    // Fuzz CoAP packet parsing
    // The parser should never panic

    if data.len() < 4 {
        return; // CoAP header is 4 bytes minimum
    }

    // Try to parse as CoAP packet
    let _ = CoapPacket::from_bytes(data);

    // If we can parse it, try to access all fields
    if let Ok(packet) = CoapPacket::from_bytes(data) {
        let _ = packet.msg_type();
        let _ = packet.code();
        let _ = packet.message_id();
        let _ = packet.token();
        let _ = packet.payload();

        // Iterate all options
        for option_result in packet.options() {
            if let Ok(option) = option_result {
                let _ = option.number;
                let _ = option.value;
            }
        }
    }

    // Try building and parsing round-trip
    if data.len() >= 10 && data.len() <= 100 {
        let mut buf = [0u8; 256];
        let token = &data[2..6.min(data.len())];
        let message_id = u16::from_be_bytes([data[0], data[1]]);

        if let Ok(builder) = CoapBuilder::new(
            &mut buf,
            MessageType::Confirmable,
            MessageCode::GET,
            message_id,
            token,
        ) {
            let len = builder.finish();
            let _ = CoapPacket::from_bytes(&buf[..len]);
        }
    }
});
