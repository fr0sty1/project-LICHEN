#![no_main]

use libfuzzer_sys::fuzz_target;
use lichen_schc::{PacketProfile, ParsedPacket, CoapUdpLinkLocalProfile, Icmpv6EchoProfile};

fuzz_target!(|data: &[u8]| {
    // Fuzz SCHC packet parsing with arbitrary data
    // The parser should never panic, only return errors

    if data.len() < 8 {
        return;  // Too short for any valid packet
    }

    // Try parsing as different packet profiles
    // Each profile has different header expectations

    // CoAP over UDP (link-local)
    let _ = CoapUdpLinkLocalProfile::parse(data);

    // ICMPv6 Echo
    let _ = Icmpv6EchoProfile::parse(data);

    // Try rule matching on the parsed packet
    if let Ok(parsed) = CoapUdpLinkLocalProfile::parse(data) {
        let _ = lichen_schc::rule_matches(&parsed, 0);
        let _ = lichen_schc::rule_matches(&parsed, 1);
        let _ = lichen_schc::rule_matches(&parsed, 255);
    }
});
