#![no_main]

use libfuzzer_sys::fuzz_target;
use lichen_schc::{CoapUdpLinkLocalProfile, Icmpv6EchoProfile, PacketProfile};

fuzz_target!(|data: &[u8]| {
    // Fuzz SCHC packet parsing with arbitrary data
    // The parser should never panic, only return errors

    // Must match the fixed SCHC_MAX_DECOMPRESSED profile bound.
    let mut output = vec![0u8; 1_500];
    let _ = lichen_schc::decompress(data, &mut output);

    // Try parsing as different packet profiles
    // Each profile has different header expectations

    // CoAP over UDP (link-local)
    let coap = CoapUdpLinkLocalProfile;
    let _ = coap.parse(data);

    // ICMPv6 Echo
    let echo = Icmpv6EchoProfile;
    let _ = echo.parse(data);

    // Try rule matching on the parsed packet
    if let Ok(parsed) = coap.parse(data) {
        let _ = lichen_schc::rule_matches(coap.rule(), parsed.as_slice());
    }
});
