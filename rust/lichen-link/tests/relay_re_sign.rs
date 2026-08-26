#![cfg(all(feature = "std", feature = "schnorr"))]

//! Hop-by-hop relay semantics per spec/06-security.md §8.4: the relay
//! verifies the inbound link signature against the pinned peer key BEFORE any
//! mutation, then emits a NEW frame signed with its OWN key.
//!
//! Oracles:
//! - `EXPECTED_RELAYED_WIRE_HEX` was computed independently by the Python
//!   reference implementation (`python/src/lichen/crypto/schnorr48.py`) over
//!   the normative transcript for the fixed relay parameters below.
//! - The canonical `short_addr_signed` corpus entry comes from
//!   `test/vectors/link_frame.json` (independent PyNaCl reference signer).
//!
//! Negative cases prove ordering: every pre-verification failure leaves the
//! output buffer untouched, and any post-signature tamper is rejected by the
//! next hop.

use std::fs;
use std::path::Path;

use serde::Deserialize;

use lichen_link::frame::{AddrMode, LichenFrame};
use lichen_link::identity::{Identity, PeerIdentity};
use lichen_link::link_layer::LinkLayer;
use lichen_link::relay::RelayError;
use lichen_link::schnorr::verify_frame;
use lichen_link::{LinkSeqNum, PublicKey, Seed};

const ORIGIN_A_PUBKEY_HEX: &str =
    "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
const RELAY_B_PUBKEY_HEX: &str = "a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0";
const EUI_B_HEX: &str = "ef16b2a301070ea1";
const EUI_C_HEX: &str = "4281522aa3b40812";
/// Full expected relay output: length||llsec||epoch||seq||dst(C)||signer(B)||
/// payload||Schnorr48-by-relay-B, computed by the Python reference signer.
const EXPECTED_RELAYED_WIRE_HEX: &str = "4ca20712344281522aa3b40812ef16b2a301070ea172656c61792d6d6514144515fe77b0376e5a2a61e715763e467ce145630280cd97cb68bc3c9efd13faff4c09131730ddba87198184fc480e";

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn node(seed: u8) -> LinkLayer {
    LinkLayer::new(Identity::from_seed(Seed::new([seed; 32])))
}

fn eui64(id: &Identity) -> [u8; 8] {
    let mut eui = id.iid;
    eui[0] ^= 0x02;
    eui
}

fn seq(n: u16) -> LinkSeqNum {
    LinkSeqNum::new(n)
}

/// Origin A -> relay B -> destination C with the exact parameters mirrored in
/// EXPECTED_RELAYED_WIRE_HEX. Returns the relayed wire bytes, the verified
/// upstream identity, the relay identity, and C's link (B configured as peer).
fn relay_origin_to_dest() -> (Vec<u8>, PeerIdentity, Identity, LinkLayer) {
    let origin = Identity::from_seed(Seed::new([0x11; 32]));
    let relay_identity = Identity::from_seed(Seed::new([0x22; 32]));
    let dest = Identity::from_seed(Seed::new([0x33; 32]));
    let mut relay = LinkLayer::new(relay_identity.clone());
    let mut dest_link = node(0x33);
    relay.add_peer(PeerIdentity::from_pubkey(origin.pubkey));
    dest_link.add_peer(PeerIdentity::from_pubkey(relay_identity.pubkey));

    let eui_b = eui64(&relay_identity);
    let eui_c = eui64(&dest);
    let mut inbound = [0u8; 256];
    let n = node(0x11)
        .build_frame(3, seq(9), &eui_b, b"relay-me", &mut inbound)
        .unwrap();

    let mut out = [0xA5u8; 256];
    let outcome = relay
        .relay_verified_frame(
            &inbound[..n],
            &eui_c,
            AddrMode::Extended,
            None,
            7,
            seq(0x1234),
            &mut out,
        )
        .expect("relay accepts authentic inbound");
    assert_eq!(outcome.upstream.pubkey.as_bytes(), origin.pubkey.as_bytes());
    (
        out[..outcome.len].to_vec(),
        outcome.upstream,
        relay_identity,
        dest_link,
    )
}

#[test]
fn relayed_wire_matches_independent_python_reference() {
    let (relayed, _, relay_identity, _) = relay_origin_to_dest();
    let expected = hex(EXPECTED_RELAYED_WIRE_HEX);
    assert_eq!(
        relayed, expected,
        "relay re-sign output must equal the independent Python reference"
    );

    // Structural checks against the same oracle constants.
    let frame = LichenFrame::from_bytes(&relayed).unwrap();
    assert_eq!(frame.signer_eui64, hex(EUI_B_HEX).as_slice());
    assert_eq!(frame.dst_addr, hex(EUI_C_HEX).as_slice());
    assert_eq!(frame.payload, b"relay-me");
    assert_eq!(frame.epoch, 7);
    assert_eq!(frame.seqnum.get(), 0x1234);

    // The relay's own canonical EUI-64 derivation matches the oracle too.
    assert_eq!(eui64(&relay_identity), hex(EUI_B_HEX).as_slice());
    assert_eq!(
        relay_identity.pubkey.as_bytes(),
        hex(RELAY_B_PUBKEY_HEX).as_slice()
    );
    assert_eq!(
        PublicKey::new(hex(ORIGIN_A_PUBKEY_HEX).try_into().unwrap()).as_bytes(),
        hex(ORIGIN_A_PUBKEY_HEX).as_slice()
    );
}

#[test]
fn next_hop_accepts_relayed_frame_and_relay_counter_is_relays_own() {
    let (relayed, _, relay_identity, mut dest_link) = relay_origin_to_dest();
    let received = dest_link
        .receive_frame(&relayed)
        .expect("dest accepts re-signed frame");
    assert_eq!(received.payload(), b"relay-me");
    assert_eq!(
        received.sender().pubkey.as_bytes(),
        relay_identity.pubkey.as_bytes(),
        "downstream trust must bind to the RELAY's key, not the origin's"
    );
    assert_eq!(received.seqnum(), seq(0x1234));

    // The relay allocated its own replay counter; replaying the identical
    // relayed frame at the destination is rejected.
    assert!(matches!(
        dest_link.receive_frame(&relayed),
        Err(lichen_link::LinkRxError::Replay)
    ));
}

#[test]
fn relay_never_forwards_inbound_signature() {
    let origin = Identity::from_seed(Seed::new([0x11; 32]));
    let relay_identity = Identity::from_seed(Seed::new([0x22; 32]));
    let dest = Identity::from_seed(Seed::new([0x33; 32]));
    let mut relay = LinkLayer::new(relay_identity.clone());
    relay.add_peer(PeerIdentity::from_pubkey(origin.pubkey));
    let eui_b = eui64(&relay_identity);
    let eui_c = eui64(&dest);

    let mut inbound = [0u8; 256];
    let n = node(0x11)
        .build_frame(3, seq(9), &eui_b, b"relay-me", &mut inbound)
        .unwrap();
    let inbound_mic = LichenFrame::from_bytes(&inbound[..n]).unwrap().mic.to_vec();

    let mut out = [0u8; 256];
    let outcome = relay
        .relay_verified_frame(
            &inbound[..n],
            &eui_c,
            AddrMode::Extended,
            None,
            7,
            seq(0x1234),
            &mut out,
        )
        .unwrap();
    let relayed_wire = &out[..outcome.len];
    let relayed = LichenFrame::from_bytes(relayed_wire).unwrap();
    assert_ne!(
        relayed.mic,
        inbound_mic.as_slice(),
        "the inbound MIC must never be forwarded"
    );
    // The fresh MIC verifies only under the relay's own key.
    let length = relayed_wire[0];
    assert!(verify_frame(
        length,
        relayed.llsec_byte(),
        relayed.epoch,
        relayed.seqnum,
        relayed.dst_addr,
        relayed.signer_eui64,
        relayed.payload,
        relayed.mic,
        &relay_identity.pubkey,
    ));
    assert!(
        !verify_frame(
            length,
            relayed.llsec_byte(),
            relayed.epoch,
            relayed.seqnum,
            relayed.dst_addr,
            relayed.signer_eui64,
            relayed.payload,
            relayed.mic,
            &origin.pubkey,
        ),
        "re-signed frame must not verify under the origin's key"
    );
}

#[test]
fn tampered_inbound_is_rejected_before_any_emission() {
    let origin = Identity::from_seed(Seed::new([0x11; 32]));
    let relay_identity = Identity::from_seed(Seed::new([0x22; 32]));
    let dest = Identity::from_seed(Seed::new([0x33; 32]));
    let mut relay = LinkLayer::new(relay_identity.clone());
    relay.add_peer(PeerIdentity::from_pubkey(origin.pubkey));
    let eui_b = eui64(&relay_identity);
    let eui_c = eui64(&dest);

    let mut inbound = [0u8; 256];
    let n = node(0x11)
        .build_frame(3, seq(9), &eui_b, b"relay-me", &mut inbound)
        .unwrap();

    // Payload tamper (last payload byte sits just before the 48-byte MIC).
    let mut tampered = inbound;
    tampered[n - 49] ^= 0x01;
    let mut out = [0xA5u8; 256];
    let result = relay.relay_verified_frame(
        &tampered[..n],
        &eui_c,
        AddrMode::Extended,
        None,
        7,
        seq(0x1234),
        &mut out,
    );
    assert!(
        matches!(result, Err(RelayError::Inbound(_))),
        "bad signature must fail before mutation"
    );
    assert!(
        out.iter().all(|&b| b == 0xA5),
        "output buffer must be untouched after verification failure"
    );

    // Signature-bit tamper.
    let mut bad_sig = inbound;
    bad_sig[n - 1] ^= 0x80;
    let mut out = [0xA5u8; 256];
    assert!(matches!(
        relay.relay_verified_frame(
            &bad_sig[..n],
            &eui_c,
            AddrMode::Extended,
            None,
            7,
            seq(0x1234),
            &mut out,
        ),
        Err(RelayError::Inbound(_))
    ));
    assert!(out.iter().all(|&b| b == 0xA5));

    // Header tamper (epoch).
    let mut bad_epoch = inbound;
    bad_epoch[2] ^= 0x01;
    let mut out = [0xA5u8; 256];
    assert!(matches!(
        relay.relay_verified_frame(
            &bad_epoch[..n],
            &eui_c,
            AddrMode::Extended,
            None,
            7,
            seq(0x1234),
            &mut out,
        ),
        Err(RelayError::Inbound(_))
    ));
    assert!(out.iter().all(|&b| b == 0xA5));
}

#[test]
fn unsigned_unknown_and_replayed_inbound_fail_before_emission() {
    let origin = Identity::from_seed(Seed::new([0x11; 32]));
    let relay_identity = Identity::from_seed(Seed::new([0x22; 32]));
    let dest = Identity::from_seed(Seed::new([0x33; 32]));
    let stranger = Identity::from_seed(Seed::new([0x55; 32]));
    let mut relay = LinkLayer::new(relay_identity.clone());
    relay.add_peer(PeerIdentity::from_pubkey(origin.pubkey));
    let eui_b = eui64(&relay_identity);
    let eui_c = eui64(&dest);

    let mut out = [0xA5u8; 256];
    let relay_args = (&eui_c as &[u8], AddrMode::Extended, 7u8, seq(0x1234));

    // Unsigned broadcast frame (no MIC): parsed OK, rejected as Unsigned.
    let unsigned = [0x05u8, 0x00, 0x01, 0x00, 0x01, b'x'];
    assert!(LichenFrame::from_bytes(&unsigned).unwrap().mic.is_empty());
    assert!(matches!(
        relay.relay_verified_frame(
            &unsigned,
            relay_args.0,
            relay_args.1,
            None,
            relay_args.2,
            relay_args.3,
            &mut out,
        ),
        Err(RelayError::Inbound(lichen_link::LinkRxError::Unsigned))
    ));
    assert!(out.iter().all(|&b| b == 0xA5));

    // Validly signed by a node that is NOT a pinned peer.
    let mut stranger_wire = [0u8; 256];
    let n = node(0x55)
        .build_frame(3, seq(9), &eui_b, b"relay-me", &mut stranger_wire)
        .unwrap();
    drop(stranger);
    assert!(matches!(
        relay.relay_verified_frame(
            &stranger_wire[..n],
            relay_args.0,
            relay_args.1,
            None,
            relay_args.2,
            relay_args.3,
            &mut out,
        ),
        Err(RelayError::Inbound(lichen_link::LinkRxError::UnknownSender))
    ));
    assert!(out.iter().all(|&b| b == 0xA5));

    // Genuine frame accepted once; identical replay rejected before emission.
    let mut inbound = [0u8; 256];
    let n = node(0x11)
        .build_frame(3, seq(9), &eui_b, b"relay-me", &mut inbound)
        .unwrap();
    let first = relay.relay_verified_frame(
        &inbound[..n],
        relay_args.0,
        relay_args.1,
        None,
        relay_args.2,
        relay_args.3,
        &mut out,
    );
    assert!(first.is_ok());
    let written = out[..first.unwrap().len].to_vec();
    let mut replay_out = [0xA5u8; 256];
    assert!(matches!(
        relay.relay_verified_frame(
            &inbound[..n],
            relay_args.0,
            relay_args.1,
            None,
            relay_args.2,
            relay_args.3,
            &mut replay_out,
        ),
        Err(RelayError::Inbound(lichen_link::LinkRxError::Replay))
    ));
    assert!(replay_out.iter().all(|&b| b == 0xA5));
    drop(written);
    drop(dest);
}

#[test]
fn permitted_mutation_flows_through_resign_after_verification() {
    let origin = Identity::from_seed(Seed::new([0x11; 32]));
    let relay_identity = Identity::from_seed(Seed::new([0x22; 32]));
    let dest = Identity::from_seed(Seed::new([0x33; 32]));
    let mut relay = LinkLayer::new(relay_identity.clone());
    let mut dest_link = node(0x33);
    relay.add_peer(PeerIdentity::from_pubkey(origin.pubkey));
    dest_link.add_peer(PeerIdentity::from_pubkey(relay_identity.pubkey));
    let eui_b = eui64(&relay_identity);
    let eui_c = eui64(&dest);

    let mut inbound = [0u8; 256];
    let n = node(0x11)
        .build_frame(3, seq(9), &eui_b, b"\x40relay-me", &mut inbound)
        .unwrap();

    // Simulate a Hop-Limit decrement inside the payload, applied by the
    // routing layer AFTER the relay's own verification succeeded.
    let mut mutated = b"\x40relay-me".to_vec();
    mutated[0] = 0x3F;
    let mut out = [0u8; 256];
    let outcome = relay
        .relay_verified_frame(
            &inbound[..n],
            &eui_c,
            AddrMode::Extended,
            Some(&mutated),
            7,
            seq(0x1234),
            &mut out,
        )
        .unwrap();

    let received = dest_link
        .receive_frame(&out[..outcome.len])
        .expect("mutated+resigned frame authenticates downstream");
    assert_eq!(received.payload(), mutated.as_slice());
    assert_ne!(received.payload(), b"\x40relay-me");
}

#[test]
fn tamper_after_sign_is_detected_downstream() {
    let (relayed, _, _, mut dest_link) = relay_origin_to_dest();
    let total = relayed.len();

    // Every single-byte flip anywhere in the re-signed frame must be caught:
    // header, destination, payload, and signature.
    for idx in [
        0usize,
        1,
        2,
        4,
        5,
        total / 2,
        total - 49,
        total - 48,
        total - 1,
    ] {
        let mut tampered = relayed.clone();
        tampered[idx] ^= 0x01;
        assert!(
            dest_link.receive_frame(&tampered).is_err(),
            "tampered byte {} must be detected downstream",
            idx
        );
    }

    // The pristine frame still passes afterwards (failures were per-copy).
    // Note: each successful accept advances B's window at C, so only count
    // the pristine acceptance once.
    let mut fresh_dest = node(0x33);
    fresh_dest.add_peer(PeerIdentity::from_pubkey(
        Identity::from_seed(Seed::new([0x22; 32])).pubkey,
    ));
    assert!(fresh_dest.receive_frame(&relayed).is_ok());
}

// ─── Canonical corpus: relay accepts the independent reference frame ────────

#[derive(Deserialize)]
struct VectorFile {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    encoded: String,
    crypto: Option<CryptoMeta>,
}

#[derive(Deserialize)]
struct CryptoMeta {
    public_key: String,
    signature: String,
}

#[test]
fn canonical_vector_frame_verifies_through_relay_path_then_is_resigned() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test/vectors/link_frame.json");
    let content = fs::read_to_string(path).expect("read canonical link-frame vectors");
    let vectors: VectorFile = serde_json::from_str(&content).expect("parse vectors");
    let vector = vectors
        .vectors
        .iter()
        .find(|v| v.name == "short_addr_signed")
        .expect("canonical short_addr_signed vector");
    let crypto = vector.crypto.as_ref().expect("crypto metadata");
    let wire = hex(&vector.encoded);
    let origin_pubkey = PublicKey::new(hex(&crypto.public_key).try_into().unwrap());

    let relay_identity = Identity::from_seed(Seed::new([0x44; 32]));
    let mut relay = LinkLayer::new(relay_identity.clone());
    relay.add_peer(PeerIdentity::from_pubkey(origin_pubkey));

    let mut out = [0xA5u8; 256];
    let outcome = relay
        .relay_verified_frame(
            &wire,
            &[0x12, 0x34],
            AddrMode::Short,
            None,
            2,
            seq(77),
            &mut out,
        )
        .expect("canonical reference frame must pass relay verification");

    let relayed = &out[..outcome.len];
    let frame = LichenFrame::from_bytes(relayed).unwrap();
    // Re-signed: different signer, different MIC than the canonical one.
    assert_ne!(frame.mic, hex(&crypto.signature).as_slice());
    assert_eq!(frame.signer_eui64, eui64(&relay_identity));
    assert_eq!(frame.payload, b"hello!");
    assert!(verify_frame(
        relayed[0],
        frame.llsec_byte(),
        frame.epoch,
        frame.seqnum,
        frame.dst_addr,
        frame.signer_eui64,
        frame.payload,
        frame.mic,
        &relay_identity.pubkey,
    ));

    // Tamper-after-sign on this path too: downstream rejects.
    let mut tampered = relayed.to_vec();
    tampered[relayed.len() - 49] ^= 0x10;
    if let Ok(tampered_frame) = LichenFrame::from_bytes(&tampered) {
        assert!(
            !verify_frame(
                tampered[0],
                tampered_frame.llsec_byte(),
                tampered_frame.epoch,
                tampered_frame.seqnum,
                tampered_frame.dst_addr,
                tampered_frame.signer_eui64,
                tampered_frame.payload,
                tampered_frame.mic,
                &relay_identity.pubkey,
            ),
            "tampered re-signed frame must not verify"
        );
    } else {
        // Structural rejection is equally acceptable.
    }
}
