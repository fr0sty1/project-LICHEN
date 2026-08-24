// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! IPv6 and L2 address utility functions.

use std::vec;
use std::vec::Vec;

use lichen_core::announce::Announce;
use lichen_core::constants::RPL_ICMPV6_TYPE;
use lichen_core::icmpv6::hdr_field;
use lichen_core::ipv6::{field, next_header, IPV6_HEADER_LEN};
use lichen_core::l2_payload::{
    body as l2_payload_body, classify as classify_l2_payload, L2PayloadKind,
    L2_ROUTING_TYPE_ANNOUNCE,
};
use lichen_ipv6::{icmpv6_checksum, Addr, Ipv6Header};
use lichen_link::frame::{AddrMode, LichenFrame};
use lichen_link::identity::PeerIdentity;
use lichen_link::link_layer::LinkRxError;
use lichen_link::schnorr;
use lichen_schc::codec;

use crate::announce::AnnounceRejectReason;
use crate::node::{claims_rpl_ipv6, rpl_code};
use crate::stack::RxError;

pub(crate) const RPL_ALL_NODES: [u8; 16] =
    [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1a];

pub(crate) fn ipv6_eui64(address: [u8; 16]) -> [u8; 8] {
    let mut eui64: [u8; 8] = address[8..].try_into().unwrap();
    eui64[0] ^= 0x02;
    eui64
}

pub(crate) fn ipv6_l2_destination(address: [u8; 16]) -> Option<[u8; 8]> {
    (address[0] != 0xff).then(|| ipv6_eui64(address))
}

pub(crate) fn link_local_from_iid(iid: [u8; 8]) -> [u8; 16] {
    let mut address = [0u8; 16];
    address[0] = 0xfe;
    address[1] = 0x80;
    address[8..].copy_from_slice(&iid);
    address
}

pub(crate) fn eui64_link_local(mut eui64: [u8; 8]) -> [u8; 16] {
    eui64[0] ^= 0x02;
    link_local_from_iid(eui64)
}

pub(crate) fn rpl_ipv6_packet(
    source: [u8; 16],
    destination: [u8; 16],
    code: u8,
    body: &[u8],
) -> Option<Vec<u8>> {
    let payload_len = hdr_field::BODY_OFFSET.checked_add(body.len())?;
    let payload_len = u16::try_from(payload_len).ok()?;
    let mut packet = vec![0u8; IPV6_HEADER_LEN + usize::from(payload_len)];
    let src = Addr(source);
    let dst = Addr(destination);
    Ipv6Header::new(next_header::ICMPV6, src, dst)
        .write_to(payload_len, &mut packet[..IPV6_HEADER_LEN])
        .ok()?;
    packet[IPV6_HEADER_LEN] = RPL_ICMPV6_TYPE;
    packet[IPV6_HEADER_LEN + 1] = code;
    packet[IPV6_HEADER_LEN + hdr_field::BODY_OFFSET..].copy_from_slice(body);
    let checksum = icmpv6_checksum(&src, &dst, &packet[IPV6_HEADER_LEN..]).ok()?;
    packet[IPV6_HEADER_LEN + 2..IPV6_HEADER_LEN + 4].copy_from_slice(&checksum.to_be_bytes());
    Some(packet)
}

pub(crate) fn dao_ipv6_packet(
    source: [u8; 16],
    destination: [u8; 16],
    dao: &[u8],
) -> Option<Vec<u8>> {
    rpl_ipv6_packet(source, destination, rpl_code::DAO, dao)
}

pub(crate) fn dao_parts(ipv6: &[u8]) -> Option<([u8; 16], &[u8])> {
    use crate::node::valid_rpl_ipv6;

    if !valid_rpl_ipv6(ipv6) || ipv6[IPV6_HEADER_LEN + 1] != rpl_code::DAO {
        return None;
    }
    let source = ipv6[field::SRC_OFFSET..field::DST_OFFSET].try_into().ok()?;
    Some((source, &ipv6[IPV6_HEADER_LEN + hdr_field::BODY_OFFSET..]))
}

pub(crate) fn multicast_dis_jitter(local_eui64: [u8; 8], source: [u8; 16], now_ms: u64) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for byte in local_eui64
        .into_iter()
        .chain(source)
        .chain(now_ms.to_be_bytes())
    {
        hash = (hash ^ u32::from(byte)).wrapping_mul(0x0100_0193);
    }
    hash
}

pub(crate) fn bootstrap_announce_peer(wire: &[u8]) -> Option<PeerIdentity> {
    let frame = LichenFrame::from_bytes(wire).ok()?;
    if !frame.signature.is_present() {
        return None;
    }
    let inner = frame.payload;
    let announce = Announce::from_bytes(routing_announce(inner).ok()?).ok()?;
    let peer = PeerIdentity::from_pubkey(lichen_link::keys::PublicKey::new(*announce.pubkey));
    let mut expected_signer_eui64 = peer.iid;
    expected_signer_eui64[0] ^= 0x02;
    if peer.iid != *announce.originator_iid
        || frame.signer_eui64 != expected_signer_eui64
        || !schnorr::verify_frame(
            wire[0],
            wire[1],
            frame.epoch,
            frame.seqnum,
            frame.dst_addr,
            frame.signer_eui64,
            frame.payload,
            frame.mic,
            &peer.pubkey,
        )
    {
        return None;
    }
    Some(peer)
}

pub(crate) fn routing_announce(payload: &[u8]) -> Result<&[u8], AnnounceRejectReason> {
    if classify_l2_payload(payload) != L2PayloadKind::Routing {
        return Err(AnnounceRejectReason::Malformed);
    }
    let body = l2_payload_body(payload);
    match body.first() {
        Some(&L2_ROUTING_TYPE_ANNOUNCE) => Ok(body),
        Some(_) | None => Err(AnnounceRejectReason::Malformed),
    }
}

pub(crate) fn wire_is_for_local(wire: &[u8], local_eui64: [u8; 8]) -> Result<bool, LinkRxError> {
    let frame = LichenFrame::from_bytes(wire)?;
    Ok(match frame.addr_mode {
        AddrMode::None => inspect_schc_ipv6(&frame)
            .is_none_or(|ipv6| !claims_rpl_ipv6(&ipv6) || rpl_ipv6_multicast_is_allowed(&ipv6)),
        AddrMode::Short => false,
        AddrMode::Extended => frame.dst_addr == local_eui64,
        AddrMode::Elided => inspect_schc_ipv6(&frame).is_some_and(|ipv6| {
            if claims_rpl_ipv6(&ipv6) {
                return rpl_ipv6_multicast_is_allowed(&ipv6)
                    && ipv6_destination(&ipv6).is_some_and(|destination| {
                        destination[0] == 0xff || ipv6_eui64(destination) == local_eui64
                    });
            }
            let destination: [u8; 16] =
                ipv6[field::DST_OFFSET..IPV6_HEADER_LEN].try_into().unwrap();
            destination[0] == 0xff || ipv6_eui64(destination) == local_eui64
        }),
    })
}

fn inspect_schc_ipv6(frame: &LichenFrame<'_>) -> Option<Vec<u8>> {
    if !frame.signature.is_present() {
        return None;
    }
    let inner = frame.payload;
    if classify_l2_payload(inner) != L2PayloadKind::Schc {
        return None;
    }
    let mut ipv6 = vec![0u8; 256];
    let len = codec::decompress(l2_payload_body(inner), &mut ipv6).ok()?;
    if len < IPV6_HEADER_LEN || ipv6[0] >> 4 != 6 {
        return None;
    }
    ipv6.truncate(len);
    Some(ipv6)
}

pub(crate) fn ipv6_destination(ipv6: &[u8]) -> Option<[u8; 16]> {
    ipv6.get(field::DST_OFFSET..IPV6_HEADER_LEN)
        .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
}

pub(crate) fn rpl_ipv6_multicast_is_allowed(ipv6: &[u8]) -> bool {
    ipv6_destination(ipv6)
        .is_some_and(|destination| destination[0] != 0xff || destination == RPL_ALL_NODES)
}

pub(crate) fn dio_dis_destination_is_allowed(ipv6: &[u8], local_rpl_addr: [u8; 16]) -> bool {
    let Some(code) = ipv6.get(IPV6_HEADER_LEN + hdr_field::CODE_OFFSET) else {
        return false;
    };
    if !matches!(*code, rpl_code::DIO | rpl_code::DIS) {
        return true;
    }
    let canonical_source = ipv6
        .get(field::SRC_OFFSET..field::DST_OFFSET)
        .is_some_and(|source| source[..8] == [0xfe, 0x80, 0, 0, 0, 0, 0, 0]);
    canonical_source
        && ipv6_destination(ipv6).is_some_and(|destination| {
            destination == RPL_ALL_NODES
                || (destination[..8] == [0xfe, 0x80, 0, 0, 0, 0, 0, 0]
                    && destination[8..] == local_rpl_addr[8..])
        })
}

pub(crate) fn advance_rpl_source_route(
    ipv6: &mut Vec<u8>,
    current_destination: [u8; 16],
    sender_iid: [u8; 8],
) -> Result<Option<[u8; 16]>, RxError> {
    if ipv6.len() < 64 || ipv6[6] != 43 || ipv6[24..40] != current_destination {
        return Err(RxError::InvalidSourceRoute);
    }
    let payload_len = usize::from(u16::from_be_bytes([ipv6[4], ipv6[5]]));
    let routing_len = (usize::from(ipv6[41]) + 1) * 8;
    if routing_len < 24
        || routing_len > payload_len
        || (routing_len - 8) % 16 != 0
        || IPV6_HEADER_LEN + payload_len != ipv6.len()
        || ipv6[42] != 3
        || ipv6[44..48] != [0, 0, 0, 0]
    {
        return Err(RxError::InvalidSourceRoute);
    }
    let address_count = (routing_len - 8) / 16;
    let segments_left = usize::from(ipv6[43]);
    if segments_left > address_count {
        return Err(RxError::InvalidSourceRoute);
    }
    for index in 0..address_count {
        let start = 48 + index * 16;
        let address: [u8; 16] = ipv6[start..start + 16].try_into().unwrap();
        if address[0] == 0xff || address == current_destination {
            return Err(RxError::InvalidSourceRoute);
        }
        for prior in 0..index {
            let prior_start = 48 + prior * 16;
            if ipv6[prior_start..prior_start + 16] == address {
                return Err(RxError::InvalidSourceRoute);
            }
        }
    }

    if segments_left == 0 {
        let plain_payload_len = payload_len - routing_len;
        let mut plain = vec![0u8; IPV6_HEADER_LEN + plain_payload_len];
        plain[..IPV6_HEADER_LEN].copy_from_slice(&ipv6[..IPV6_HEADER_LEN]);
        plain[4..6].copy_from_slice(&(plain_payload_len as u16).to_be_bytes());
        plain[6] = ipv6[40];
        plain[IPV6_HEADER_LEN..].copy_from_slice(&ipv6[IPV6_HEADER_LEN + routing_len..]);
        *ipv6 = plain;
        return Ok(None);
    }

    let next_index = address_count - segments_left;
    let next_start = 48 + next_index * 16;
    let next_destination: [u8; 16] = ipv6[next_start..next_start + 16].try_into().unwrap();
    if ipv6_eui64(next_destination) == ipv6_eui64(link_local_from_iid(sender_iid)) {
        return Err(RxError::InvalidSourceRoute);
    }
    ipv6[next_start..next_start + 16].copy_from_slice(&current_destination);
    ipv6[24..40].copy_from_slice(&next_destination);
    ipv6[43] -= 1;
    Ok(Some(next_destination))
}
