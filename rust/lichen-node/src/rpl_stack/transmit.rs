// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Packet transmission methods.

use std::vec::Vec;

use lichen_core::announce::Announce;
use lichen_core::ipv6::{next_header, IPV6_HEADER_LEN};
use lichen_hal::{NonVolatile, Radio, RadioConfig};
use lichen_ipv6::Ipv6Header;
use lichen_link::identity::iid_from_pubkey;
use lichen_link::schnorr;
use lichen_rpl::routing::DaoTxError;

use crate::node::{rpl_code, valid_ipv6_envelope};
use crate::stack::TxError;

use super::error::{DaoSendError, RplControlError};
use super::util::{dao_ipv6_packet, ipv6_eui64, ipv6_l2_destination, rpl_ipv6_packet};
use super::{RplRole, RplStack};

impl<R: Radio, S: NonVolatile> RplStack<R, S> {
    pub fn configure_radio(&mut self, config: &RadioConfig) {
        self.stack.radio().configure(config);
    }

    pub async fn send_announce(
        &mut self,
        announce_wire: &[u8],
        _now_ms: u32,
    ) -> Result<(), RplControlError> {
        let announce =
            Announce::from_bytes(announce_wire).map_err(|_| RplControlError::MalformedAnnounce)?;
        let local_key = self.stack.local_public_key();
        let mut signed = [0u8; 256];
        let signed_len = announce
            .write_signed_data(&mut signed)
            .map_err(|_| RplControlError::MalformedAnnounce)?;
        if *announce.originator_iid != iid_from_pubkey(&local_key)
            || *announce.pubkey != *local_key.as_bytes()
            || !schnorr::verify(&local_key, &signed[..signed_len], announce.signature)
        {
            return Err(RplControlError::MalformedAnnounce);
        }
        let mut payload = Vec::with_capacity(announce_wire.len() + 1);
        payload.push(lichen_core::constants::L2_DISPATCH_ROUTING);
        payload.extend_from_slice(announce_wire);
        self.stack
            .send_l2_payload_to(&payload, &[])
            .await
            .map_err(RplControlError::Transmit)
    }

    pub async fn send_dio(&mut self, destination: [u8; 16]) -> Result<(), TxError> {
        let mut body = [0u8; 64];
        let len = self.rpl.build_dio(&mut body);
        if len == 0 {
            return Err(TxError::BufferTooSmall);
        }
        let packet = rpl_ipv6_packet(
            self.local_rpl_addr,
            destination,
            rpl_code::DIO,
            &body[..len],
        )
        .ok_or(TxError::BufferTooSmall)?;
        let l2_destination = ipv6_l2_destination(destination);
        self.stack
            .send_ipv6_to(
                &packet,
                l2_destination.as_ref().map_or(&[], <[u8; 8]>::as_slice),
            )
            .await
    }

    pub async fn send_dis(&mut self, destination: [u8; 16]) -> Result<(), TxError> {
        let packet = rpl_ipv6_packet(self.local_rpl_addr, destination, rpl_code::DIS, &[0, 0])
            .ok_or(TxError::BufferTooSmall)?;
        let l2_destination = ipv6_l2_destination(destination);
        self.stack
            .send_ipv6_to(
                &packet,
                l2_destination.as_ref().map_or(&[], <[u8; 8]>::as_slice),
            )
            .await
    }

    pub async fn send_dao(&mut self) -> Result<(), DaoSendError<S::Error>> {
        let RplRole::Leaf(tx) = &mut self.role else {
            return Err(DaoSendError::NotLeaf);
        };
        let dao = if let Some(dao) = tx.last_signed_dao() {
            dao.to_vec()
        } else {
            self.rpl
                .build_signed_dao(
                    self.local_rpl_addr,
                    tx,
                    &mut self.storage,
                    self.stack.link(),
                )
                .map_err(DaoSendError::Dao)?
        };
        self.transmit_dao(&dao).await?;
        let RplRole::Leaf(tx) = &mut self.role else {
            unreachable!("DAO sender role changed during transmission")
        };
        tx.clear_transmitted(&mut self.storage)
            .map_err(DaoSendError::Dao)
    }

    async fn transmit_dao(&mut self, dao: &[u8]) -> Result<(), DaoSendError<S::Error>> {
        let dodag_id = self.rpl.router.dodag_id();
        let next_hop = self
            .rpl
            .preferred_parent()
            .ok_or(DaoSendError::Dao(DaoTxError::NotJoined))?;
        let packet = dao_ipv6_packet(self.local_rpl_addr, dodag_id, dao)
            .ok_or(DaoSendError::PacketTooLarge)?;
        self.stack
            .send_ipv6_to(&packet, &ipv6_eui64(next_hop))
            .await
            .map_err(DaoSendError::Transmit)
    }

    /// Send a non-CoAP IPv6 diagnostic through the selected RPL/gradient next hop.
    pub async fn send_ipv6(&mut self, ipv6: &[u8], now_ms: u64) -> Result<(), TxError> {
        let header = Ipv6Header::from_bytes(ipv6).map_err(|_| TxError::BufferTooSmall)?;
        if !valid_ipv6_envelope(ipv6) {
            return Err(TxError::BufferTooSmall);
        }
        if header.next_header == next_header::UDP {
            let udp = lichen_ipv6::UdpHeader::from_bytes(&ipv6[IPV6_HEADER_LEN..])
                .map_err(|_| TxError::BufferTooSmall)?;
            if udp.src_port == lichen_core::constants::PORT_COAP
                || udp.dst_port == lichen_core::constants::PORT_COAP
            {
                return Err(TxError::PlaintextCoap);
            }
        } else if matches!(header.next_header, 0 | 43 | 44 | 50 | 51 | 60) {
            return Err(TxError::UnsupportedIpv6Extension);
        }
        let route = self
            .route_for(header.dst.0, now_ms, false)
            .ok_or(TxError::NoRoute)?;
        self.stack
            .send_ipv6_to_route(ipv6, &route.next_hop, &route.source_route)
            .await
    }

    pub fn last_signed_dao(&self) -> Option<&[u8]> {
        match &self.role {
            RplRole::Leaf(state) => state.last_signed_dao(),
            RplRole::Root(_) => None,
        }
    }
}
