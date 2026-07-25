// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! OSCORE/secure CoAP methods.

use lichen_hal::{NonVolatile, Radio};
use lichen_ipv6::Addr;
use lichen_oscore::{Context, SenderStateStore};

use crate::secure::{
    secure_datagram_from_received, ReceivedSecureDatagram, RequestCorrelation, SecureError,
    SecureRequest, SecureResponse, SecureResponseData, SecureRoute,
};
use crate::stack::{ReceivedIpv6, RxError, TxError};

use super::RplStack;

impl<R: Radio, S: NonVolatile> RplStack<R, S> {
    /// Atomically register a newly established OSCORE context.
    ///
    /// `peer_iid` is the authoritative IPv6 identity binding for the context.
    pub fn register_fresh_context<T: SenderStateStore>(
        &mut self,
        peer_iid: [u8; 8],
        context: Context,
        store: &mut T,
    ) -> Result<(), SecureError> {
        self.stack.register_fresh_context(peer_iid, context, store)
    }

    /// Restore authoritative sender state for an existing OSCORE context.
    ///
    /// `peer_iid` must match the IPv6 identity originally bound to the context.
    pub fn restore_context<T: SenderStateStore>(
        &mut self,
        peer_iid: [u8; 8],
        context: Context,
        store: &mut T,
    ) -> Result<(), SecureError> {
        self.stack.restore_context(peer_iid, context, store)
    }

    /// Send OSCORE-protected CoAP through the single RPL/link owner.
    pub async fn send_secure_get<T: SenderStateStore>(
        &mut self,
        dst: &Addr,
        peer_iid: &[u8; 8],
        uri_path: &[&str],
        token: &[u8],
        store: &mut T,
        now_ms: u64,
    ) -> Result<RequestCorrelation, SecureError> {
        let route = self
            .route_for(dst.0, now_ms, false)
            .ok_or(SecureError::Tx(TxError::NoRoute))?;
        self.stack
            .send_secure_get_to(
                SecureRoute {
                    source: &Addr(self.local_rpl_addr),
                    destination: dst,
                    l2_destination: &route.next_hop,
                    source_route: &route.source_route,
                },
                peer_iid,
                uri_path,
                token,
                store,
            )
            .await
    }

    /// Authenticate and decrypt a response received through this owner.
    pub async fn decrypt_response(
        &mut self,
        received: &ReceivedSecureDatagram,
        correlation: &mut RequestCorrelation,
        now_ms: u64,
    ) -> Result<SecureResponse, SecureError> {
        self.routing_now_ms = self.routing_now_ms.max(now_ms);
        let source = received.destination();
        let destination = received.source();
        if received.requires_ack() {
            match self
                .stack
                .decrypt_response_to(None, received, correlation)
                .await
            {
                Err(SecureError::Tx(TxError::NoRoute)) => {}
                result => return result,
            }
        }
        let route = if received.requires_ack() {
            let plan = self
                .route_for(destination.0, self.routing_now_ms, false)
                .ok_or(SecureError::Tx(TxError::NoRoute))?;
            Some((plan.next_hop, plan.source_route))
        } else {
            None
        };
        self.stack
            .decrypt_response_to(
                route.as_ref().map(|(next_hop, source_route)| SecureRoute {
                    source: &source,
                    destination: &destination,
                    l2_destination: next_hop,
                    source_route,
                }),
                received,
                correlation,
            )
            .await
    }

    /// Authenticate and decrypt a request received through this owner.
    pub fn decrypt_request(
        &mut self,
        received: &ReceivedSecureDatagram,
    ) -> Result<SecureRequest, SecureError> {
        self.stack.decrypt_request(received)
    }

    /// Classify an already received IPv6 datagram as protected CoAP.
    pub fn secure_datagram(
        &self,
        received: &ReceivedIpv6,
    ) -> Result<Option<ReceivedSecureDatagram>, RxError> {
        secure_datagram_from_received(received)
    }

    /// Protect and route a response bound to a decrypted request.
    pub async fn send_secure_response<T: SenderStateStore>(
        &mut self,
        dst: &Addr,
        peer_iid: &[u8; 8],
        request: &SecureRequest,
        response: SecureResponseData<'_>,
        store: &mut T,
        now_ms: u64,
    ) -> Result<(), SecureError> {
        let route = self
            .route_for(dst.0, now_ms, false)
            .ok_or(SecureError::Tx(TxError::NoRoute))?;
        self.stack
            .send_secure_response_to(
                SecureRoute {
                    source: &Addr(self.local_rpl_addr),
                    destination: dst,
                    l2_destination: &route.next_hop,
                    source_route: &route.source_route,
                },
                peer_iid,
                request,
                response,
                store,
            )
            .await
    }
}
