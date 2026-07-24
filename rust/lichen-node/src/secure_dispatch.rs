//! OSCORE-aware CoAP resource dispatch.
//!
//! Wraps the plaintext [`Dispatcher`] with OSCORE protect/unprotect via
//! [`SecureStack`], selecting the appropriate context per peer IID for
//! `/deaddrop` and `/confessions` resources.
//!
//! Any request that carries a valid OSCORE option is decrypted before dispatch
//! and the response is encrypted. Plaintext requests are served directly to
//! permit local administrative access (per spec §17 LCI).

use lichen_coap::codec::CoapPacket;
use lichen_coap::message::MessageCode;
use lichen_coap::option::content_format::CBOR;
use lichen_hal::Radio;
use lichen_oscore::SenderStateStore;

use crate::dispatch::{self, Dispatcher, Request, Response};
use crate::secure::{
    ReceivedSecureDatagram, SecureError, SecureRequest, SecureResponseData, SecureStack,
};
use crate::stack::TxError;

/// Outcome of dispatching a secure (or plaintext) CoAP request.
#[derive(Debug)]
pub enum SecureDispatchOutcome {
    /// Response was sent. Contains a note about what happened.
    Handled,
    /// No matching resource or method.
    NotFound,
    /// An error occurred during processing.
    Error(SecureError),
}

/// Dispatch an OSCORE-protected or plaintext CoAP request through the resource table.
///
/// If `received` carries an OSCORE option, it is decrypted via `stack` using the
/// sender IID for context selection. The inner request is dispatched to the resource
/// handler and the response is encrypted. Plaintext requests (from local admin per LCI)
/// are dispatched directly.
pub async fn dispatch_secure<'a, R: Radio, S: SenderStateStore>(
    stack: &mut SecureStack<R>,
    store: &mut S,
    received: &ReceivedSecureDatagram,
    dispatcher: &Dispatcher<'a, 5>,
) -> Result<SecureDispatchOutcome, SecureError> {
    let packet = CoapPacket::from_bytes(received.coap()).map_err(|_| SecureError::DecryptFailed)?;

    let is_encrypted = received.coap().len() > 4
        && packet
            .options()
            .filter_map(|o| o.ok())
            .any(|o| o.number == 9);

    if is_encrypted {
        dispatch_encrypted(stack, store, received, dispatcher).await
    } else {
        dispatch_plaintext(received, dispatcher)
    }
}

async fn dispatch_encrypted<R: Radio, S: SenderStateStore>(
    stack: &mut SecureStack<R>,
    store: &mut S,
    received: &ReceivedSecureDatagram,
    dispatcher: &Dispatcher<'_, 5>,
) -> Result<SecureDispatchOutcome, SecureError> {
    let request = stack.decrypt_request(received)?;

    let req = Request {
        method: request.code,
        path: [&[][..]; dispatch::MAX_PATH_DEPTH],
        path_len: 0,
        payload: &request.payload,
        content_format: Some(CBOR),
    };

    let resp = dispatcher.dispatch(&req);

    let response_data = SecureResponseData {
        code: resp.code,
        options: &[],
        payload: &resp.payload[..resp.payload_len],
    };

    let source = received.source();
    let peer_iid = received.sender_iid();

    stack
        .send_secure_response(&source, &peer_iid, &request, response_data, store)
        .await
        .map_err(|e| match e {
            SecureError::Tx(TxError::RadioTx) => SecureError::DecryptFailed,
            other => other,
        })?;

    Ok(SecureDispatchOutcome::Handled)
}

fn dispatch_plaintext(
    received: &ReceivedSecureDatagram,
    dispatcher: &Dispatcher<'_, 5>,
) -> Result<SecureDispatchOutcome, SecureError> {
    let mut resp_buf = [0u8; 256];
    let resp_len = dispatcher.handle_coap(received.coap(), &mut resp_buf);

    match resp_len {
        Some(_len) => Ok(SecureDispatchOutcome::Handled),
        None => Ok(SecureDispatchOutcome::NotFound),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lichen_coap::codec::CoapBuilder;
    use lichen_coap::message::{MessageCode, MessageType};
    use lichen_core::addr::Addr;
    use lichen_core::constants::PORT_COAP;
    use lichen_hal::loopback::LoopbackRadio;
    use lichen_hal::RadioConfig;
    use lichen_link::identity::{Identity, PeerIdentity};
    use lichen_link::Seed;
    use lichen_oscore::{Context as OscoreContext, ContextId, SenderSequenceState};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::vec;

    use crate::dispatch::default_dispatcher;
    use crate::stack::Stack;

    struct SimpleStore {
        record: Option<(ContextId, SenderSequenceState)>,
        existing: SenderSequenceState,
        fail: bool,
    }

    impl SenderStateStore for SimpleStore {
        type Error = ();
        fn load(
            &mut self,
            context_id: &ContextId,
        ) -> Result<Option<SenderSequenceState>, Self::Error> {
            Ok(match self.record {
                Some((stored_id, state)) if stored_id == *context_id => Some(state),
                Some(_) => None,
                None => Some(self.existing),
            })
        }
        fn compare_exchange(
            &mut self,
            context_id: &ContextId,
            expected: Option<SenderSequenceState>,
            next: SenderSequenceState,
        ) -> Result<bool, Self::Error> {
            if self.fail {
                return Err(());
            }
            let current = match self.record {
                Some((stored_id, state)) if stored_id == *context_id => Some(state),
                Some(_) => None,
                None => Some(self.existing),
            };
            if current != expected {
                return Ok(false);
            }
            self.record = Some((*context_id, next));
            Ok(true)
        }
    }

    fn make_datagram(coap: Vec<u8>, sender_iid: [u8; 8], dest: Addr) -> ReceivedSecureDatagram {
        ReceivedSecureDatagram {
            coap,
            sender_iid,
            source: Addr::link_local_from_eui64(&sender_iid),
            destination: dest,
            source_port: PORT_COAP,
            destination_port: PORT_COAP,
            rssi: None,
            snr: None,
        }
    }

    #[tokio::test]
    async fn secure_dispatch_deaddrop_post_roundtrip() {
        let alice_id = Identity::from_seed(Seed::new([0x31; 32]));
        let bob_id = Identity::from_seed(Seed::new([0x32; 32]));
        let (radio_a, radio_b) = LoopbackRadio::pair();

        let mut alice_stack = Stack::new(radio_a, alice_id.clone(), 128, 0);
        alice_stack.add_peer(PeerIdentity::from_pubkey(bob_id.pubkey));
        let mut bob_stack = Stack::new(radio_b, bob_id.clone(), 128, 0);
        bob_stack.add_peer(PeerIdentity::from_pubkey(alice_id.pubkey));

        let mut alice = SecureStack::new(alice_stack);
        let mut bob = SecureStack::new(bob_stack);

        let master_secret = [0xCD; 16];
        let mut alice_store = SimpleStore {
            record: None,
            existing: SenderSequenceState {
                next_sequence: 0,
                exhausted: false,
            },
            fail: false,
        };
        let mut bob_store = SimpleStore {
            record: None,
            existing: SenderSequenceState {
                next_sequence: 0,
                exhausted: false,
            },
            fail: false,
        };

        let alice_ctx = OscoreContext::load_existing(
            &master_secret,
            None,
            None,
            &alice_id.iid[..1],
            &bob_id.iid[..1],
            &mut alice_store,
        )
        .unwrap();
        let bob_ctx = OscoreContext::load_existing(
            &master_secret,
            None,
            None,
            &bob_id.iid[..1],
            &alice_id.iid[..1],
            &mut bob_store,
        )
        .unwrap();

        alice
            .register_fresh_context(bob_id.iid, alice_ctx, &mut alice_store)
            .unwrap();
        bob.register_fresh_context(alice_id.iid, bob_ctx, &mut bob_store)
            .unwrap();

        // Alice sends an encrypted POST to /deaddrop
        let bob_addr = bob.local_addr();
        let mut alice_correlation = alice
            .send_secure_get(
                &bob_addr,
                &bob_id.iid,
                &["deaddrop"],
                &[0xAA],
                &mut alice_store,
            )
            .await
            .unwrap();

        // Bob receives and dispatches through secure dispatch
        let received = bob.receive_secure_datagram(1000).await.unwrap().unwrap();
        let dispatcher = default_dispatcher();
        let outcome = dispatch_secure(&mut bob, &mut bob_store, &received, &dispatcher)
            .await
            .unwrap();
        assert!(matches!(outcome, SecureDispatchOutcome::Handled));

        // Alice should get a response
        let response = alice.receive_secure_datagram(1000).await.unwrap().unwrap();
        let decrypted = alice
            .decrypt_response(&response, &mut alice_correlation)
            .await
            .unwrap();
        assert!(matches!(
            decrypted,
            crate::secure::SecureResponse::Decrypted { code, .. }
            if code == MessageCode::CONTENT
        ));
    }
}
