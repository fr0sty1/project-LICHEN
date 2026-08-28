// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Public-wrapper coverage for RFC 8613 responses used by CoAP Observe.

use core::convert::Infallible;

use lichen_oscore::{Context, ContextId, OscoreError, SenderSequenceState, SenderStateStore};

#[derive(Default)]
struct MemoryStore(Option<(ContextId, SenderSequenceState)>);

impl SenderStateStore for MemoryStore {
    type Error = Infallible;

    fn load(&mut self, context_id: &ContextId) -> Result<Option<SenderSequenceState>, Self::Error> {
        Ok(self
            .0
            .filter(|(stored_id, _)| stored_id == context_id)
            .map(|(_, state)| state))
    }

    fn compare_exchange(
        &mut self,
        context_id: &ContextId,
        expected: Option<SenderSequenceState>,
        next: SenderSequenceState,
    ) -> Result<bool, Self::Error> {
        let current = self
            .0
            .filter(|(stored_id, _)| stored_id == context_id)
            .map(|(_, state)| state);
        if current != expected {
            return Ok(false);
        }
        self.0 = Some((*context_id, next));
        Ok(true)
    }
}

fn active_context(
    master_secret: &[u8; 16],
    sender_id: &[u8],
    recipient_id: &[u8],
) -> (Context, MemoryStore) {
    let context = Context::new_fresh(master_secret, None, None, sender_id, recipient_id).unwrap();
    let mut store = MemoryStore::default();
    let context = context.register_fresh(&mut store).unwrap();
    (context, store)
}

#[test]
fn reexport_accepts_multiple_observe_responses_but_preserves_one_shot_api() {
    let master_secret = [0x11; 16];
    let (mut client, mut client_store) = active_context(&master_secret, &[0], &[1]);
    let (mut server, mut server_store) = active_context(&master_secret, &[1], &[0]);
    let (_, request_option) = client
        .reserve_sender(&mut client_store)
        .unwrap()
        .protect_request(0x01, &[], b"observe")
        .unwrap();
    let request_piv = &request_option[1..2];
    let first = server
        .reserve_sender(&mut server_store)
        .unwrap()
        .protect_response_with_piv(0x45, &[], b"first", &[0], request_piv)
        .unwrap();
    let second = server
        .reserve_sender(&mut server_store)
        .unwrap()
        .protect_response_with_piv(0x45, &[], b"second", &[0], request_piv)
        .unwrap();

    assert_eq!(
        client
            .unprotect_observe_response(&first.1, &first.0, request_piv)
            .unwrap()
            .2,
        b"first"
    );
    assert_eq!(
        client
            .unprotect_observe_response(&second.1, &second.0, request_piv)
            .unwrap()
            .2,
        b"second"
    );

    let (mut one_shot, _) = active_context(&master_secret, &[0], &[1]);
    one_shot
        .unprotect_response(&first.1, &first.0, request_piv)
        .unwrap();
    assert_eq!(
        one_shot
            .unprotect_response(&second.1, &second.0, request_piv)
            .unwrap_err(),
        OscoreError::Replay
    );
}
