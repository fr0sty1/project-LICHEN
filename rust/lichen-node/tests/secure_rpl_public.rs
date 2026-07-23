#![cfg(feature = "std")]

// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

use lichen_hal::loopback::LoopbackRadio;
use lichen_hal::storage::mem::MemStorage;
use lichen_ipv6::Addr;
use lichen_link::identity::{Identity, PeerIdentity};
use lichen_link::Seed;
use lichen_node::{AnnounceProcessor, GradientTable, RplReceiveOutcome, RplStack, SecureStack};
use lichen_oscore::{Context, ContextId, SenderSequenceState, SenderStateStore};

#[derive(Default)]
struct OscoreStore(Option<(ContextId, SenderSequenceState)>);

impl SenderStateStore for OscoreStore {
    type Error = ();

    fn load(&mut self, context_id: &ContextId) -> Result<Option<SenderSequenceState>, Self::Error> {
        Ok(Some(
            self.0
                .filter(|(stored_context, _)| stored_context == context_id)
                .map_or(
                    SenderSequenceState {
                        next_sequence: 0,
                        exhausted: false,
                    },
                    |(_, state)| state,
                ),
        ))
    }

    fn compare_exchange(
        &mut self,
        context_id: &ContextId,
        expected: Option<SenderSequenceState>,
        next: SenderSequenceState,
    ) -> Result<bool, Self::Error> {
        if self.load(context_id)? != expected {
            return Ok(false);
        }
        self.0 = Some((*context_id, next));
        Ok(true)
    }
}

#[test]
fn downstream_can_construct_secure_rpl_owner() {
    let (radio, _peer_radio) = LoopbackRadio::pair();
    let identity = Identity::from_seed(Seed::new([0x61; 32]));
    let secure = SecureStack::from_radio(radio, identity, 128).unwrap();
    let local_addr = secure.local_addr().0;
    let announces = AnnounceProcessor::new(GradientTable::new(64), [0xfd, 0, 0, 0, 0, 0, 0, 1]);

    let _owner =
        RplStack::provision_leaf(secure, local_addr, local_addr, announces, MemStorage::new())
            .unwrap();
}

#[tokio::test]
async fn downstream_secure_rpl_request() {
    let (alice_radio, bob_radio) = LoopbackRadio::pair();
    let alice_identity = Identity::from_seed(Seed::new([0x71; 32]));
    let bob_identity = Identity::from_seed(Seed::new([0x72; 32]));
    let alice_iid = alice_identity.iid;
    let bob_iid = bob_identity.iid;

    let mut alice_secure = SecureStack::from_radio(alice_radio, alice_identity, 128).unwrap();
    let mut bob_secure = SecureStack::from_radio(bob_radio, bob_identity, 128).unwrap();
    alice_secure.add_peer(PeerIdentity::from_pubkey(
        Identity::from_seed(Seed::new([0x72; 32])).pubkey,
    ));
    bob_secure.add_peer(PeerIdentity::from_pubkey(
        Identity::from_seed(Seed::new([0x71; 32])).pubkey,
    ));
    let alice_addr = alice_secure.local_addr().0;
    let bob_addr = bob_secure.local_addr().0;

    let mut alice = RplStack::provision_leaf(
        alice_secure,
        alice_addr,
        bob_addr,
        AnnounceProcessor::new(GradientTable::new(64), alice_addr[..8].try_into().unwrap()),
        MemStorage::new(),
    )
    .unwrap();
    let mut bob = RplStack::provision_leaf(
        bob_secure,
        bob_addr,
        bob_addr,
        AnnounceProcessor::new(GradientTable::new(64), bob_addr[..8].try_into().unwrap()),
        MemStorage::new(),
    )
    .unwrap();

    let secret = [0x42; 16];
    let mut alice_store = OscoreStore::default();
    let mut bob_store = OscoreStore::default();
    let alice_context =
        Context::load_existing(&secret, None, None, &[0x00], &[0x01], &mut alice_store).unwrap();
    let bob_context =
        Context::load_existing(&secret, None, None, &[0x01], &[0x00], &mut bob_store).unwrap();
    alice
        .restore_context(bob_iid, alice_context, &mut alice_store)
        .unwrap();
    bob.restore_context(alice_iid, bob_context, &mut bob_store)
        .unwrap();

    alice
        .send_secure_get(
            &Addr(bob_addr),
            &bob_iid,
            &["status"],
            &[0xa1],
            &mut alice_store,
            0,
        )
        .await
        .unwrap();

    let received = bob.receive(0, 0).await.unwrap().unwrap();
    let RplReceiveOutcome::DeliveredIpv6(received) = received else {
        panic!("secure CoAP escaped the secure receive path");
    };
    let datagram = bob.secure_datagram(&received).unwrap().unwrap();
    let request = bob.decrypt_request(&datagram).unwrap();
    assert_eq!(request.sender_iid, alice_iid);
    assert_eq!(request.code.0, 1);
}
