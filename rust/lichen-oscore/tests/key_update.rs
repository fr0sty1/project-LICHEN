// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

use std::collections::HashMap;
use std::fs;

use lichen_oscore::{
    Context, ContextId, KeyUpdateContext, KeyUpdateError, KeyUpdateMaterial, KeyUpdateState,
    KeyUpdateStore, SenderSequenceState, SenderStateStore,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct VectorFile {
    vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    initial_generation: u32,
    initial: Material,
    replacement_generation: u32,
    replacement: Material,
    replacement_sender_high_water: u64,
}

#[derive(Debug, Deserialize)]
struct Material {
    master_secret: String,
    master_salt: String,
    sender_id: String,
    recipient_id: String,
    id_context: Option<String>,
    context_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoreError {
    Simulated,
}

#[derive(Default)]
struct AtomicStore {
    active: Option<KeyUpdateState>,
    senders: HashMap<ContextId, SenderSequenceState>,
    conflict: bool,
    fail: bool,
}

impl SenderStateStore for AtomicStore {
    type Error = StoreError;

    fn load(&mut self, context_id: &ContextId) -> Result<Option<SenderSequenceState>, Self::Error> {
        Ok(self.senders.get(context_id).copied())
    }

    fn compare_exchange(
        &mut self,
        context_id: &ContextId,
        expected: Option<SenderSequenceState>,
        next: SenderSequenceState,
    ) -> Result<bool, Self::Error> {
        if self.fail {
            return Err(StoreError::Simulated);
        }
        if self.senders.get(context_id).copied() != expected {
            return Ok(false);
        }
        self.senders.insert(*context_id, next);
        Ok(true)
    }
}

impl KeyUpdateStore for AtomicStore {
    fn load_key_update(&mut self) -> Result<Option<KeyUpdateState>, Self::Error> {
        if self.fail {
            return Err(StoreError::Simulated);
        }
        Ok(self.active)
    }

    fn compare_exchange_key_update(
        &mut self,
        expected: KeyUpdateState,
        replacement: KeyUpdateState,
        initial_sender_state: SenderSequenceState,
    ) -> Result<bool, Self::Error> {
        if self.fail {
            return Err(StoreError::Simulated);
        }
        if self.conflict || self.active != Some(expected) {
            return Ok(false);
        }
        if self.senders.contains_key(&replacement.context_id) {
            return Ok(false);
        }
        self.senders
            .insert(replacement.context_id, initial_sender_state);
        self.active = Some(replacement);
        Ok(true)
    }
}

fn decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
        .collect()
}

fn secret(material: &Material) -> [u8; 16] {
    decode(&material.master_secret).try_into().unwrap()
}

fn context(material: &Material, store: &mut AtomicStore) -> Context {
    let salt = decode(&material.master_salt);
    let sender = decode(&material.sender_id);
    let recipient = decode(&material.recipient_id);
    let id_context = material.id_context.as_deref().map(decode);
    Context::new_fresh(
        &secret(material),
        Some(&salt),
        id_context.as_deref(),
        &sender,
        &recipient,
    )
    .unwrap()
    .register_fresh(store)
    .unwrap()
}

fn load_vectors() -> VectorFile {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test/vectors/oscore_key_update.json"
    );
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn initialized(vector: &Vector) -> (KeyUpdateContext, AtomicStore) {
    let mut store = AtomicStore::default();
    let context = context(&vector.initial, &mut store);
    let state = KeyUpdateState {
        generation: vector.initial_generation,
        context_id: context.context_id(),
    };
    store.active = Some(state);
    (
        KeyUpdateContext::new(context, vector.initial_generation),
        store,
    )
}

#[test]
fn canonical_key_updates_are_atomic_and_cross_implementation_stable() {
    for vector in load_vectors().vectors {
        let (mut slot, mut store) = initialized(&vector);
        assert_eq!(
            slot.context().context_id().as_bytes().as_slice(),
            decode(&vector.initial.context_id),
            "initial context ID for {}",
            vector.name
        );

        let salt = decode(&vector.replacement.master_salt);
        let sender = decode(&vector.replacement.sender_id);
        let recipient = decode(&vector.replacement.recipient_id);
        let id_context = vector.replacement.id_context.as_deref().map(decode);
        let replacement_secret = secret(&vector.replacement);
        slot.update(
            KeyUpdateMaterial {
                master_secret: &replacement_secret,
                master_salt: Some(&salt),
                id_context: id_context.as_deref(),
                sender_id: &sender,
                recipient_id: &recipient,
            },
            vector.replacement_generation,
            &mut store,
        )
        .unwrap();

        assert_eq!(slot.generation(), vector.replacement_generation);
        assert_eq!(
            slot.context().context_id().as_bytes().as_slice(),
            decode(&vector.replacement.context_id),
            "replacement context ID for {}",
            vector.name
        );
        assert_eq!(
            store.active,
            Some(KeyUpdateState {
                generation: vector.replacement_generation,
                context_id: slot.context().context_id(),
            })
        );
        assert_eq!(
            store.senders[&slot.context().context_id()].next_sequence,
            vector.replacement_sender_high_water
        );

        slot.context_mut()
            .reserve_sender(&mut store)
            .unwrap()
            .protect_request(1, &[], b"after update")
            .unwrap();
        assert_eq!(slot.context().sender_sequence_state().next_sequence, 1);
    }
}

#[test]
fn rollback_skip_reuse_and_overflow_leave_old_context_active() {
    let vectors = load_vectors();
    let vector = &vectors.vectors[0];
    for requested in [6, 7, 9, u32::MAX] {
        let (mut slot, mut store) = initialized(vector);
        let original = slot.context().context_id();
        let replacement_secret = secret(&vector.replacement);
        let replacement_salt = decode(&vector.replacement.master_salt);
        let replacement_sender = decode(&vector.replacement.sender_id);
        let replacement_recipient = decode(&vector.replacement.recipient_id);
        let result = slot.update(
            KeyUpdateMaterial {
                master_secret: &replacement_secret,
                master_salt: Some(&replacement_salt),
                id_context: None,
                sender_id: &replacement_sender,
                recipient_id: &replacement_recipient,
            },
            requested,
            &mut store,
        );
        assert_eq!(result, Err(KeyUpdateError::InvalidGeneration));
        assert_eq!(slot.context().context_id(), original);
        assert_eq!(store.active.unwrap().context_id, original);
    }

    let (mut slot, mut store) = initialized(vector);
    let original = slot.context().context_id();
    let initial_secret = secret(&vector.initial);
    let initial_salt = decode(&vector.initial.master_salt);
    let initial_sender = decode(&vector.initial.sender_id);
    let initial_recipient = decode(&vector.initial.recipient_id);
    let result = slot.update(
        KeyUpdateMaterial {
            master_secret: &initial_secret,
            master_salt: Some(&initial_salt),
            id_context: None,
            sender_id: &initial_sender,
            recipient_id: &initial_recipient,
        },
        8,
        &mut store,
    );
    assert_eq!(result, Err(KeyUpdateError::ReusedContext));
    assert_eq!(slot.context().context_id(), original);

    let mut store = AtomicStore::default();
    let context = context(&vector.initial, &mut store);
    let state = KeyUpdateState {
        generation: u32::MAX,
        context_id: context.context_id(),
    };
    store.active = Some(state);
    let mut slot = KeyUpdateContext::new(context, u32::MAX);
    let replacement_secret = secret(&vector.replacement);
    let replacement_salt = decode(&vector.replacement.master_salt);
    let replacement_sender = decode(&vector.replacement.sender_id);
    let replacement_recipient = decode(&vector.replacement.recipient_id);
    let result = slot.update(
        KeyUpdateMaterial {
            master_secret: &replacement_secret,
            master_salt: Some(&replacement_salt),
            id_context: None,
            sender_id: &replacement_sender,
            recipient_id: &replacement_recipient,
        },
        0,
        &mut store,
    );
    assert_eq!(result, Err(KeyUpdateError::InvalidGeneration));
    assert_eq!(slot.context().context_id(), state.context_id);
}

#[test]
fn store_conflict_or_error_preserves_old_context_and_sender_state() {
    let vectors = load_vectors();
    let vector = &vectors.vectors[0];
    for fail in [false, true] {
        let (mut slot, mut store) = initialized(vector);
        let original = slot.context().context_id();
        store.conflict = !fail;
        store.fail = fail;
        let replacement_secret = secret(&vector.replacement);
        let replacement_salt = decode(&vector.replacement.master_salt);
        let replacement_sender = decode(&vector.replacement.sender_id);
        let replacement_recipient = decode(&vector.replacement.recipient_id);
        let result = slot.update(
            KeyUpdateMaterial {
                master_secret: &replacement_secret,
                master_salt: Some(&replacement_salt),
                id_context: None,
                sender_id: &replacement_sender,
                recipient_id: &replacement_recipient,
            },
            8,
            &mut store,
        );
        if fail {
            assert_eq!(result, Err(KeyUpdateError::Storage(StoreError::Simulated)));
        } else {
            assert_eq!(result, Err(KeyUpdateError::Conflict));
        }
        store.conflict = false;
        store.fail = false;
        assert_eq!(slot.context().context_id(), original);
        assert_eq!(store.active.unwrap().context_id, original);
        slot.context_mut()
            .reserve_sender(&mut store)
            .unwrap()
            .protect_request(1, &[], b"old context still active")
            .unwrap();
        assert_eq!(slot.context().sender_sequence_state().next_sequence, 1);
    }
}

#[test]
fn restore_rejects_rolled_back_or_wrong_context_state() {
    let vectors = load_vectors();
    let vector = &vectors.vectors[0];
    let (slot, mut store) = initialized(vector);
    let generation = slot.generation();
    let context_id = slot.context().context_id();
    let context = slot.into_context();
    store.active = Some(KeyUpdateState {
        generation: generation + 1,
        context_id,
    });
    let result = KeyUpdateContext::restore_checked(context, generation, &mut store);
    assert!(matches!(result, Err(KeyUpdateError::Stale)));
}
