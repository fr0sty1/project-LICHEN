// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Short-address assignment conformance tests checked against the canonical
//! vectors in `test/vectors/short_addr_assignment.json`.
//!
//! Required invocation:
//!
//! ```sh
//! cargo test -p lichen-rpl --test address_assignment_vectors
//! ```
//!
//! The substring filter `cargo test -p lichen-rpl address_assignment`
//! matches only the lib unit tests inside `src/address_assignment.rs`; no
//! test in this suite contains that substring, so omitting
//! `--test address_assignment_vectors` silently skips every check here.

use lichen_rpl::address_assignment::{
    decode_assignment_state, encode_assignment_state, AddressAssignmentAck,
    AddressAssignmentRequest, AddressAssignmentStore, AssignmentError, AssignmentOperation,
    AssignmentStatus, MemoryAddressAssignmentStore, ShortAddressAssignmentClient,
    ShortAddressCoordinator, SHORT_ADDRESS_OPTION_TYPE,
};
use serde_json::Value;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

const VECTORS: &str = include_str!("../../../test/vectors/short_addr_assignment.json");
const EUI: [u8; 8] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
const OTHER_EUI: [u8; 8] = [0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
const THIRD_EUI: [u8; 8] = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];

fn document() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn from_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex length must be even");
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

fn to_hex(data: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for &byte in data {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn wire(name: &str) -> Vec<u8> {
    from_hex(document()["wire"][name].as_str().unwrap())
}

#[test]
fn canonical_request_ack_and_release_wires_match_python() {
    let doc = document();
    assert_eq!(doc["format_version"], 2);
    assert_eq!(doc["option_type"], u64::from(SHORT_ADDRESS_OPTION_TYPE));

    let allocate_request = wire("allocate_request_hex");
    let request = AddressAssignmentRequest::from_dao_bytes(&allocate_request).unwrap();
    assert_eq!(
        request,
        AddressAssignmentRequest::allocate(EUI, Some(0x1234)).unwrap()
    );
    let mut actual = [0u8; 64];
    let n = request.write_dao(0, 7, None, &mut actual).unwrap();
    assert_eq!(&actual[..n], allocate_request);

    let allocate_ack = wire("allocate_ack_hex");
    let ack = AddressAssignmentAck::from_dao_ack_bytes(&allocate_ack).unwrap();
    assert_eq!(
        ack,
        AddressAssignmentAck::new(
            EUI,
            AssignmentOperation::Allocate,
            AssignmentStatus::Success,
            Some(0x1234),
            7,
        )
        .unwrap()
    );
    let n = ack.write_dao_ack(0, None, &mut actual).unwrap();
    assert_eq!(&actual[..n], allocate_ack);

    let release_request = wire("release_request_hex");
    let request = AddressAssignmentRequest::from_dao_bytes(&release_request).unwrap();
    assert_eq!(request, AddressAssignmentRequest::release(EUI).unwrap());
    let release_ack = wire("release_ack_hex");
    let ack = AddressAssignmentAck::from_dao_ack_bytes(&release_ack).unwrap();
    assert_eq!(ack.operation, AssignmentOperation::Release);
    assert_eq!(ack.assigned_short, None);
    let n = ack.write_dao_ack(0, None, &mut actual).unwrap();
    assert_eq!(&actual[..n], release_ack);
}

#[test]
fn handle_dao_rejects_option_eui_not_matching_authenticated_origin() {
    let mut coordinator = ShortAddressCoordinator::new().unwrap();
    let allocate = wire("allocate_request_hex");
    assert!(matches!(
        coordinator.handle_dao(&allocate, OTHER_EUI),
        Err(AssignmentError::Protocol(
            "assignment option EUI-64 does not match authenticated origin"
        ))
    ));
    assert!(coordinator.is_empty());
    let ack = coordinator.handle_dao(&allocate, EUI).unwrap();
    assert_eq!(ack, wire("allocate_ack_hex"));
}

#[test]
fn coordinator_handles_wire_idempotency_collision_capacity_release_and_reuse() {
    let mut coordinator = ShortAddressCoordinator::with_capacity(2).unwrap();
    let request = AddressAssignmentRequest::allocate(EUI, Some(0x1234)).unwrap();
    let dao = request.to_dao_vec(0, 7, None).unwrap();
    let first = coordinator.handle_dao(&dao, EUI).unwrap();
    let second = coordinator.handle_dao(&dao, EUI).unwrap();
    assert_eq!(first, second);
    assert_eq!(first, wire("allocate_ack_hex"));
    assert_eq!(coordinator.lookup_by_eui(&EUI).unwrap(), Some(0x1234));

    let collision = coordinator
        .process(
            AddressAssignmentRequest::allocate(OTHER_EUI, Some(0x1234)).unwrap(),
            8,
            OTHER_EUI,
        )
        .unwrap();
    assert_eq!(collision.assigned_short, Some(0x9fcf));
    assert_ne!(collision.assigned_short, Some(0x1234));

    let exhausted = coordinator
        .process(
            AddressAssignmentRequest::allocate(THIRD_EUI, Some(0x2222)).unwrap(),
            9,
            THIRD_EUI,
        )
        .unwrap();
    assert_eq!(exhausted.status, AssignmentStatus::Exhausted);
    assert_eq!(coordinator.len(), 2);

    let released = coordinator
        .process(AddressAssignmentRequest::release(EUI).unwrap(), 10, EUI)
        .unwrap();
    assert_eq!(released.status, AssignmentStatus::Success);
    assert_eq!(coordinator.lookup_by_eui(&EUI).unwrap(), None);
    let reused = coordinator
        .process(
            AddressAssignmentRequest::allocate(THIRD_EUI, Some(0x1234)).unwrap(),
            11,
            THIRD_EUI,
        )
        .unwrap();
    assert_eq!(reused.assigned_short, Some(0x1234));
}

#[test]
fn stale_release_does_not_drop_a_newer_allocation() {
    let mut coordinator = ShortAddressCoordinator::new().unwrap();
    let allocate = AddressAssignmentRequest::allocate(EUI, Some(0x1234)).unwrap();
    let release = AddressAssignmentRequest::release(EUI).unwrap();
    coordinator.process(allocate, 1, EUI).unwrap();
    coordinator.process(release, 2, EUI).unwrap();
    coordinator.process(allocate, 3, EUI).unwrap();
    let stale = coordinator.process(release, 2, EUI).unwrap();
    assert_eq!(stale.status, AssignmentStatus::Invalid);
    assert_eq!(coordinator.lookup_by_eui(&EUI).unwrap(), Some(0x1234));
    let duplicate = coordinator.process(release, 4, EUI).unwrap();
    assert_eq!(duplicate.status, AssignmentStatus::Success);
    assert_eq!(coordinator.lookup_by_eui(&EUI).unwrap(), None);
    assert_eq!(
        coordinator.process(release, 4, EUI).unwrap().status,
        AssignmentStatus::Success
    );
}

#[test]
fn vector_collision_fallback_is_the_requester_derived_address() {
    let allocation = &document()["allocation"];
    let preferred = allocation["preferred"].as_u64().unwrap() as u16;
    let fallback = allocation["collision_fallback"].as_u64().unwrap() as u16;
    let owner: [u8; 8] = from_hex(allocation["collision_owner_eui64"].as_str().unwrap())
        .try_into()
        .unwrap();
    let mut initial = BTreeMap::new();
    initial.insert(preferred, owner);
    let mut coordinator = ShortAddressCoordinator::with_initial_assignments(initial).unwrap();
    let result = coordinator
        .process(
            AddressAssignmentRequest::allocate(EUI, Some(preferred)).unwrap(),
            8,
            EUI,
        )
        .unwrap();
    assert_eq!(result.assigned_short, Some(fallback));
    assert_eq!(coordinator.lookup_by_short(preferred), Some(owner));
    assert_eq!(coordinator.lookup_by_short(fallback), Some(EUI));
}

#[derive(Clone, Default)]
struct SharedStore(Arc<Mutex<Option<Vec<u8>>>>);

impl AddressAssignmentStore for SharedStore {
    fn load(&self) -> Result<Option<Vec<u8>>, AssignmentError> {
        Ok(self.0.lock().unwrap().clone())
    }

    fn save(&mut self, state: &[u8]) -> Result<(), AssignmentError> {
        *self.0.lock().unwrap() = Some(state.to_vec());
        Ok(())
    }
}

#[test]
fn lease_renewal_expiry_reuse_and_restart_match_shared_vector() {
    let maintenance = &document()["maintenance"];
    let clock = Rc::new(Cell::new(maintenance["allocated_at"].as_u64().unwrap()));
    let store = SharedStore::default();
    let clock_for_first = Rc::clone(&clock);
    let mut coordinator = ShortAddressCoordinator::with_lease(
        store.clone(),
        maintenance["capacity"].as_u64().unwrap() as u16,
        Some(maintenance["lease_seconds"].as_u64().unwrap()),
        move || clock_for_first.get(),
    )
    .unwrap();
    let request = AddressAssignmentRequest::allocate(EUI, Some(0x1234)).unwrap();
    coordinator
        .process(
            request,
            maintenance["initial_sequence"].as_u64().unwrap() as u8,
            EUI,
        )
        .unwrap();
    assert_eq!(
        coordinator.expires_at(&EUI).unwrap(),
        Some(maintenance["initial_expiry"].as_u64().unwrap())
    );
    drop(coordinator);

    clock.set(maintenance["duplicate_at"].as_u64().unwrap());
    let clock_for_restart = Rc::clone(&clock);
    let mut restarted =
        ShortAddressCoordinator::with_lease(store.clone(), 1, Some(60), move || {
            clock_for_restart.get()
        })
        .unwrap();
    restarted.process(request, 21, EUI).unwrap();
    assert_eq!(restarted.expires_at(&EUI).unwrap(), Some(160));

    clock.set(maintenance["renewed_at"].as_u64().unwrap());
    restarted
        .process(
            request,
            maintenance["renewed_sequence"].as_u64().unwrap() as u8,
            EUI,
        )
        .unwrap();
    assert_eq!(
        restarted.expires_at(&EUI).unwrap(),
        Some(maintenance["renewed_expiry"].as_u64().unwrap())
    );
    drop(restarted);

    clock.set(maintenance["expires_at"].as_u64().unwrap());
    let clock_for_expiry = Rc::clone(&clock);
    let mut after_expiry =
        ShortAddressCoordinator::with_lease(store, 1, Some(60), move || clock_for_expiry.get())
            .unwrap();
    assert_eq!(after_expiry.lookup_by_eui(&EUI).unwrap(), None);
    let reused = after_expiry
        .process(
            AddressAssignmentRequest::allocate(OTHER_EUI, Some(0x1234)).unwrap(),
            23,
            OTHER_EUI,
        )
        .unwrap();
    assert_eq!(reused.assigned_short, Some(0x1234));
}

#[test]
fn client_rejects_mismatch_replay_conflict_status_and_reserved_values() {
    let mut client = ShortAddressAssignmentClient::new(EUI);
    let accepted = AddressAssignmentAck::new(
        EUI,
        AssignmentOperation::Allocate,
        AssignmentStatus::Success,
        Some(0x1234),
        12,
    )
    .unwrap()
    .to_dao_ack_vec(0, None)
    .unwrap();
    assert!(matches!(
        client.apply_dao_ack(&accepted, 12, false),
        Err(AssignmentError::Protocol(
            "DAO-ACK is not root-authenticated"
        ))
    ));
    assert_eq!(client.assigned_short(), None);
    assert!(!client.apply_dao_ack(&accepted, 11, true).unwrap());

    let spoof = AddressAssignmentAck::new(
        OTHER_EUI,
        AssignmentOperation::Allocate,
        AssignmentStatus::Success,
        Some(0x1234),
        12,
    )
    .unwrap()
    .to_dao_ack_vec(0, None)
    .unwrap();
    assert!(!client.apply_dao_ack(&spoof, 12, true).unwrap());
    assert!(client.apply_dao_ack(&accepted, 12, true).unwrap());
    assert!(client.apply_dao_ack(&accepted, 12, true).unwrap());
    assert_eq!(client.assigned_short(), Some(0x1234));

    let conflict = AddressAssignmentAck::new(
        EUI,
        AssignmentOperation::Allocate,
        AssignmentStatus::Success,
        Some(0x1235),
        12,
    )
    .unwrap()
    .to_dao_ack_vec(0, None)
    .unwrap();
    assert!(matches!(
        client.apply_dao_ack(&conflict, 12, true),
        Err(AssignmentError::Protocol(
            "conflicting DAO-ACK for one sequence"
        ))
    ));
    assert_eq!(client.assigned_short(), Some(0x1234));

    let exhausted = AddressAssignmentAck::new(
        EUI,
        AssignmentOperation::Allocate,
        AssignmentStatus::Exhausted,
        None,
        13,
    )
    .unwrap()
    .to_dao_ack_vec(0, None)
    .unwrap();
    assert!(!client.apply_dao_ack(&exhausted, 13, true).unwrap());
    assert_eq!(client.assigned_short(), Some(0x1234));

    let release = AddressAssignmentAck::new(
        EUI,
        AssignmentOperation::Release,
        AssignmentStatus::Success,
        None,
        14,
    )
    .unwrap()
    .to_dao_ack_vec(0, None)
    .unwrap();
    assert!(client.apply_dao_ack(&release, 14, true).unwrap());
    assert_eq!(client.assigned_short(), None);

    for reserved in [0x0000u16, 0xfffe, 0xffff] {
        let mut malicious = accepted.clone();
        let n = malicious.len();
        malicious[n - 2..].copy_from_slice(&reserved.to_be_bytes());
        assert!(AddressAssignmentAck::from_dao_ack_bytes(&malicious).is_err());
    }
}

#[test]
fn snapshot_matches_vector_and_corruption_fails_closed() {
    let mut assignments = BTreeMap::new();
    assignments.insert(0x1234, EUI);
    let snapshot = encode_assignment_state(&assignments).unwrap();
    assert_eq!(to_hex(&snapshot), document()["state_snapshot_hex"]);
    assert_eq!(decode_assignment_state(&snapshot).unwrap(), assignments);

    let mut corrupt = snapshot.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(decode_assignment_state(&corrupt).is_err());
    assert!(decode_assignment_state(&snapshot[..snapshot.len() - 1]).is_err());
}

#[test]
fn malformed_options_status_disagreement_and_output_boundaries_fail_closed() {
    let request = AddressAssignmentRequest::allocate(EUI, Some(0x1234)).unwrap();
    let mut dao = request.to_dao_vec(0, 7, None).unwrap();
    for index in [4usize, 5, 6] {
        let mut malformed = dao.clone();
        malformed[index] ^= 0xff;
        assert!(AddressAssignmentRequest::from_dao_bytes(&malformed).is_err());
    }
    let option = dao[4..].to_vec();
    dao.extend_from_slice(&option);
    assert!(AddressAssignmentRequest::from_dao_bytes(&dao).is_err());

    let mut ack = wire("allocate_ack_hex");
    ack[3] = AssignmentStatus::Exhausted as u8;
    assert!(AddressAssignmentAck::from_dao_ack_bytes(&ack).is_err());

    let mut tiny = [0u8; 18];
    assert!(request.write_dao(0, 7, None, &mut tiny).is_err());
    assert!(request.write_dao(0xc0, 7, None, &mut [0u8; 64]).is_err());
    assert!(AddressAssignmentRequest::allocate(EUI, Some(0)).is_err());
    assert!(AddressAssignmentRequest::allocate(EUI, Some(0xfffe)).is_err());
    assert!(AddressAssignmentRequest::allocate(EUI, Some(0xffff)).is_err());
}

struct FailingStore;

impl AddressAssignmentStore for FailingStore {
    fn load(&self) -> Result<Option<Vec<u8>>, AssignmentError> {
        Ok(None)
    }

    fn save(&mut self, _state: &[u8]) -> Result<(), AssignmentError> {
        Err(AssignmentError::Persistence("injected"))
    }
}

#[test]
fn persistence_failure_does_not_publish_allocation() {
    let mut coordinator = ShortAddressCoordinator::with_store(FailingStore).unwrap();
    let result = coordinator.process(
        AddressAssignmentRequest::allocate(EUI, Some(0x1234)).unwrap(),
        1,
        EUI,
    );
    assert!(matches!(result, Err(AssignmentError::Persistence(_))));
    assert!(coordinator.is_empty());
    assert_eq!(coordinator.lookup_by_eui(&EUI).unwrap(), None);
}

#[test]
fn memory_store_first_boot_and_capacity_boundaries_are_explicit() {
    assert!(ShortAddressCoordinator::with_capacity(0).is_err());
    assert!(ShortAddressCoordinator::with_capacity(0xfffe).is_err());
    let coordinator =
        ShortAddressCoordinator::with_store(MemoryAddressAssignmentStore::default()).unwrap();
    assert!(coordinator.is_empty());
    assert_eq!(coordinator.capacity(), 0xfffd);
}

#[test]
fn with_store_restart_prunes_expired_leases_with_wall_clock() {
    let maintenance = &document()["maintenance"];
    let clock_for_setup = Rc::new(Cell::new(maintenance["allocated_at"].as_u64().unwrap()));
    let store = SharedStore::default();
    {
        let clock = Rc::clone(&clock_for_setup);
        let mut coordinator =
            ShortAddressCoordinator::with_lease(store.clone(), 1, Some(60), move || clock.get())
                .unwrap();
        coordinator
            .process(
                AddressAssignmentRequest::allocate(EUI, Some(0x1234)).unwrap(),
                maintenance["initial_sequence"].as_u64().unwrap() as u8,
                EUI,
            )
            .unwrap();
        assert_eq!(
            coordinator.expires_at(&EUI).unwrap(),
            Some(maintenance["initial_expiry"].as_u64().unwrap())
        );
    }
    let mut restarted = ShortAddressCoordinator::with_store(store.clone()).unwrap();
    assert_eq!(restarted.lookup_by_eui(&EUI).unwrap(), None);
    assert!(restarted.is_empty());
    let reused = restarted
        .process(
            AddressAssignmentRequest::allocate(OTHER_EUI, Some(0x1234)).unwrap(),
            30,
            OTHER_EUI,
        )
        .unwrap();
    assert_eq!(reused.status, AssignmentStatus::Success);
    assert_eq!(
        reused.assigned_short,
        Some(maintenance["reused_short"].as_u64().unwrap() as u16)
    );
}

#[test]
fn with_store_restart_keeps_unexpired_leases_with_wall_clock() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expiry = now + 3600;
    let store = SharedStore::default();
    {
        let mut coordinator =
            ShortAddressCoordinator::with_lease(store.clone(), 1, Some(3600), move || now).unwrap();
        coordinator
            .process(
                AddressAssignmentRequest::allocate(EUI, Some(0x1234)).unwrap(),
                21,
                EUI,
            )
            .unwrap();
        assert_eq!(coordinator.expires_at(&EUI).unwrap(), Some(expiry));
    }
    let restarted = ShortAddressCoordinator::with_store(store).unwrap();
    assert_eq!(restarted.lookup_by_eui(&EUI).unwrap(), Some(0x1234));
    assert_eq!(restarted.expires_at(&EUI).unwrap(), Some(expiry));
}
