// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Stack provisioning and constructor methods.

use std::collections::{HashSet, VecDeque};

use lichen_hal::{NonVolatile, Radio};
use lichen_link::identity::iid_from_pubkey;
use lichen_rpl::routing::{
    DaoAdmissionState, DaoAdmissionUpdateError, DaoPersistentOpenError, DaoProvisionError,
    DaoTxState,
};


use crate::announce::AnnounceProcessor;
use crate::node::{Node, RplNode};
use crate::routing::{DaoRxState, Router};
use crate::secure::SecureStack;

use super::error::{DaoAdmissionError, RplStackOpenError, RplStackProvisionError};
use super::{RplRole, RplStack};

impl<R: Radio, S: NonVolatile> RplStack<R, S> {
    pub fn provision_leaf<T: Into<SecureStack<R>>>(
        stack: T,
        local_rpl_addr: [u8; 16],
        dodag_id: [u8; 16],
        announces: AnnounceProcessor,
        mut storage: S,
    ) -> Result<Self, RplStackProvisionError<S::Error>> {
        let stack = stack.into();
        validate_origin(&stack, local_rpl_addr)
            .map_err(|()| RplStackProvisionError::InvalidOrigin)?;
        let key = stack.local_public_key();
        let tx = DaoTxState::provision(
            &mut storage,
            key,
            local_rpl_addr,
            lichen_core::constants::RPL_INSTANCE_ID,
            dodag_id,
        )
        .map_err(RplStackProvisionError::Dao)?;
        let rpl = RplNode {
            node: Node::new(stack.node_id()),
            router: Router::new(local_rpl_addr, dodag_id),
        };
        Ok(Self {
            stack,
            rpl,
            announces,
            storage,
            role: RplRole::Leaf(tx),
            local_rpl_addr,
            bootstrap_peers: VecDeque::new(),
            dao_admissions: None,
            routing_now_ms: 0,
            generation: 1,
            direct_neighbors: HashSet::new(),
        })
    }

    pub fn open_leaf<T: Into<SecureStack<R>>>(
        stack: T,
        local_rpl_addr: [u8; 16],
        dodag_id: [u8; 16],
        announces: AnnounceProcessor,
        storage: S,
    ) -> Result<Self, RplStackOpenError<S::Error>> {
        let stack = stack.into();
        validate_origin(&stack, local_rpl_addr).map_err(|()| RplStackOpenError::InvalidOrigin)?;
        let key = stack.local_public_key();
        let tx = DaoTxState::open(
            &storage,
            key,
            local_rpl_addr,
            lichen_core::constants::RPL_INSTANCE_ID,
            dodag_id,
        )
        .map_err(RplStackOpenError::Dao)?;
        let rpl = RplNode {
            node: Node::new(stack.node_id()),
            router: Router::new(local_rpl_addr, dodag_id),
        };
        Ok(Self {
            stack,
            rpl,
            announces,
            storage,
            role: RplRole::Leaf(tx),
            local_rpl_addr,
            bootstrap_peers: VecDeque::new(),
            dao_admissions: None,
            routing_now_ms: 0,
            generation: 1,
            direct_neighbors: HashSet::new(),
        })
    }

    pub fn provision_root<T: Into<SecureStack<R>>>(
        stack: T,
        root_addr: [u8; 16],
        dodag_id: [u8; 16],
        announces: AnnounceProcessor,
        mut storage: S,
    ) -> Result<Self, RplStackProvisionError<S::Error>> {
        let stack = stack.into();
        validate_origin(&stack, root_addr).map_err(|()| RplStackProvisionError::InvalidOrigin)?;
        if root_addr != dodag_id {
            return Err(RplStackProvisionError::RootAddressMismatch);
        }
        let (router, rx, admissions) = provision_or_resume_root_state(
            &mut storage,
            root_addr,
            lichen_core::constants::RPL_INSTANCE_ID,
            dodag_id,
        )?;
        Ok(Self {
            rpl: RplNode {
                node: Node::new(stack.node_id()),
                router,
            },
            stack,
            announces,
            storage,
            role: RplRole::Root(rx),
            local_rpl_addr: root_addr,
            bootstrap_peers: VecDeque::new(),
            dao_admissions: Some(admissions),
            routing_now_ms: 0,
            generation: 1,
            direct_neighbors: HashSet::new(),
        })
    }

    pub fn open_root<T: Into<SecureStack<R>>>(
        stack: T,
        root_addr: [u8; 16],
        dodag_id: [u8; 16],
        announces: AnnounceProcessor,
        storage: S,
    ) -> Result<Self, RplStackOpenError<S::Error>> {
        let stack = stack.into();
        validate_origin(&stack, root_addr).map_err(|()| RplStackOpenError::InvalidOrigin)?;
        if root_addr != dodag_id {
            return Err(RplStackOpenError::RootAddressMismatch);
        }
        let (router, rx) =
            Router::open_root(&storage, root_addr).map_err(RplStackOpenError::Dao)?;
        let admissions = DaoAdmissionState::open(
            &storage,
            root_addr,
            lichen_core::constants::RPL_INSTANCE_ID,
            dodag_id,
        )
        .map_err(RplStackOpenError::Admission)?;
        if router
            .dao_manager
            .origin_high_water()
            .iter()
            .any(|hw| !admissions.contains(&hw.public_key))
        {
            return Err(RplStackOpenError::AdmissionInconsistent);
        }
        Ok(Self {
            rpl: RplNode {
                node: Node::new(stack.node_id()),
                router,
            },
            stack,
            announces,
            storage,
            role: RplRole::Root(rx),
            local_rpl_addr: root_addr,
            bootstrap_peers: VecDeque::new(),
            dao_admissions: Some(admissions),
            routing_now_ms: 0,
            generation: 1,
            direct_neighbors: HashSet::new(),
        })
    }

    /// Admit the currently pinned Announce identity to create root DAO state.
    ///
    /// Admissions are bounded by durable replay capacity and cannot be retired
    /// through this API. Origins already represented in persisted high-water
    /// state are restored as admitted by [`Self::open_root`].
    pub fn admit_dao_origin(&mut self, iid: [u8; 8]) -> Result<(), DaoAdmissionError<S::Error>> {
        if !matches!(self.role, RplRole::Root(_)) {
            return Err(DaoAdmissionError::NotRoot);
        }
        let key = self
            .announces
            .pinned_pubkey_for(&iid)
            .ok_or(DaoAdmissionError::IdentityNotPinned)?;
        let admissions = self
            .dao_admissions
            .as_mut()
            .ok_or(DaoAdmissionError::NotRoot)?;
        admissions
            .admit(&mut self.storage, *key.as_bytes())
            .map_err(|error| match error {
                DaoAdmissionUpdateError::Persistence(error) => {
                    DaoAdmissionError::Persistence(error)
                }
                DaoAdmissionUpdateError::Stale => DaoAdmissionError::Stale,
                DaoAdmissionUpdateError::Exhausted => DaoAdmissionError::Exhausted,
                DaoAdmissionUpdateError::Corrupt => DaoAdmissionError::Corrupt,
                DaoAdmissionUpdateError::Capacity => DaoAdmissionError::Capacity,
            })
    }
}

pub(crate) fn validate_origin<R: Radio>(
    stack: &SecureStack<R>,
    origin: [u8; 16],
) -> Result<(), ()> {
    let expected = iid_from_pubkey(&stack.local_public_key());
    (origin[8..] == expected).then_some(()).ok_or(())
}

pub(crate) fn provision_or_resume_root_state<S: NonVolatile>(
    storage: &mut S,
    root_addr: [u8; 16],
    rpl_instance_id: u8,
    dodag_id: [u8; 16],
) -> Result<(Router, DaoRxState, DaoAdmissionState), RplStackProvisionError<S::Error>> {
    let admissions = match DaoAdmissionState::open(storage, root_addr, rpl_instance_id, dodag_id) {
        Ok(state) => Some(state),
        Err(DaoPersistentOpenError::Missing) => None,
        Err(error) => {
            return Err(RplStackProvisionError::Admission(DaoProvisionError::Open(
                error,
            )))
        }
    };
    let replay = match Router::open_root(storage, root_addr) {
        Ok(state) => Some(state),
        Err(DaoPersistentOpenError::Missing) => None,
        Err(error) => return Err(RplStackProvisionError::Dao(DaoProvisionError::Open(error))),
    };

    if admissions.as_ref().is_some_and(|state| !state.is_empty())
        || replay
            .as_ref()
            .is_some_and(|(router, _)| !router.dao_manager.origin_high_water().is_empty())
    {
        return Err(RplStackProvisionError::ExistingNonEmpty);
    }

    let admissions = match admissions {
        Some(state) => state,
        None => DaoAdmissionState::provision(storage, root_addr, rpl_instance_id, dodag_id)
            .map_err(RplStackProvisionError::Admission)?,
    };
    let (router, rx) = match replay {
        Some(state) => state,
        None => Router::provision_root(storage, root_addr).map_err(RplStackProvisionError::Dao)?,
    };
    Ok((router, rx, admissions))
}
