// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Error types for the production RPL stack.

use lichen_rpl::routing::{DaoPersistentOpenError, DaoProvisionError, DaoTxError};

use crate::runtime::RplRuntimeActionError;
use crate::stack::{RxError, TxError};

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RplStackProvisionError<E> {
    InvalidOrigin,
    RootAddressMismatch,
    Dao(DaoProvisionError<E>),
    Admission(DaoProvisionError<E>),
    ExistingNonEmpty,
}

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RplStackOpenError<E> {
    InvalidOrigin,
    RootAddressMismatch,
    Dao(DaoPersistentOpenError<E>),
    Admission(DaoPersistentOpenError<E>),
    AdmissionInconsistent,
}

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DaoSendError<E> {
    NotLeaf,
    Dao(DaoTxError<E>),
    PacketTooLarge,
    Transmit(TxError),
}

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RplReceiveError {
    Receive(RxError),
    Transmit(TxError),
}

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RplControlError {
    MalformedAnnounce,
    Transmit(TxError),
}

#[derive(Debug)]
#[non_exhaustive]
pub enum RplRuntimeReceiveError {
    Action(RplRuntimeActionError),
    Receive(RplReceiveError),
}

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RplRuntimeTrickleError {
    Action(RplRuntimeActionError),
    Transmit(TxError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DaoAdmissionError<E> {
    NotRoot,
    IdentityNotPinned,
    Capacity,
    Persistence(E),
    Stale,
    Exhausted,
    Corrupt,
}

impl<E: core::fmt::Debug> core::fmt::Display for RplStackProvisionError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidOrigin => write!(f, "RPL origin IID does not match the local identity"),
            Self::RootAddressMismatch => write!(f, "root address must equal the DODAG ID"),
            Self::Dao(error) => write!(f, "DAO state provisioning failed: {error:?}"),
            Self::Admission(error) => write!(f, "DAO admission provisioning failed: {error:?}"),
            Self::ExistingNonEmpty => {
                write!(
                    f,
                    "existing DAO root state is nonempty and cannot be reprovisioned"
                )
            }
        }
    }
}

impl<E: core::fmt::Debug + 'static> core::error::Error for RplStackProvisionError<E> {}

impl<E: core::fmt::Debug> core::fmt::Display for RplStackOpenError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidOrigin => write!(f, "RPL origin IID does not match the local identity"),
            Self::RootAddressMismatch => write!(f, "root address must equal the DODAG ID"),
            Self::Dao(error) => write!(f, "DAO state open failed: {error:?}"),
            Self::Admission(error) => write!(f, "DAO admission open failed: {error:?}"),
            Self::AdmissionInconsistent => {
                write!(f, "DAO high-water contains an origin that is not admitted")
            }
        }
    }
}

impl<E: core::fmt::Debug + 'static> core::error::Error for RplStackOpenError<E> {}

impl<E: core::fmt::Debug> core::fmt::Display for DaoSendError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotLeaf => write!(f, "DAO transmission requires a leaf role"),
            Self::Dao(error) => write!(f, "DAO construction failed: {error:?}"),
            Self::PacketTooLarge => write!(f, "DAO packet is too large"),
            Self::Transmit(error) => write!(f, "DAO transmission failed: {error}"),
        }
    }
}

impl<E: core::fmt::Debug + 'static> core::error::Error for DaoSendError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Transmit(error) => Some(error),
            _ => None,
        }
    }
}

impl core::fmt::Display for RplReceiveError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Receive(error) => write!(f, "RPL receive failed: {error}"),
            Self::Transmit(error) => write!(f, "RPL forwarding failed: {error}"),
        }
    }
}

impl core::error::Error for RplReceiveError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Receive(error) => Some(error),
            Self::Transmit(error) => Some(error),
        }
    }
}

impl core::fmt::Display for RplControlError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MalformedAnnounce => write!(f, "invalid local announce"),
            Self::Transmit(error) => write!(f, "control transmission failed: {error}"),
        }
    }
}

impl core::error::Error for RplControlError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::MalformedAnnounce => None,
            Self::Transmit(error) => Some(error),
        }
    }
}

impl core::fmt::Display for RplRuntimeReceiveError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Action(error) => write!(f, "invalid RPL runtime receive action: {error:?}"),
            Self::Receive(error) => write!(f, "{error}"),
        }
    }
}

impl core::error::Error for RplRuntimeReceiveError {}

impl core::fmt::Display for RplRuntimeTrickleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Action(error) => write!(f, "invalid RPL runtime Trickle action: {error:?}"),
            Self::Transmit(error) => write!(f, "Trickle DIO transmission failed: {error}"),
        }
    }
}

impl core::error::Error for RplRuntimeTrickleError {}

impl<E: core::fmt::Debug> core::fmt::Display for DaoAdmissionError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotRoot => write!(f, "DAO origins can only be admitted at a root"),
            Self::IdentityNotPinned => write!(f, "DAO origin has no currently pinned Announce key"),
            Self::Capacity => write!(f, "DAO origin admission capacity exhausted"),
            Self::Persistence(error) => write!(f, "DAO admission persistence failed: {error:?}"),
            Self::Stale => write!(f, "DAO admission state handle is stale"),
            Self::Exhausted => write!(f, "DAO admission persistence generation exhausted"),
            Self::Corrupt => write!(f, "DAO admission persistence is corrupt"),
        }
    }
}

impl<E: core::fmt::Debug + 'static> core::error::Error for DaoAdmissionError<E> {}
