//! Firmware build / board-provision epoch floor (spec 09 section 14.6).
//!
//! Samples below the effective floor MUST NOT establish wall-clock time.
//! Wire status strings match Python `ProvisionEpochStatus`.

/// Outcome of combining firmware-build and optional provision epochs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochFloorResult {
    floor: u32,
    provision_status: ProvisionEpochStatus,
}

/// Why a board-provision epoch was accepted or ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionEpochStatus {
    /// No provision metadata present.
    Missing,
    /// Authenticated provision epoch is the effective floor.
    Accepted,
    /// Raw / unauthenticated provision integer is ignored.
    Unauthenticated,
    /// Provision epoch is earlier than the firmware build epoch.
    BeforeBuild,
    /// Provision epoch exceeds the configured lead bound.
    BeyondLead,
}

/// Invalid firmware-build epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochFloorError {
    /// Production firmware requires a non-zero uint32 build epoch.
    ZeroBuildEpoch,
}

impl ProvisionEpochStatus {
    /// Canonical JSON / vector status string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Accepted => "accepted",
            Self::Unauthenticated => "unauthenticated",
            Self::BeforeBuild => "before-build",
            Self::BeyondLead => "beyond-lead",
        }
    }
}

impl EpochFloorResult {
    /// Effective Unix floor in seconds.
    pub const fn floor(self) -> u32 {
        self.floor
    }

    /// Provision-metadata evaluation status.
    pub const fn provision_status(self) -> ProvisionEpochStatus {
        self.provision_status
    }

    /// True if `unix` may establish wall-clock time.
    pub const fn accepts(self, unix: u32) -> bool {
        unix >= self.floor
    }
}

/// Combine a required firmware-build epoch with optional provision metadata.
///
/// `board_provision_epoch` is considered only when `authenticated` is true.
/// Unauthenticated integers are ignored (Python `effective_epoch_floor` raw-int
/// deprecation path).
pub fn evaluate_epoch_floor(
    firmware_build_epoch: u32,
    board_provision_epoch: Option<u32>,
    authenticated: bool,
    max_provision_lead_s: u32,
) -> Result<EpochFloorResult, EpochFloorError> {
    if firmware_build_epoch == 0 {
        return Err(EpochFloorError::ZeroBuildEpoch);
    }
    let build = firmware_build_epoch;
    match board_provision_epoch {
        None => Ok(EpochFloorResult {
            floor: build,
            provision_status: ProvisionEpochStatus::Missing,
        }),
        Some(_) if !authenticated => Ok(EpochFloorResult {
            floor: build,
            provision_status: ProvisionEpochStatus::Unauthenticated,
        }),
        Some(provision) if provision < build => Ok(EpochFloorResult {
            floor: build,
            provision_status: ProvisionEpochStatus::BeforeBuild,
        }),
        Some(provision) if provision.saturating_sub(build) > max_provision_lead_s => {
            Ok(EpochFloorResult {
                floor: build,
                provision_status: ProvisionEpochStatus::BeyondLead,
            })
        }
        Some(provision) => Ok(EpochFloorResult {
            floor: provision,
            provision_status: ProvisionEpochStatus::Accepted,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUILD: u32 = 1_700_000_000;

    #[test]
    fn firmware_only_rejects_below_build_epoch() {
        let result = evaluate_epoch_floor(BUILD, None, false, 0).expect("build");
        assert_eq!(result.floor(), BUILD);
        assert_eq!(result.provision_status(), ProvisionEpochStatus::Missing);
        assert!(!result.accepts(BUILD - 1));
        assert!(result.accepts(BUILD));
        assert!(result.accepts(BUILD + 1));
    }

    #[test]
    fn zero_build_epoch_is_rejected() {
        assert_eq!(
            evaluate_epoch_floor(0, None, false, 0),
            Err(EpochFloorError::ZeroBuildEpoch)
        );
    }

    #[test]
    fn accepted_provision_is_the_stricter_floor() {
        let result = evaluate_epoch_floor(BUILD, Some(BUILD + 10), true, 100).expect("ok");
        assert_eq!(result.floor(), BUILD + 10);
        assert_eq!(result.provision_status(), ProvisionEpochStatus::Accepted);
        assert!(!result.accepts(BUILD + 9));
        assert!(result.accepts(BUILD + 10));
    }
}
