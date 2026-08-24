//! Access level types for principal-based access control.
//!
//! Defines the three access levels per 11-lci.md:
//! - Read-only: GET on non-sensitive resources; excludes `/diag/raw/*`
//! - Standard: GET, Observe, direct mesh CoAP; excludes `/diag/raw/*`
//! - Admin: All operations including PUT /config, DELETE /keys, `/diag/raw/*`
//!
//! Access level is typically determined by transport (e.g., USB = Admin, BLE = Standard).

/// Access level for a principal (e.g., a connected client).
///
/// Ordered from least to most privileged for comparison purposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(u8)]
pub enum AccessLevel {
    /// GET on non-sensitive resources only. Excludes `/diag/raw/*`.
    #[default]
    ReadOnly = 0,
    /// GET, Observe, direct mesh CoAP reachability, optional `/proxy`.
    /// Excludes `/diag/raw/*`.
    Standard = 1,
    /// Full access: PUT /config, DELETE /keys, `/diag/raw/*`, all operations.
    Admin = 2,
}

impl AccessLevel {
    /// Returns true if this access level permits reading non-sensitive resources.
    ///
    /// All levels can read non-sensitive resources.
    #[inline]
    pub fn can_read(&self) -> bool {
        true
    }

    /// Returns true if this access level permits access to `/diag/raw/*` endpoints.
    ///
    /// Only Admin level has access to raw diagnostics.
    #[inline]
    pub fn can_access_raw_diag(&self) -> bool {
        *self == AccessLevel::Admin
    }

    /// Returns true if this access level permits write operations (PUT, DELETE).
    ///
    /// Only Admin level can perform write operations.
    #[inline]
    pub fn can_write(&self) -> bool {
        *self == AccessLevel::Admin
    }

    /// Returns true if this access level permits Observe subscriptions.
    ///
    /// Standard and Admin levels can use Observe.
    #[inline]
    pub fn can_observe(&self) -> bool {
        *self >= AccessLevel::Standard
    }

    /// Returns true if this access level permits mesh CoAP reachability.
    ///
    /// Standard and Admin levels have mesh access.
    #[inline]
    pub fn can_access_mesh(&self) -> bool {
        *self >= AccessLevel::Standard
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_readonly() {
        assert_eq!(AccessLevel::default(), AccessLevel::ReadOnly);
    }

    #[test]
    fn test_ordering() {
        assert!(AccessLevel::ReadOnly < AccessLevel::Standard);
        assert!(AccessLevel::Standard < AccessLevel::Admin);
    }

    #[test]
    fn test_readonly_permissions() {
        let level = AccessLevel::ReadOnly;
        assert!(level.can_read());
        assert!(!level.can_observe());
        assert!(!level.can_access_mesh());
        assert!(!level.can_access_raw_diag());
        assert!(!level.can_write());
    }

    #[test]
    fn test_standard_permissions() {
        let level = AccessLevel::Standard;
        assert!(level.can_read());
        assert!(level.can_observe());
        assert!(level.can_access_mesh());
        assert!(!level.can_access_raw_diag());
        assert!(!level.can_write());
    }

    #[test]
    fn test_admin_permissions() {
        let level = AccessLevel::Admin;
        assert!(level.can_read());
        assert!(level.can_observe());
        assert!(level.can_access_mesh());
        assert!(level.can_access_raw_diag());
        assert!(level.can_write());
    }

    #[test]
    fn test_repr_values() {
        assert_eq!(AccessLevel::ReadOnly as u8, 0);
        assert_eq!(AccessLevel::Standard as u8, 1);
        assert_eq!(AccessLevel::Admin as u8, 2);
    }
}
