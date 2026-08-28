// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Group invitation and removal types (spec/12-apps.md 18.8.2).

/// Invitation role. Spec POST /groups/invite allows "member" or "admin".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteRole {
    Member,
    Admin,
}

impl InviteRole {
    /// Parse the spec role string.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "member" => Some(Self::Member),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }

    /// Spec wire token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::Admin => "admin",
        }
    }
}

/// POST /groups/invite body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupInvitation {
    pub group_id: String,
    pub group_name: String,
    pub mcast: String,
    pub inviter: String,
    pub role: InviteRole,
    pub expires: u64,
    pub signature: Vec<u8>,
}

impl GroupInvitation {
    /// Reject unknown roles. Owner is not an invite role (spec 18.8.2).
    pub fn new(
        group_id: String,
        group_name: String,
        mcast: String,
        inviter: String,
        role: InviteRole,
        expires: u64,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            group_id,
            group_name,
            mcast,
            inviter,
            role,
            expires,
            signature,
        }
    }
}

/// POST /groups/remove body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRemoval {
    pub group_id: String,
    pub removed_by: String,
    pub reason: Option<String>,
    pub signature: Vec<u8>,
}

/// Local group record (spec/12-apps.md 18.8.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub mcast: String,
    pub owner: String,
    pub admins: Vec<String>,
    pub members: Vec<String>,
    pub key_id: Option<String>,
    pub created: u64,
    pub key_epoch: u32,
}

impl Group {
    /// Owner is always a member (spec 18.8.2).
    pub fn new(id: String, name: String, mcast: String, owner: String, created: u64) -> Self {
        Self {
            id,
            name,
            mcast,
            owner: owner.clone(),
            admins: Vec::new(),
            members: vec![owner],
            key_id: None,
            created,
            key_epoch: 1,
        }
    }

    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Rotate key_epoch after a removal (spec 18.8.2). Callers replace key material.
    pub fn rekey(&mut self, removed_member: Option<&str>) {
        if let Some(member) = removed_member {
            if member != self.owner {
                self.members.retain(|m| m != member);
                self.admins.retain(|admin| admin != member);
            }
        }
        self.key_epoch = self.key_epoch.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_roles_are_member_or_admin() {
        assert_eq!(InviteRole::parse("member"), Some(InviteRole::Member));
        assert_eq!(InviteRole::parse("admin"), Some(InviteRole::Admin));
        assert_eq!(InviteRole::parse("owner"), None);
        assert_eq!(InviteRole::Member.as_str(), "member");
        assert_eq!(InviteRole::Admin.as_str(), "admin");
    }

    #[test]
    fn owner_is_always_a_member() {
        let group = Group::new(
            "team-alpha".into(),
            "Team Alpha".into(),
            "ff35:0040::1".into(),
            "0200::1111".into(),
            1716742800,
        );
        assert_eq!(group.member_count(), 1);
        assert_eq!(group.members[0], group.owner);
        assert_eq!(group.key_epoch, 1);
        assert!(group.admins.is_empty());
    }

    #[test]
    fn rekey_increments_epoch_and_drops_member() {
        let mut group = Group::new(
            "team-alpha".into(),
            "Team Alpha".into(),
            "ff35:0040::1".into(),
            "0200::1111".into(),
            1716742800,
        );
        group.members.push("0200::3333".into());
        group.rekey(Some("0200::3333"));
        assert_eq!(group.key_epoch, 2);
        assert!(!group.members.iter().any(|m| m == "0200::3333"));
        assert!(group.members.contains(&group.owner));
    }

    #[test]
    fn rekey_drops_admin_but_never_owner() {
        let mut group = Group::new(
            "team-alpha".into(),
            "Team Alpha".into(),
            "ff35:0040::1".into(),
            "0200::1111".into(),
            1716742800,
        );
        let admin = "0200::2222".to_string();
        group.members.push(admin.clone());
        group.admins.push(admin.clone());

        group.rekey(Some(&admin));
        assert!(!group.members.contains(&admin));
        assert!(!group.admins.contains(&admin));
        assert!(group.members.contains(&group.owner));

        let owner = group.owner.clone();
        group.rekey(Some(&owner));
        assert!(group.members.contains(&group.owner));
    }
}
