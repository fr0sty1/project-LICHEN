// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

use lichen_gateway::membership::{GroupInvitation, GroupRemoval, InviteRole};
use serde_json::Value;

const VECTORS_JSON: &str = include_str!("../../../test/vectors/groups_membership.json");

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn groups_membership_vectors_parse() {
    let document: Value = serde_json::from_str(VECTORS_JSON).expect("parse");
    let mut invitations = 0;
    let mut removals = 0;
    for case in document["vectors"].as_array().unwrap() {
        let payload = &case["payload"];
        let signature = hex(payload["signature_hex"].as_str().unwrap());
        match case["kind"].as_str().unwrap() {
            "invitation" => {
                let role =
                    InviteRole::parse(payload["role"].as_str().unwrap()).expect("invite role");
                let invite = GroupInvitation::new(
                    payload["group_id"].as_str().unwrap().to_string(),
                    payload["group_name"].as_str().unwrap().to_string(),
                    payload["mcast"].as_str().unwrap().to_string(),
                    payload["inviter"].as_str().unwrap().to_string(),
                    role,
                    payload["expires"].as_u64().unwrap(),
                    signature,
                );
                assert_eq!(invite.role.as_str(), payload["role"].as_str().unwrap());
                invitations += 1;
            }
            "removal" => {
                let removal = GroupRemoval {
                    group_id: payload["group_id"].as_str().unwrap().to_string(),
                    removed_by: payload["removed_by"].as_str().unwrap().to_string(),
                    reason: payload["reason"].as_str().map(str::to_string),
                    signature,
                };
                assert_eq!(removal.group_id, payload["group_id"].as_str().unwrap());
                removals += 1;
            }
            other => panic!("unknown kind {other}"),
        }
    }
    assert!(invitations >= 2);
    assert!(removals >= 1);
}
