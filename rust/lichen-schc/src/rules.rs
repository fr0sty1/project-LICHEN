//! SCHC rule model (RFC 8724 §7).

use lichen_core::constants::{
    RULE_GLOBAL_COAP, RULE_GLOBAL_OSCORE, RULE_ICMPV6_ECHO, RULE_LINK_LOCAL_COAP,
    RULE_LINK_LOCAL_OSCORE, RULE_MQTT_SN, RULE_RPL_DAO, RULE_RPL_DIO, RULE_UNCOMPRESSED,
};

/// Matching Operator — decides whether a rule applies to a field value.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Mo {
    Equal,
    #[default]
    Ignore,
    Msb,
    MatchMapping,
}

/// Compression/Decompression Action — what appears in the residue.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Cda {
    #[default]
    NotSent,
    ValueSent,
    Lsb,
    Compute,
    MappingSent,
}

/// One field's compression behaviour within a rule (RFC 8724 §7.4).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FieldDescriptor {
    /// Stable identifier, e.g. `"CoAP.MID"`.
    pub field_id: &'static str,
    /// Field width in bits.
    pub length_bits: u16,
    pub mo: Mo,
    pub cda: Cda,
    /// Target value for Equal/MSB matching and NotSent reconstruction.
    pub target_value: u128,
    /// For MSB: number of most-significant bits to match; also determines
    /// residue width (`length_bits - mo_arg`).
    pub mo_arg: Option<u16>,
    /// For MatchMapping/MappingSent: ordered list of possible values (per RFC 8724 §7.4).
    /// Index into table sent as residue for MappingSent CDA.
    pub mapping: Option<&'static [u128]>,
}

/// A SCHC rule: an ordered list of field descriptors keyed by a rule ID.
///
/// Rule IDs 0-127 are compression rules; 255 is the uncompressed fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule {
    pub rule_id: u8,
    pub fields: &'static [FieldDescriptor],
}

// ---------------------------------------------------------------------------
const LINK_LOCAL_PREFIX_TV: u128 = 0xfe80_0000_0000_0000_0000_0000_0000_0000;

// Common field groups to match Python rules.py:246-311 and parsed fields in headers.rs/codec.rs:296+
const IPV6_BASE: &[FieldDescriptor] = &[
    FieldDescriptor {
        field_id: "IPv6.version",
        length_bits: 4,
        mo: Mo::Equal,
        cda: Cda::NotSent,
        target_value: 6,
        mo_arg: None,
        mapping: None,
    },
    FieldDescriptor {
        field_id: "IPv6.traffic_class",
        length_bits: 8,
        mo: Mo::Equal,
        cda: Cda::NotSent,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
    FieldDescriptor {
        field_id: "IPv6.flow_label",
        length_bits: 20,
        mo: Mo::Equal,
        cda: Cda::NotSent,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
    FieldDescriptor {
        field_id: "IPv6.payload_length",
        length_bits: 16,
        mo: Mo::Ignore,
        cda: Cda::Compute,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
    FieldDescriptor {
        field_id: "IPv6.hop_limit",
        length_bits: 8,
        mo: Mo::Ignore,
        cda: Cda::ValueSent,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
];

const LINK_LOCAL_ADDR: &[FieldDescriptor] = &[
    FieldDescriptor {
        field_id: "IPv6.src",
        length_bits: 128,
        mo: Mo::Msb,
        cda: Cda::Lsb,
        target_value: LINK_LOCAL_PREFIX_TV,
        mo_arg: Some(64),
        mapping: None,
    },
    FieldDescriptor {
        field_id: "IPv6.dst",
        length_bits: 128,
        mo: Mo::Msb,
        cda: Cda::Lsb,
        target_value: LINK_LOCAL_PREFIX_TV,
        mo_arg: Some(64),
        mapping: None,
    },
];

const GLOBAL_ADDR: &[FieldDescriptor] = &[
    FieldDescriptor {
        field_id: "IPv6.src",
        length_bits: 128,
        mo: Mo::Ignore,
        cda: Cda::ValueSent,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
    FieldDescriptor {
        field_id: "IPv6.dst",
        length_bits: 128,
        mo: Mo::Ignore,
        cda: Cda::ValueSent,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
];

const NEXT_UDP: FieldDescriptor = FieldDescriptor {
    field_id: "IPv6.next_header",
    length_bits: 8,
    mo: Mo::Equal,
    cda: Cda::NotSent,
    target_value: 17,
    mo_arg: None,
    mapping: None,
};
const NEXT_ICMPV6: FieldDescriptor = FieldDescriptor {
    field_id: "IPv6.next_header",
    length_bits: 8,
    mo: Mo::Equal,
    cda: Cda::NotSent,
    target_value: 58,
    mo_arg: None,
    mapping: None,
};

const UDP_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor {
        field_id: "UDP.src_port",
        length_bits: 16,
        mo: Mo::Ignore,
        cda: Cda::ValueSent,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
    FieldDescriptor {
        field_id: "UDP.dst_port",
        length_bits: 16,
        mo: Mo::Ignore,
        cda: Cda::ValueSent,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
    FieldDescriptor {
        field_id: "UDP.length",
        length_bits: 16,
        mo: Mo::Ignore,
        cda: Cda::Compute,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
    FieldDescriptor {
        field_id: "UDP.checksum",
        length_bits: 16,
        mo: Mo::Ignore,
        cda: Cda::Compute,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
];

const COAP_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor {
        field_id: "CoAP.version",
        length_bits: 2,
        mo: Mo::Equal,
        cda: Cda::NotSent,
        target_value: 1,
        mo_arg: None,
        mapping: None,
    },
    FieldDescriptor {
        field_id: "CoAP.type",
        length_bits: 2,
        mo: Mo::Ignore,
        cda: Cda::ValueSent,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
    FieldDescriptor {
        field_id: "CoAP.tkl",
        length_bits: 4,
        mo: Mo::Ignore,
        cda: Cda::ValueSent,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
    FieldDescriptor {
        field_id: "CoAP.code",
        length_bits: 8,
        mo: Mo::Ignore,
        cda: Cda::ValueSent,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
    FieldDescriptor {
        field_id: "CoAP.mid",
        length_bits: 16,
        mo: Mo::Ignore,
        cda: Cda::ValueSent,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
];

const ICMPV6_ECHO_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor {
        field_id: "ICMPv6.type",
        length_bits: 8,
        mo: Mo::Ignore,
        cda: Cda::ValueSent,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
    FieldDescriptor {
        field_id: "ICMPv6.code",
        length_bits: 8,
        mo: Mo::Equal,
        cda: Cda::NotSent,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
    FieldDescriptor {
        field_id: "ICMPv6.checksum",
        length_bits: 16,
        mo: Mo::Ignore,
        cda: Cda::Compute,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
    FieldDescriptor {
        field_id: "ICMPv6.identifier",
        length_bits: 16,
        mo: Mo::Ignore,
        cda: Cda::ValueSent,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
    FieldDescriptor {
        field_id: "ICMPv6.sequence",
        length_bits: 16,
        mo: Mo::Ignore,
        cda: Cda::ValueSent,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
];

const ICMPV6_RPL_BASE: &[FieldDescriptor] = &[
    FieldDescriptor {
        field_id: "ICMPv6.type",
        length_bits: 8,
        mo: Mo::Equal,
        cda: Cda::NotSent,
        target_value: 155,
        mo_arg: None,
        mapping: None,
    },
    FieldDescriptor {
        field_id: "ICMPv6.code",
        length_bits: 8,
        mo: Mo::Equal,
        cda: Cda::NotSent,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    }, // overridden per-rule
    FieldDescriptor {
        field_id: "ICMPv6.checksum",
        length_bits: 16,
        mo: Mo::Ignore,
        cda: Cda::Compute,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
];

const RPL_DIO_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor {
        field_id: "RPL.instance",
        length_bits: 8,
        mo: Mo::Ignore,
        cda: Cda::ValueSent,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
    FieldDescriptor {
        field_id: "RPL.version",
        length_bits: 8,
        mo: Mo::Ignore,
        cda: Cda::ValueSent,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
    FieldDescriptor {
        field_id: "RPL.rank",
        length_bits: 16,
        mo: Mo::Ignore,
        cda: Cda::ValueSent,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
    FieldDescriptor {
        field_id: "RPL.gmop",
        length_bits: 8,
        mo: Mo::Ignore,
        cda: Cda::ValueSent,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
    FieldDescriptor {
        field_id: "RPL.dtsn",
        length_bits: 8,
        mo: Mo::Ignore,
        cda: Cda::ValueSent,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
    FieldDescriptor {
        field_id: "RPL.flags",
        length_bits: 8,
        mo: Mo::Equal,
        cda: Cda::NotSent,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
    FieldDescriptor {
        field_id: "RPL.reserved",
        length_bits: 8,
        mo: Mo::Equal,
        cda: Cda::NotSent,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
    FieldDescriptor {
        field_id: "RPL.dodagid",
        length_bits: 128,
        mo: Mo::Ignore,
        cda: Cda::ValueSent,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
];

/// RPL option type values common in DIO messages.
const RPL_OPTION_TYPE_MAPPING: &[u128] = &[0, 3, 2, 5, 6, 7];

/// PIO (Prefix Information Option) field descriptors for RPL DIO.
///
/// Uses MatchMapping on RPL.Option.Type, with PIO-specific sub-fields.
const RPL_PIO_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor {
        field_id: "RPL.Option.Type",
        length_bits: 8,
        mo: Mo::MatchMapping,
        cda: Cda::MappingSent,
        target_value: 3,
        mo_arg: None,
        mapping: Some(RPL_OPTION_TYPE_MAPPING),
    },
    FieldDescriptor {
        field_id: "RPL.Option.Length",
        length_bits: 8,
        mo: Mo::Equal,
        cda: Cda::NotSent,
        target_value: 30,
        mo_arg: None,
        mapping: None,
    },
    FieldDescriptor {
        field_id: "PIO.Prefix Length",
        length_bits: 8,
        mo: Mo::Equal,
        cda: Cda::NotSent,
        target_value: 64,
        mo_arg: None,
        mapping: None,
    },
    FieldDescriptor {
        field_id: "PIO.Flags",
        length_bits: 8,
        mo: Mo::Equal,
        cda: Cda::NotSent,
        target_value: 0xC0,
        mo_arg: None,
        mapping: None,
    },
    FieldDescriptor {
        field_id: "PIO.Lifetime",
        length_bits: 32,
        mo: Mo::Ignore,
        cda: Cda::ValueSent,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
    FieldDescriptor {
        field_id: "PIO.Prefix",
        length_bits: 128,
        mo: Mo::Msb,
        cda: Cda::Lsb,
        target_value: 0xfe80_0000_0000_0000_0000_0000_0000_0000,
        mo_arg: Some(64),
        mapping: None,
    },
];

const RPL_DAO_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor {
        field_id: "RPL.instance",
        length_bits: 8,
        mo: Mo::Ignore,
        cda: Cda::ValueSent,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
    FieldDescriptor {
        field_id: "RPL.flags",
        length_bits: 8,
        mo: Mo::Ignore,
        cda: Cda::ValueSent,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
    FieldDescriptor {
        field_id: "RPL.reserved",
        length_bits: 8,
        mo: Mo::Equal,
        cda: Cda::NotSent,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
    FieldDescriptor {
        field_id: "RPL.seq",
        length_bits: 8,
        mo: Mo::Ignore,
        cda: Cda::ValueSent,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
    FieldDescriptor {
        field_id: "RPL.dodagid",
        length_bits: 128,
        mo: Mo::Ignore,
        cda: Cda::ValueSent,
        target_value: 0,
        mo_arg: None,
        mapping: None,
    },
];

// Full rules matching Python rules.py helpers (_ipv6_header_fields, _coap_fields) and codec (RPL_DIO/DAO/OSCORE/MQTT_SN complete)
pub const LINK_LOCAL_COAP_RULE: Rule = Rule {
    rule_id: RULE_LINK_LOCAL_COAP,
    fields: &[
        IPV6_BASE[0],
        IPV6_BASE[1],
        IPV6_BASE[2],
        IPV6_BASE[3],
        NEXT_UDP,
        IPV6_BASE[4],
        LINK_LOCAL_ADDR[0],
        LINK_LOCAL_ADDR[1],
        UDP_FIELDS[0],
        UDP_FIELDS[1],
        UDP_FIELDS[2],
        UDP_FIELDS[3],
        COAP_FIELDS[0],
        COAP_FIELDS[1],
        COAP_FIELDS[2],
        COAP_FIELDS[3],
        COAP_FIELDS[4],
    ],
};
pub const GLOBAL_COAP_RULE: Rule = Rule {
    rule_id: RULE_GLOBAL_COAP,
    fields: &[
        IPV6_BASE[0],
        IPV6_BASE[1],
        IPV6_BASE[2],
        IPV6_BASE[3],
        NEXT_UDP,
        IPV6_BASE[4],
        GLOBAL_ADDR[0],
        GLOBAL_ADDR[1],
        UDP_FIELDS[0],
        UDP_FIELDS[1],
        UDP_FIELDS[2],
        UDP_FIELDS[3],
        COAP_FIELDS[0],
        COAP_FIELDS[1],
        COAP_FIELDS[2],
        COAP_FIELDS[3],
        COAP_FIELDS[4],
    ],
};
pub const ICMPV6_ECHO_RULE: Rule = Rule {
    rule_id: RULE_ICMPV6_ECHO,
    fields: &[
        IPV6_BASE[0],
        IPV6_BASE[1],
        IPV6_BASE[2],
        IPV6_BASE[3],
        NEXT_ICMPV6,
        IPV6_BASE[4],
        LINK_LOCAL_ADDR[0],
        LINK_LOCAL_ADDR[1],
        ICMPV6_ECHO_FIELDS[0],
        ICMPV6_ECHO_FIELDS[1],
        ICMPV6_ECHO_FIELDS[2],
        ICMPV6_ECHO_FIELDS[3],
        ICMPV6_ECHO_FIELDS[4],
    ],
};
pub const RPL_DIO_RULE: Rule = Rule {
    rule_id: RULE_RPL_DIO,
    fields: &[
        IPV6_BASE[0],
        IPV6_BASE[1],
        IPV6_BASE[2],
        IPV6_BASE[3],
        NEXT_ICMPV6,
        IPV6_BASE[4],
        LINK_LOCAL_ADDR[0],
        LINK_LOCAL_ADDR[1],
        ICMPV6_RPL_BASE[0],
        FieldDescriptor {
            field_id: "ICMPv6.code",
            length_bits: 8,
            mo: Mo::Equal,
            cda: Cda::NotSent,
            target_value: 1,
            mo_arg: None,
            mapping: None,
        },
        ICMPV6_RPL_BASE[2],
        RPL_DIO_FIELDS[0],
        RPL_DIO_FIELDS[1],
        RPL_DIO_FIELDS[2],
        RPL_DIO_FIELDS[3],
        RPL_DIO_FIELDS[4],
        RPL_DIO_FIELDS[5],
        RPL_DIO_FIELDS[6],
        RPL_DIO_FIELDS[7],
        RPL_PIO_FIELDS[0],
        RPL_PIO_FIELDS[1],
        RPL_PIO_FIELDS[2],
        RPL_PIO_FIELDS[3],
        RPL_PIO_FIELDS[4],
        RPL_PIO_FIELDS[5],
    ],
};
pub const RPL_DAO_RULE: Rule = Rule {
    rule_id: RULE_RPL_DAO,
    fields: &[
        IPV6_BASE[0],
        IPV6_BASE[1],
        IPV6_BASE[2],
        IPV6_BASE[3],
        NEXT_ICMPV6,
        IPV6_BASE[4],
        LINK_LOCAL_ADDR[0],
        LINK_LOCAL_ADDR[1],
        ICMPV6_RPL_BASE[0],
        FieldDescriptor {
            field_id: "ICMPv6.code",
            length_bits: 8,
            mo: Mo::Equal,
            cda: Cda::NotSent,
            target_value: 2,
            mo_arg: None,
            mapping: None,
        },
        ICMPV6_RPL_BASE[2],
        RPL_DAO_FIELDS[0],
        RPL_DAO_FIELDS[1],
        RPL_DAO_FIELDS[2],
        RPL_DAO_FIELDS[3],
        RPL_DAO_FIELDS[4],
    ],
};
pub const LINK_LOCAL_OSCORE_RULE: Rule = Rule {
    rule_id: RULE_LINK_LOCAL_OSCORE,
    fields: &[
        IPV6_BASE[0],
        IPV6_BASE[1],
        IPV6_BASE[2],
        IPV6_BASE[3],
        NEXT_UDP,
        IPV6_BASE[4],
        LINK_LOCAL_ADDR[0],
        LINK_LOCAL_ADDR[1],
        UDP_FIELDS[0],
        UDP_FIELDS[1],
        UDP_FIELDS[2],
        UDP_FIELDS[3],
        COAP_FIELDS[0],
        COAP_FIELDS[1],
        COAP_FIELDS[2],
        COAP_FIELDS[3],
        COAP_FIELDS[4],
    ],
};
pub const GLOBAL_OSCORE_RULE: Rule = Rule {
    rule_id: RULE_GLOBAL_OSCORE,
    fields: &[
        IPV6_BASE[0],
        IPV6_BASE[1],
        IPV6_BASE[2],
        IPV6_BASE[3],
        NEXT_UDP,
        IPV6_BASE[4],
        GLOBAL_ADDR[0],
        GLOBAL_ADDR[1],
        UDP_FIELDS[0],
        UDP_FIELDS[1],
        UDP_FIELDS[2],
        UDP_FIELDS[3],
        COAP_FIELDS[0],
        COAP_FIELDS[1],
        COAP_FIELDS[2],
        COAP_FIELDS[3],
        COAP_FIELDS[4],
    ],
};
pub const MQTT_SN_RULE: Rule = Rule {
    rule_id: RULE_MQTT_SN,
    fields: &[
        IPV6_BASE[0],
        IPV6_BASE[1],
        IPV6_BASE[2],
        IPV6_BASE[3],
        NEXT_UDP,
        IPV6_BASE[4],
        GLOBAL_ADDR[0], // use global (Ignore) to support both link-local and global addresses in one rule
        GLOBAL_ADDR[1],
        UDP_FIELDS[0],
        UDP_FIELDS[1],
        UDP_FIELDS[2],
        UDP_FIELDS[3],
    ], // port matching and direction bit handled in codec; uses IGNORE/VALUE_SENT to match Python helper style
};
pub const UNCOMPRESSED_RULE: Rule = Rule {
    rule_id: RULE_UNCOMPRESSED,
    fields: &[],
};
