# LICHEN Internet-Drafts

**STATUS: PRELIMINARY — WORK IN PROGRESS**

These documents are early drafts developed alongside the LICHEN reference
implementation. They are not IETF submissions. Coding agents with human
oversight may modify these specifications as implementation experience is
gained.

## Documents

| Draft | Title | Status |
|-------|-------|--------|
| [draft-lichen-schnorr-00](draft-lichen-schnorr-00.md) | Schnorr Signatures with Truncated Challenge | Preliminary |
| [draft-lichen-schc-lora-00](draft-lichen-schc-lora-00.md) | SCHC Profile for LoRa Mesh Networks | Preliminary |
| [draft-lichen-rpl-lora-00](draft-lichen-rpl-lora-00.md) | RPL Configuration for LoRa Mesh Networks | Preliminary |

## Purpose

These drafts document the novel or LoRa-specific aspects of LICHEN that
may be useful to the broader community:

1. **Schnorr-48:** A bandwidth-efficient signature scheme for constrained
   networks. Useful beyond LICHEN for any LoRa/LPWAN application needing
   per-packet authentication.

2. **SCHC-LoRa:** A SCHC compression profile. The IETF has a process for
   SCHC profiles; this could feed into that if the community finds it useful.

3. **RPL-LoRa:** RPL timing and configuration for LoRa characteristics.
   Useful for any RPL-over-LoRa deployment.

## Future Drafts (Not Yet Written)

| Draft | Topic | Priority |
|-------|-------|----------|
| draft-lichen-link | Link layer framing, LLSec | Medium |
| draft-lichen-edhoc | EDHOC profile for LICHEN | Low (uses RFC 9528) |
| draft-lichen-lci | Local Client Interface | Low (LICHEN-specific) |
| draft-lichen-apps | Application protocols | Low (LICHEN-specific) |

## Contributing

These drafts are maintained in the LICHEN repository. Contributions via
pull request are welcome. The primary audience is:

1. LICHEN implementers (reference during coding)
2. Security reviewers (especially for Schnorr-48)
3. IETF community (if standardization is pursued)

## Versioning

Draft versions follow IETF convention:
- `-00`: Initial draft
- `-01`, `-02`, etc.: Revisions

Major changes increment the version number. The drafts will be updated
as the reference implementation matures.

## License

These documents are released under CC-BY-4.0, consistent with the LICHEN
specification.
