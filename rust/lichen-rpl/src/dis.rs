//! Authenticated DIS solicitation handling (RFC 6550 Sections 6.7.9 and 8.3).

use crate::message::{Dis, OptionIter, RplError};
use crate::trickle::TrickleTimer;

const OPT_SOLICITED_INFORMATION: u8 = 7;
const VERSION_PREDICATE: u8 = 0x80;
const INSTANCE_PREDICATE: u8 = 0x40;
const DODAG_PREDICATE: u8 = 0x20;
const SOLICITED_INFORMATION_LEN: usize = 19;

/// Action selected after a link-authenticated, replay-admitted DIS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisAction {
    Ignore,
    ResetTrickle,
    UnicastDioWithConfiguration,
}

/// Local DODAG state used by Solicited Information predicates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisContext {
    pub rpl_instance_id: u8,
    pub dodag_id: [u8; 16],
    pub version: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SolicitedInformation {
    rpl_instance_id: u8,
    flags: u8,
    dodag_id: [u8; 16],
    version: u8,
}

impl SolicitedInformation {
    fn from_data(data: &[u8]) -> Result<Self, RplError> {
        if data.len() != SOLICITED_INFORMATION_LEN {
            return Err(RplError::InvalidOption);
        }
        Ok(Self {
            rpl_instance_id: data[0],
            flags: data[1],
            dodag_id: data[2..18]
                .try_into()
                .map_err(|_| RplError::InvalidOption)?,
            version: data[18],
        })
    }

    fn matches(self, context: DisContext) -> bool {
        (self.flags & INSTANCE_PREDICATE == 0 || self.rpl_instance_id == context.rpl_instance_id)
            && (self.flags & DODAG_PREDICATE == 0 || self.dodag_id == context.dodag_id)
            && (self.flags & VERSION_PREDICATE == 0 || self.version == context.version)
    }
}

/// Handle one DIS after the caller has verified its link signature and replay tuple.
///
/// A matching multicast DIS resets the DIO Trickle timer. A matching unicast
/// DIS requests an immediate unicast DIO with a DODAG Configuration option and
/// deliberately leaves Trickle unchanged. DIO construction and transmission
/// remain the caller's responsibility.
pub fn handle_authenticated_dis(
    wire: &[u8],
    destination_is_multicast: bool,
    context: DisContext,
    trickle: &mut TrickleTimer,
    now_ms: u64,
    rand_offset: u32,
) -> Result<DisAction, RplError> {
    Dis::from_bytes(wire)?;
    let mut solicited = None;
    for option in OptionIter::new(Dis::options_tail(wire)) {
        let option = option?;
        if option.opt_type != OPT_SOLICITED_INFORMATION {
            continue;
        }
        if solicited.is_some() {
            return Err(RplError::InvalidOption);
        }
        solicited = Some(SolicitedInformation::from_data(option.data)?);
    }

    if solicited.is_some_and(|information| !information.matches(context)) {
        return Ok(DisAction::Ignore);
    }
    if !destination_is_multicast {
        return Ok(DisAction::UnicastDioWithConfiguration);
    }

    trickle.reset(now_ms, rand_offset);
    Ok(DisAction::ResetTrickle)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTEXT: DisContext = DisContext {
        rpl_instance_id: 7,
        dodag_id: [0x22; 16],
        version: 9,
    };

    fn timer() -> TrickleTimer {
        let mut timer = TrickleTimer::new(4_000, 8, 10);
        timer.start(0, 0);
        timer.fire_transmit();
        timer.expire(4_000, 0);
        timer.heard_consistent();
        timer
    }

    fn solicited(flags: u8, instance: u8, dodag_id: [u8; 16], version: u8) -> [u8; 21] {
        let mut option = [0u8; 21];
        option[0] = OPT_SOLICITED_INFORMATION;
        option[1] = SOLICITED_INFORMATION_LEN as u8;
        option[2] = instance;
        option[3] = flags;
        option[4..20].copy_from_slice(&dodag_id);
        option[20] = version;
        option
    }

    fn dis_with_options(options: &[u8]) -> std::vec::Vec<u8> {
        let mut wire = std::vec![0, 0];
        wire.extend_from_slice(options);
        wire
    }

    #[test]
    fn multicast_without_predicates_resets_trickle() {
        let mut timer = timer();
        assert_eq!(timer.interval, 8_000);
        assert_eq!(timer.counter, 1);

        let action =
            handle_authenticated_dis(&[0xff, 0], true, CONTEXT, &mut timer, 10_000, 0).unwrap();

        assert_eq!(action, DisAction::ResetTrickle);
        assert_eq!(timer.interval, 4_000);
        assert_eq!(timer.interval_start, 10_000);
        assert_eq!(timer.counter, 0);
    }

    #[test]
    fn every_matching_predicate_combination_resets() {
        for flags in [0x00, 0x20, 0x40, 0x80, 0xe0, 0xff] {
            let mut timer = timer();
            let wire = dis_with_options(&solicited(flags, 7, CONTEXT.dodag_id, 9));
            assert_eq!(
                handle_authenticated_dis(&wire, true, CONTEXT, &mut timer, 10_000, 1),
                Ok(DisAction::ResetTrickle)
            );
        }
    }

    #[test]
    fn enabled_predicate_mismatch_is_ignored_without_mutation() {
        let cases = [
            solicited(INSTANCE_PREDICATE, 8, CONTEXT.dodag_id, 9),
            solicited(DODAG_PREDICATE, 7, [0x33; 16], 9),
            solicited(VERSION_PREDICATE, 7, CONTEXT.dodag_id, 10),
        ];
        for option in cases {
            let mut timer = timer();
            let before = (
                timer.interval,
                timer.interval_start,
                timer.counter,
                timer.transmit_time,
            );
            let wire = dis_with_options(&option);
            assert_eq!(
                handle_authenticated_dis(&wire, true, CONTEXT, &mut timer, 10_000, 0),
                Ok(DisAction::Ignore)
            );
            assert_eq!(
                (
                    timer.interval,
                    timer.interval_start,
                    timer.counter,
                    timer.transmit_time,
                ),
                before
            );
        }
    }

    #[test]
    fn disabled_predicates_and_reserved_flags_are_ignored() {
        let mut timer = timer();
        let wire = dis_with_options(&solicited(0x1f, 255, [0x33; 16], 255));
        assert_eq!(
            handle_authenticated_dis(&wire, true, CONTEXT, &mut timer, 10_000, 0),
            Ok(DisAction::ResetTrickle)
        );
    }

    #[test]
    fn unicast_match_requests_configured_dio_without_reset() {
        for wire in [
            std::vec![0, 0],
            dis_with_options(&solicited(0xe0, 7, CONTEXT.dodag_id, 9)),
        ] {
            let mut timer = timer();
            let before = (
                timer.interval,
                timer.interval_start,
                timer.counter,
                timer.transmit_time,
            );
            assert_eq!(
                handle_authenticated_dis(&wire, false, CONTEXT, &mut timer, 10_000, 0),
                Ok(DisAction::UnicastDioWithConfiguration)
            );
            assert_eq!(
                (
                    timer.interval,
                    timer.interval_start,
                    timer.counter,
                    timer.transmit_time,
                ),
                before
            );
        }
    }

    #[test]
    fn unicast_predicate_mismatch_is_ignored() {
        let mut timer = timer();
        let wire = dis_with_options(&solicited(VERSION_PREDICATE, 7, CONTEXT.dodag_id, 8));
        assert_eq!(
            handle_authenticated_dis(&wire, false, CONTEXT, &mut timer, 10_000, 0),
            Ok(DisAction::Ignore)
        );
    }

    #[test]
    fn malformed_or_duplicate_options_fail_before_timer_mutation() {
        let malformed = [
            std::vec![0],
            std::vec![0, 1],
            std::vec![0, 0, OPT_SOLICITED_INFORMATION],
            dis_with_options(&[OPT_SOLICITED_INFORMATION, 19, 0]),
            dis_with_options(&[
                OPT_SOLICITED_INFORMATION,
                18,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ]),
            {
                let option = solicited(0, 0, [0; 16], 0);
                let mut options = option.to_vec();
                options.extend_from_slice(&option);
                dis_with_options(&options)
            },
        ];
        for wire in malformed {
            let mut timer = timer();
            let before = (
                timer.interval,
                timer.interval_start,
                timer.counter,
                timer.transmit_time,
            );
            assert!(handle_authenticated_dis(&wire, true, CONTEXT, &mut timer, 10_000, 0).is_err());
            assert_eq!(
                (
                    timer.interval,
                    timer.interval_start,
                    timer.counter,
                    timer.transmit_time,
                ),
                before
            );
        }
    }

    #[test]
    fn padding_and_unknown_options_do_not_hide_valid_solicitation() {
        let mut options = std::vec![0, 0xee, 1, 0xaa];
        options.extend_from_slice(&solicited(0xe0, 7, CONTEXT.dodag_id, 9));
        let wire = dis_with_options(&options);
        let mut timer = timer();
        assert_eq!(
            handle_authenticated_dis(&wire, true, CONTEXT, &mut timer, 10_000, 0),
            Ok(DisAction::ResetTrickle)
        );
    }
}
