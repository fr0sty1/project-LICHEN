use lichen_rpl::trickle::{
    TrickleScope, TrickleTimer, LICHEN_TRICKLE_IMAX_DOUBLINGS, LICHEN_TRICKLE_IMAX_MS,
    LICHEN_TRICKLE_IMIN_MS, LICHEN_TRICKLE_K,
};
use serde_json::Value;

fn case<'a>(document: &'a Value, name: &str) -> &'a Value {
    document["vectors"]
        .as_array()
        .expect("vectors must be an array")
        .iter()
        .find(|case| case["name"] == name)
        .unwrap_or_else(|| panic!("missing canonical Trickle vector {name}"))
}

fn u32_field(case: &Value, field: &str) -> u32 {
    u32::try_from(
        case[field]
            .as_u64()
            .expect("field must be an unsigned integer"),
    )
    .expect("Trickle vector field must fit u32")
}

fn hex_16(value: &str) -> [u8; 16] {
    assert_eq!(value.len(), 32, "DODAG ID hex must encode 16 bytes");
    let mut output = [0u8; 16];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .expect("DODAG ID must be lowercase hexadecimal");
    }
    output
}

#[test]
fn trickle_state_machine_matches_canonical_packets_timing_vectors() {
    let document: Value =
        serde_json::from_str(include_str!("../../../test/vectors/packets-timing.json"))
            .expect("packets-timing vectors must be valid JSON");

    let constants = case(&document, "trickle_constants");
    let imin = u32_field(constants, "Imin_ms");
    let k = u32_field(constants, "k");
    let mut timer = TrickleTimer::new(imin, 8, k);
    assert_eq!(timer.max_interval, u32_field(constants, "Imax_exact_ms"));

    let profile = case(&document, "trickle_profile_math");
    assert_eq!(LICHEN_TRICKLE_IMIN_MS, u32_field(profile, "Imin_ms"));
    assert_eq!(
        LICHEN_TRICKLE_IMAX_DOUBLINGS,
        u32_field(profile, "Imax_doublings")
    );
    assert_eq!(LICHEN_TRICKLE_IMAX_MS, u32_field(profile, "Imax_exact_ms"));
    assert_eq!(LICHEN_TRICKLE_K, u32_field(profile, "k"));
    let mut profile_timer = TrickleTimer::lichen_profile();
    profile_timer.start(0, 0);
    let intervals = profile["interval_sequence_ms"]
        .as_array()
        .expect("interval sequence must be an array");
    for (index, expected) in intervals.iter().enumerate() {
        let expected = u32::try_from(expected.as_u64().unwrap()).unwrap();
        assert_eq!(profile_timer.interval, expected);
        assert!(profile_timer.transmit_time >= u64::from(expected.div_ceil(2)));
        assert!(profile_timer.transmit_time < profile_timer.interval_end());
        if index + 1 < intervals.len() {
            let _ = profile_timer.fire_transmit();
            profile_timer.expire(profile_timer.interval_end(), 0);
        }
    }
    for transmit_case in profile["transmit_cases"].as_array().unwrap() {
        let interval = u32_field(transmit_case, "interval_ms");
        let mut endpoint = TrickleTimer::new(interval, 0, LICHEN_TRICKLE_K);
        endpoint.start(0, u32_field(transmit_case, "rand_offset_ms"));
        assert_eq!(
            endpoint.transmit_time,
            transmit_case["expected_transmit_offset_ms"]
                .as_u64()
                .unwrap()
        );
        assert!(endpoint.transmit_time >= u64::from(interval.div_ceil(2)));
        assert!(endpoint.transmit_time < u64::from(interval));
    }

    timer.start(0, 0);
    let start = case(&document, "trickle_interval_start");
    assert_eq!(timer.interval, u32_field(start, "interval"));
    assert_eq!(
        timer.interval_start,
        start["interval_start"].as_u64().unwrap()
    );
    assert_eq!(
        timer.transmit_time,
        start["transmit_time"].as_u64().unwrap()
    );
    assert_eq!(
        timer.interval_end(),
        start["interval_end"].as_u64().unwrap()
    );

    timer.heard_consistent();
    let consistent = case(&document, "trickle_heard_consistent");
    assert_eq!(timer.counter, u32_field(consistent, "counter"));
    assert_eq!(
        timer.should_transmit(),
        consistent["should_transmit"].as_bool().unwrap()
    );

    for _ in 0..20 {
        timer.heard_consistent();
    }
    let suppressed = case(&document, "trickle_suppressed_at_k");
    assert_eq!(timer.counter, u32_field(suppressed, "counter"));
    assert_eq!(
        timer.should_transmit(),
        suppressed["should_transmit"].as_bool().unwrap()
    );

    let mut expiring = TrickleTimer::new(imin, 8, k);
    expiring.start(0, 1_000);
    let _ = expiring.fire_transmit();
    expiring.expire(expiring.interval_end(), 0);
    assert_eq!(
        expiring.interval,
        u32_field(
            case(&document, "trickle_expire_double"),
            "interval_after_expire"
        )
    );

    let consistency = case(&document, "trickle_consistency_detection");
    let scope = TrickleScope {
        dodag_id: hex_16(consistency["scope_dodag_id_hex"].as_str().unwrap()),
        version: u8::try_from(consistency["scope_version"].as_u64().unwrap()).unwrap(),
    };
    for vector in consistency["cases"]
        .as_array()
        .expect("cases must be an array")
    {
        let mut scoped = TrickleTimer::new_scoped(
            u32_field(consistency, "Imin_ms"),
            8,
            u32_field(consistency, "k"),
            scope,
        );
        if vector["active"].as_bool().unwrap() {
            scoped.start(0, 0);
        }
        if vector["after_transmit"].as_bool().unwrap() {
            let _ = scoped.fire_transmit();
        }
        scoped.counter = u32_field(vector, "counter_before");
        let interval_state = (scoped.interval, scoped.interval_start, scoped.transmit_time);
        let observed = TrickleScope {
            dodag_id: hex_16(vector["observed_dodag_id_hex"].as_str().unwrap()),
            version: u8::try_from(vector["observed_version"].as_u64().unwrap()).unwrap(),
        };
        assert_eq!(
            scoped.heard_consistent_for(observed),
            vector["expected_accepted"].as_bool().unwrap()
        );
        assert_eq!(scoped.counter, u32_field(vector, "expected_counter_after"));
        assert_eq!(
            scoped.should_transmit(),
            vector["expected_should_transmit"].as_bool().unwrap()
        );
        assert_eq!(
            (scoped.interval, scoped.interval_start, scoped.transmit_time),
            interval_state
        );
    }

    let reset = case(&document, "trickle_inconsistency_resets");
    let mut reset_timer = TrickleTimer::new(u32_field(reset, "Imin_ms"), 8, u32_field(reset, "k"));
    reset_timer.start(0, u32_field(reset, "initial_rand_offset_ms"));
    for step in reset["steps"].as_array().expect("steps must be an array") {
        reset_timer.heard_consistent();
        if step["fire_before_reset"]
            .as_bool()
            .expect("fire_before_reset must be boolean")
        {
            let _ = reset_timer.fire_transmit();
        }
        reset_timer.reset(
            step["now_ms"].as_u64().expect("now_ms must be u64"),
            u32_field(step, "rand_offset_ms"),
        );
        assert_eq!(
            reset_timer.interval,
            u32_field(step, "expected_interval_ms")
        );
        assert_eq!(reset_timer.counter, u32_field(step, "expected_counter"));
        assert_eq!(
            reset_timer.transmit_time,
            step["expected_transmit_time_ms"].as_u64().unwrap()
        );
        assert_eq!(
            reset_timer.interval_end(),
            step["expected_interval_end_ms"].as_u64().unwrap()
        );
    }
}
