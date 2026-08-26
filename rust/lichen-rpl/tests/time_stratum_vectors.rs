use lichen_rpl::time_stratum::TimeStratum;
use serde_json::Value;

#[test]
fn time_strata_match_canonical_packets_timing_vectors() {
    let vectors: Value =
        serde_json::from_str(include_str!("../../../test/vectors/packets-timing.json"))
            .expect("packets-timing vectors must be valid JSON");
    let case = vectors["vectors"]
        .as_array()
        .expect("vectors must be an array")
        .iter()
        .find(|case| case["category"] == "time_stratum")
        .expect("time_stratum vector must exist");
    let strata = case["strata"].as_array().expect("strata must be an array");

    assert_eq!(strata.len(), 5);
    for entry in strata {
        let wire = u8::try_from(entry["value"].as_u64().expect("value must be u64"))
            .expect("stratum vector value must fit u8");
        let expected_name = entry["name"].as_str().expect("name must be a string");
        let stratum = TimeStratum::try_from(wire).expect("canonical stratum must decode");
        let actual_name = match stratum {
            TimeStratum::NoSync => "NO_SYNC",
            TimeStratum::ConservativeSync => "CONSERVATIVE_SYNC",
            TimeStratum::Roughtime => "ROUGHTIME",
            TimeStratum::Nts => "NTS",
            TimeStratum::GnssGpsd => "GNSS_GPSD",
        };
        assert_eq!(actual_name, expected_name);
        assert_eq!(stratum.wire_value(), wire);
    }
}
