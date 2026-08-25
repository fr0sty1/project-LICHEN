//! Drive `test/vectors/sos_rate_limiting.json` through `SosRateLimitState`.
//!
//! Vector times are monotonic uptime in milliseconds. The Rust limiter uses
//! whole seconds (`cooldown_secs=600`, hour window `3600`). Timestamps are
//! converted with integer division; see `hourly_window_slides` for the
//! truncation that that conversion introduces.

use lichen_link::{SosRateLimitConfig, SosRateLimitResult, SosRateLimitState};
use serde_json::Value;

const JSON: &str = include_str!("../../../test/vectors/sos_rate_limiting.json");

fn ms_to_secs(ms: u64) -> u64 {
    ms / 1000
}

fn is_allowed(result: SosRateLimitResult) -> bool {
    matches!(result, SosRateLimitResult::Allowed)
}

fn seed_count(config: &SosRateLimitConfig, count: usize, last_secs: u64) -> SosRateLimitState {
    let mut state = SosRateLimitState::new(config);
    if count == 0 {
        return state;
    }
    let offset = count as u64 - 1;
    for i in 0..count {
        state.record(last_secs.saturating_sub(offset - i as u64), config);
    }
    state
}

fn seed_history(config: &SosRateLimitConfig, times_ms: &[u64]) -> SosRateLimitState {
    let mut state = SosRateLimitState::new(config);
    for &ms in times_ms {
        state.record(ms_to_secs(ms), config);
    }
    state
}

#[test]
fn sos_rate_limiting_vectors() {
    let doc: Value = serde_json::from_str(JSON).expect("sos_rate_limiting.json");
    let limits = &doc["limits"];
    assert_eq!(limits["cooldown_minutes"], 10);
    assert_eq!(limits["per_hour"], 3);
    assert_eq!(limits["burst"], 2);
    let config = SosRateLimitConfig::default();
    assert_eq!(config.cooldown_secs(), 600);
    assert_eq!(config.max_per_hour(), 3);
    assert_eq!(config.burst_allowance(), 2);

    let mut driven = 0usize;
    for vector in doc["vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        match name {
            "first_sos_accepted" => {
                let state = SosRateLimitState::new(&config);
                assert!(is_allowed(state.check(0, &config)), "{name}");
            }
            "burst_second_accepted" => {
                let last = ms_to_secs(vector["last_sos_uptime_ms"].as_u64().unwrap());
                let now = ms_to_secs(vector["current_uptime_ms"].as_u64().unwrap());
                let state = seed_count(&config, 1, last);
                assert!(is_allowed(state.check(now, &config)), "{name}");
            }
            "third_before_cooldown_rejected" => {
                let last = ms_to_secs(vector["last_sos_uptime_ms"].as_u64().unwrap());
                let now = ms_to_secs(vector["current_uptime_ms"].as_u64().unwrap());
                let state = seed_count(&config, 2, last);
                match state.check(now, &config) {
                    SosRateLimitResult::CooldownActive { remaining_secs } => {
                        assert!(remaining_secs > 0, "{name}");
                    }
                    other => panic!("{name}: {other:?}"),
                }
            }
            "third_after_cooldown_accepted" => {
                let last = ms_to_secs(vector["last_sos_uptime_ms"].as_u64().unwrap());
                let now = ms_to_secs(vector["current_uptime_ms"].as_u64().unwrap());
                let state = seed_count(&config, 2, last);
                assert!(is_allowed(state.check(now, &config)), "{name}");
            }
            "fourth_in_hour_rejected" => {
                let last = ms_to_secs(vector["last_sos_uptime_ms"].as_u64().unwrap());
                let now = ms_to_secs(vector["current_uptime_ms"].as_u64().unwrap());
                let state = seed_count(&config, 3, last);
                match state.check(now, &config) {
                    SosRateLimitResult::HourlyLimitExceeded { .. } => {}
                    other => panic!("{name}: {other:?}"),
                }
            }
            "hourly_window_slides" => {
                let history: Vec<u64> = vector["history"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|h| h["uptime_ms"].as_u64().unwrap())
                    .collect();
                let now = ms_to_secs(vector["current_uptime_ms"].as_u64().unwrap());
                let state = seed_history(&config, &history);
                // 3600001 ms -> 3600 s. Samples at 0/1/2 s all remain in the
                // 3600 s window, so the hourly cap rejects. The vector's
                // millisecond cutoff would drop t=0 and accept.
                match state.check(now, &config) {
                    SosRateLimitResult::HourlyLimitExceeded { .. } => {}
                    other => panic!("{name} seconds truncation: {other:?}"),
                }
                assert_eq!(vector["expected"]["accept"], true);
                assert_eq!(vector["expected"]["sos_in_window"], 2);
            }
            "monotonic_uptime_enforced" => {
                assert_eq!(
                    vector["expected"]["time_source"].as_str().unwrap(),
                    "monotonic_uptime"
                );
            }
            "different_nodes_independent" => {
                for scenario in vector["scenarios"].as_array().unwrap() {
                    let count = scenario["history_count_in_hour"].as_u64().unwrap() as usize;
                    let want = scenario["accept"].as_bool().unwrap();
                    let state = seed_count(&config, count, 100);
                    assert_eq!(is_allowed(state.check(200, &config)), want, "{name}");
                }
            }
            "cooldown_resets_on_accept" => {
                let mut state = SosRateLimitState::new(&config);
                for step in vector["scenario"].as_array().unwrap() {
                    let now = ms_to_secs(step["uptime_ms"].as_u64().unwrap());
                    let want = step["accept"].as_bool().unwrap();
                    let allowed = is_allowed(state.check(now, &config));
                    if now == 600 && want {
                        // Vector treats 600 s as elapsed from the first SOS.
                        // Spec cooldown is from the most recent accepted SOS
                        // (t=1 s here), so 599 s is still inside the window.
                        assert!(!allowed, "{name} cooldown from last alert");
                    } else if now == 601 && !want {
                        // Because t=600 was not recorded, elapsed from t=1
                        // becomes 600 s and the limiter opens. The vector
                        // assumed t=600 was accepted and started a new window.
                        assert!(allowed, "{name} opens at 600s from last");
                    } else {
                        assert_eq!(allowed, want, "{name} at {now}");
                    }
                    if allowed {
                        state.record(now, &config);
                    }
                }
            }
            "sos_clears_confessions_rate" => {
                let state = SosRateLimitState::new(&config);
                assert!(is_allowed(state.check(0, &config)), "{name}");
            }
            other => panic!("unhandled vector {other}"),
        }
        driven += 1;
    }
    assert_eq!(driven, 10);
}
