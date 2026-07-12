//! Output formatting (human-readable vs JSON).

use crate::OutputFormat;

pub fn print_kv(key: &str, value: &str, fmt: &OutputFormat) {
    match fmt {
        OutputFormat::Human => println!("  {key}: {value}"),
        OutputFormat::Json => println!("{}", serde_json::json!({"key": key, "value": value})),
    }
}

/// Display a ciborium CBOR value using the chosen format.
pub fn print_cbor(value: ciborium::value::Value, fmt: &OutputFormat) {
    let json = cbor_to_json(value);
    match fmt {
        OutputFormat::Human => print_json_human(&json, 0),
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&json).unwrap_or_else(|e| e.to_string())
        ),
    }
}

/// Recursively pretty-print a JSON value in a compact human style.
fn print_json_human(v: &serde_json::Value, indent: usize) {
    let pad = "  ".repeat(indent);
    match v {
        serde_json::Value::Object(map) => {
            for (k, val) in map {
                match val {
                    serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
                        println!("{pad}  {k}:");
                        print_json_human(val, indent + 2);
                    }
                    _ => println!("{pad}  {k}: {}", json_leaf(val)),
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, item) in arr.iter().enumerate() {
                println!("{pad}  [{i}]:");
                print_json_human(item, indent + 2);
            }
        }
        other => println!("{pad}  {}", json_leaf(other)),
    }
}

fn json_leaf(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Convert `ciborium::value::Value` → `serde_json::Value` for display.
pub fn cbor_to_json(v: ciborium::value::Value) -> serde_json::Value {
    use ciborium::value::Value;
    match v {
        Value::Bool(b) => serde_json::Value::Bool(b),
        Value::Integer(i) => {
            let n: i128 = i.into();
            // Preserve precision: use i64/u64 when possible, string for out-of-range
            if let Ok(small) = i64::try_from(n) {
                serde_json::Value::Number(serde_json::Number::from(small))
            } else if let Ok(big) = u64::try_from(n) {
                serde_json::Value::Number(serde_json::Number::from(big))
            } else {
                serde_json::Value::String(n.to_string())
            }
        }
        Value::Float(f) => serde_json::json!(f),
        Value::Bytes(b) => serde_json::Value::String(hex_encode(&b)),
        Value::Text(s) => serde_json::Value::String(s),
        Value::Array(arr) => serde_json::Value::Array(arr.into_iter().map(cbor_to_json).collect()),
        Value::Map(map) => {
            let obj: serde_json::Map<String, serde_json::Value> = map
                .into_iter()
                .map(|(k, v)| {
                    let key = match k {
                        Value::Text(s) => s,
                        Value::Integer(i) => {
                            let n: i128 = i.into();
                            n.to_string()
                        }
                        other => cbor_to_json(other).to_string(),
                    };
                    (key, cbor_to_json(v))
                })
                .collect();
            serde_json::Value::Object(obj)
        }
        Value::Tag(_, inner) => cbor_to_json(*inner),
        Value::Null => serde_json::Value::Null,
        _ => serde_json::Value::Null,
    }
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|byte| format!("{byte:02x}")).collect()
}
