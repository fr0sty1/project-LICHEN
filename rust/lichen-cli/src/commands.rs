//! CLI command implementations.
//!
//! Each function sends a real CoAP request to the node, decodes the CBOR
//! response, and prints it using the selected output format.

use crate::{output, ConfigAction, KeyAction, OutputFormat, PositionAction, RdAction};
use lichen_coap::client;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use zeroize::{Zeroize, Zeroizing};

type CmdResult = Result<(), Box<dyn std::error::Error>>;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn decode_cbor(
    resp: &client::Response,
) -> Result<ciborium::value::Value, Box<dyn std::error::Error>> {
    if !resp.is_success() {
        return Err(format!("CoAP error {}", resp.code_str()).into());
    }
    if resp.payload.is_empty() {
        return Ok(ciborium::value::Value::Map(vec![]));
    }
    let v: ciborium::value::Value = ciborium::de::from_reader(resp.payload.as_slice())?;
    Ok(v)
}

fn encode_cbor(v: &serde_json::Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cbor_val = json_to_cbor(v);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&cbor_val, &mut buf)?;
    Ok(buf)
}

fn json_to_cbor(v: &serde_json::Value) -> ciborium::value::Value {
    use ciborium::value::Value;
    match v {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Integer(i.into())
            } else {
                Value::Float(n.as_f64().unwrap_or(0.0))
            }
        }
        serde_json::Value::String(s) => Value::Text(s.clone()),
        serde_json::Value::Array(arr) => Value::Array(arr.iter().map(json_to_cbor).collect()),
        serde_json::Value::Object(map) => Value::Map(
            map.iter()
                .map(|(k, v)| (Value::Text(k.clone()), json_to_cbor(v)))
                .collect(),
        ),
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

pub async fn status(node: SocketAddr, fmt: &OutputFormat) -> CmdResult {
    println!("LICHEN node {node}");
    let resp = client::get(node, "/status").await?;
    let cbor = decode_cbor(&resp)?;
    output::print_cbor(cbor, fmt);
    Ok(())
}

pub async fn neighbors(node: SocketAddr, fmt: &OutputFormat) -> CmdResult {
    let resp = client::get(node, "/neighbors").await?;
    let cbor = decode_cbor(&resp)?;
    match &cbor {
        ciborium::value::Value::Array(arr) if arr.is_empty() => {
            println!("(no neighbors)");
        }
        _ => output::print_cbor(cbor, fmt),
    }
    Ok(())
}

pub async fn presence(node: SocketAddr, fmt: &OutputFormat) -> CmdResult {
    let resp = client::get(node, "/presence").await?;
    let cbor = decode_cbor(&resp)?;
    match &cbor {
        ciborium::value::Value::Array(arr) if arr.is_empty() => {
            println!("(no peers in presence table)");
        }
        _ => output::print_cbor(cbor, fmt),
    }
    Ok(())
}

pub async fn send(node: SocketAddr, to: &str, message: &str, fmt: &OutputFormat) -> CmdResult {
    let body_json = serde_json::json!({ "to": to, "text": message });
    let body = encode_cbor(&body_json)?;
    let resp = client::post(node, "/messages", &body).await?;
    if resp.is_success() {
        output::print_kv("sent", message, fmt);
        output::print_kv("to", to, fmt);
    } else {
        return Err(format!("send failed: {}", resp.code_str()).into());
    }
    Ok(())
}

pub async fn inbox(node: SocketAddr, fmt: &OutputFormat) -> CmdResult {
    let resp = client::get(node, "/messages").await?;
    let cbor = decode_cbor(&resp)?;
    match &cbor {
        ciborium::value::Value::Array(arr) if arr.is_empty() => {
            println!("(inbox empty)");
        }
        _ => output::print_cbor(cbor, fmt),
    }
    Ok(())
}

pub async fn sos_status(node: SocketAddr, fmt: &OutputFormat) -> CmdResult {
    let resp = client::get(node, "/sos").await?;
    let cbor = decode_cbor(&resp)?;
    output::print_cbor(cbor, fmt);
    Ok(())
}

pub async fn sos_activate(node: SocketAddr, fmt: &OutputFormat) -> CmdResult {
    let resp = client::put(node, "/sos", &[]).await?;
    if resp.is_success() {
        output::print_kv("sos", "ACTIVE — emergency beacon transmitted", fmt);
    } else {
        return Err(format!("SOS activation failed: {}", resp.code_str()).into());
    }
    Ok(())
}

pub async fn sos_cancel(node: SocketAddr, fmt: &OutputFormat) -> CmdResult {
    let resp = client::delete(node, "/sos").await?;
    if resp.is_success() {
        output::print_kv("sos", "cancelled", fmt);
    } else {
        return Err(format!("SOS cancel failed: {}", resp.code_str()).into());
    }
    Ok(())
}

pub async fn key(node: SocketAddr, action: KeyAction, fmt: &OutputFormat) -> CmdResult {
    match action {
        KeyAction::Generate { output: out_path } => {
            // Generate 32 random bytes for Ed25519 seed
            let mut seed = [0u8; 32];
            fill_random(&mut seed)?;

            // Derive public key (Ed25519: first 32 bytes of SHA512(seed) as scalar, then multiply)
            // ponytail: using simple derivation without pulling in ed25519 crate
            // Real impl would use ed25519-dalek; this outputs raw seed for now
            let seed_hex: Zeroizing<String> = Zeroizing::new(seed.iter().map(|b| format!("{b:02x}")).collect());

            // Derive IID from hashed seed (avoids leaking raw key material)
            // SECURITY: raw seed bytes must never appear in the IID
            let seed_hash = Sha256::digest(&seed);
            let iid_hex: String = seed_hash[..8].iter().map(|b| format!("{b:02x}")).collect();

            // Zeroize seed bytes now that we have the hex representation
            seed.zeroize();

            if let Some(path) = out_path {
                // Write key to file with secure permissions (Unix 0600)
                #[cfg(unix)]
                {
                    use std::fs::OpenOptions;
                    use std::io::Write;
                    use std::os::unix::fs::OpenOptionsExt;

                    let mut file = OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .mode(0o600)
                        .open(&path)?;
                    writeln!(file, "{}", &*seed_hex)?;
                }
                #[cfg(not(unix))]
                {
                    use std::fs::File;
                    use std::io::Write;

                    // SECURITY: Use writeln! instead of format! to avoid creating
                    // a temporary String that would leak seed material in memory
                    let mut file = File::create(&path)?;
                    writeln!(file, "{}", &*seed_hex)?;
                    eprintln!("warning: could not set secure file permissions on non-Unix platform");
                }
                output::print_kv("private_key", path.display().to_string().as_str(), fmt);
            } else {
                eprintln!("warning: private key will be printed to stdout");
                eprintln!("         ensure terminal history and logs do not capture this output");
                output::print_kv("private_key", &seed_hex, fmt);
            }
            output::print_kv("iid", &iid_hex, fmt);
            // seed_hex auto-zeroized on drop via Zeroizing wrapper
        }
        KeyAction::Fingerprint => {
            let resp = client::get(node, "/key").await?;
            let cbor = decode_cbor(&resp)?;
            if let ciborium::value::Value::Map(ref pairs) = cbor {
                for (k, v) in pairs {
                    if matches!(k, ciborium::value::Value::Text(s) if s == "fingerprint") {
                        output::print_cbor(v.clone(), fmt);
                        return Ok(());
                    }
                }
                return Err("node did not return a fingerprint".into());
            }
            output::print_cbor(cbor, fmt);
        }
        KeyAction::List => {
            output::print_kv("peers", "(no peer-key endpoint yet)", fmt);
        }
        KeyAction::Pin { peer: _ } => {
            return Err("key pinning not implemented (no peer-key endpoint yet)".into());
        }
        KeyAction::Unpin { peer: _ } => {
            return Err("key unpinning not implemented (no peer-key endpoint yet)".into());
        }
    }
    Ok(())
}

fn fill_random(buf: &mut [u8]) -> Result<(), Box<dyn std::error::Error>> {
    getrandom::getrandom(buf).map_err(|e| format!("getrandom failed: {e}"))?;
    Ok(())
}

pub async fn config(node: SocketAddr, action: ConfigAction, fmt: &OutputFormat) -> CmdResult {
    match action {
        ConfigAction::Get { key } => {
            let resp = client::get(node, "/config").await?;
            let cbor = decode_cbor(&resp)?;
            if let ciborium::value::Value::Map(ref pairs) = cbor {
                for (k, v) in pairs {
                    if let ciborium::value::Value::Text(ref s) = k {
                        if s == &key {
                            output::print_cbor(v.clone(), fmt);
                            return Ok(());
                        }
                    }
                }
                return Err(format!("key '{key}' not found in config").into());
            }
            output::print_cbor(cbor, fmt);
        }
        ConfigAction::Set { key, value } => {
            let body_json = serde_json::json!({ key.clone(): value });
            let body = encode_cbor(&body_json)?;
            let resp = client::put(node, "/config", &body).await?;
            if resp.is_success() {
                output::print_kv(&key, &value, fmt);
            } else {
                return Err(format!("config set failed: {}", resp.code_str()).into());
            }
        }
    }
    Ok(())
}

pub async fn position(node: SocketAddr, action: PositionAction, fmt: &OutputFormat) -> CmdResult {
    match action {
        PositionAction::Show => {
            let resp = client::get(node, "/location").await?;
            let cbor = decode_cbor(&resp)?;
            output::print_cbor(cbor, fmt);
        }
        PositionAction::Broadcast => {
            return Err("position broadcast not implemented".into());
        }
        PositionAction::Peers => {
            let resp = client::get(node, "/presence").await?;
            let cbor = decode_cbor(&resp)?;
            output::print_cbor(cbor, fmt);
        }
    }
    Ok(())
}

pub async fn rd(node: SocketAddr, action: RdAction, fmt: &OutputFormat) -> CmdResult {
    match action {
        RdAction::List { ep } => {
            let path = match &ep {
                Some(name) => {
                    let encoded = utf8_percent_encode(name, NON_ALPHANUMERIC);
                    format!("/rd?ep={encoded}")
                }
                None => "/rd".to_owned(),
            };
            let resp = client::get(node, &path).await?;
            let cbor = decode_cbor(&resp)?;
            match &cbor {
                ciborium::value::Value::Array(arr) if arr.is_empty() => {
                    println!("(no registrations)");
                }
                _ => output::print_cbor(cbor, fmt),
            }
        }
        RdAction::Register { ep, lt } => {
            let ep_name = ep.unwrap_or_else(|| node.to_string());
            let encoded = utf8_percent_encode(&ep_name, NON_ALPHANUMERIC);
            let path = format!("/rd?ep={encoded}&lt={lt}");
            let resp = client::post(node, &path, &[]).await?;
            if resp.is_success() {
                output::print_kv("registered", &ep_name, fmt);
                output::print_kv("lt", &lt.to_string(), fmt);
            } else {
                return Err(format!("registration failed: {}", resp.code_str()).into());
            }
        }
        RdAction::Delete { id } => {
            let encoded_id = utf8_percent_encode(&id, NON_ALPHANUMERIC);
            let path = format!("/rd/{encoded_id}");
            let resp = client::delete(node, &path).await?;
            if resp.is_success() {
                output::print_kv("deleted", &id, fmt);
            } else {
                return Err(format!("delete failed: {}", resp.code_str()).into());
            }
        }
    }
    Ok(())
}
