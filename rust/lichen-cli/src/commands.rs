//! CLI command implementations.
//!
//! Each function sends a real CoAP request to the node, decodes the CBOR
//! response, and prints it using the selected output format.

use crate::{output, ConfigAction, KeyAction, OutputFormat, PositionAction};
use lichen_client::keys::{KeyEntry, KeyList, KeyPin};
use lichen_client::msg::{Inbox, OutgoingMessage, SentMessage};
use lichen_client::paths;
use lichen_client::pos::Position;
use lichen_client::status::Neighbors;
use lichen_coap::client;
use sha2::{Digest, Sha256};
use std::net::{Ipv6Addr, SocketAddr};
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

/// Derive a peer's key-store interface identifier from its IPv6 address.
///
/// The IID is the address's lower 64 bits, formatted as the firmware's
/// `xxxx:xxxx:xxxx:xxxx` key path segment (see `coap_keys.c`).
fn iid_from_ipv6(peer: &str) -> Result<String, Box<dyn std::error::Error>> {
    let addr: Ipv6Addr = peer
        .parse()
        .map_err(|_| format!("invalid IPv6 address: {peer}"))?;
    let s = addr.segments();
    Ok(format!(
        "{:04x}:{:04x}:{:04x}:{:04x}",
        s[4], s[5], s[6], s[7]
    ))
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
    let resp = client::get(node, paths::STATUS_NEIGHBORS).await?;
    if !resp.is_success() {
        return Err(format!("neighbors failed: {}", resp.code_str()).into());
    }
    let ns = Neighbors::from_cbor(&resp.payload)?;
    match fmt {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&ns)?),
        OutputFormat::Human => {
            if ns.neighbors.is_empty() {
                println!("(no neighbors)");
            } else {
                for n in &ns.neighbors {
                    println!(
                        "  {} rssi={:3} snr={:.1} etx={:.1} seen={}s trust={}",
                        n.addr,
                        n.rssi_dbm,
                        n.snr_db(),
                        n.etx(),
                        n.last_seen_s,
                        n.trust
                    );
                }
            }
        }
    }
    Ok(())
}

pub async fn send(node: SocketAddr, to: &str, message: &str, fmt: &OutputFormat) -> CmdResult {
    let msg = OutgoingMessage::new(to, message);
    let resp = client::post(node, paths::MSG_SENT, &msg.to_cbor()).await?;
    if !resp.is_success() {
        return Err(format!("send failed: {}", resp.code_str()).into());
    }
    // The firmware answers with {id, to, body, timestamp, status}; a bodyless
    // 2.01 Created is also valid, so fall back to echoing the request.
    match SentMessage::from_cbor(&resp.payload) {
        Ok(sent) => match fmt {
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&sent)?),
            OutputFormat::Human => {
                println!("  sent [{}] to {}: {}", sent.id, sent.to, sent.body);
                println!("  status: {}", sent.status);
            }
        },
        Err(_) => {
            output::print_kv("sent", message, fmt);
            output::print_kv("to", to, fmt);
        }
    }
    Ok(())
}

pub async fn inbox(node: SocketAddr, fmt: &OutputFormat) -> CmdResult {
    let resp = client::get(node, paths::MSG_INBOX).await?;
    let inbox = Inbox::from_cbor(&resp.payload)?;
    match fmt {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&inbox)?),
        OutputFormat::Human => {
            if inbox.messages.is_empty() {
                println!("(inbox empty)");
            } else {
                for m in &inbox.messages {
                    println!(
                        "  [{}] from {} (t={}): {}",
                        m.id, m.from, m.received, m.body
                    );
                }
            }
        }
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
            let seed_hex: Zeroizing<String> =
                Zeroizing::new(seed.iter().map(|b| format!("{b:02x}")).collect());

            // Derive IID from hashed seed (avoids leaking raw key material)
            // SECURITY: raw seed bytes must never appear in the IID
            let seed_hash = Sha256::digest(seed);
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
                    writeln!(file, "{}", *seed_hex)?;
                }
                #[cfg(windows)]
                {
                    use std::fs::OpenOptions;
                    use std::io::Write;
                    use std::os::windows::fs::OpenOptionsExt;

                    // Restrict access: owner-only read/write, no sharing
                    // Windows DACL manipulation requires FFI beyond OpenOptionsExt
                    // but share_mode(0) prevents concurrent readers
                    let mut file = OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .share_mode(0)
                        .open(&path)?;
                    writeln!(file, "{}", *seed_hex)?;
                }
                #[cfg(not(any(unix, windows)))]
                {
                    use std::fs::File;
                    use std::io::Write;

                    let mut file = File::create(&path)?;
                    writeln!(file, "{}", *seed_hex)?;
                    eprintln!(
                        "warning: could not set secure file permissions on non-Unix platform"
                    );
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
            let resp = client::get(node, paths::KEYS).await?;
            if !resp.is_success() {
                return Err(format!("key list failed: {}", resp.code_str()).into());
            }
            let list = KeyList::from_cbor(&resp.payload)?;
            match fmt {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&list)?),
                OutputFormat::Human => {
                    if list.keys.is_empty() {
                        println!("(no peer keys)");
                    } else {
                        for k in &list.keys {
                            println!(
                                "  {} [{}] {} (last seen {})",
                                k.iid, k.trust, k.pubkey_fp, k.last_seen
                            );
                        }
                    }
                }
            }
        }
        KeyAction::Pin { peer } => {
            let iid = iid_from_ipv6(&peer)?;
            let path = paths::keys_iid(&iid);
            // Read the key the node already pinned (TOFU) for this peer.
            let resp = client::get(node, &path).await?;
            if !resp.is_success() {
                return Err(format!(
                    "no key on record for {peer} (iid {iid}): {} — the node must \
                     have seen this peer before its key can be confirmed",
                    resp.code_str()
                )
                .into());
            }
            let entry = KeyEntry::from_cbor(&resp.payload)?;
            // SECURITY: re-send the SAME pubkey with trust=verified. The node
            // TOFU-rejects any pubkey change, so this only elevates trust on the
            // already-seen key; it cannot inject a new key for this IID.
            let pin = KeyPin {
                pubkey: entry.pubkey.clone(),
                trust: "verified".to_string(),
            };
            let put = client::put(node, &path, &pin.to_cbor()).await?;
            if !put.is_success() {
                return Err(format!("pin failed: {}", put.code_str()).into());
            }
            output::print_kv(
                "pinned",
                &format!("{peer} (iid {iid}): {} -> verified", entry.trust),
                fmt,
            );
        }
        KeyAction::Unpin { peer } => {
            let iid = iid_from_ipv6(&peer)?;
            let resp = client::delete(node, &paths::keys_iid(&iid)).await?;
            if !resp.is_success() {
                return Err(format!("unpin failed: {}", resp.code_str()).into());
            }
            output::print_kv("unpinned", &format!("{peer} (iid {iid})"), fmt);
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
            // Spec §18.2.2: GET /sensors/location -> application/senml+cbor.
            let resp = client::get(node, paths::SENSORS_LOCATION).await?;
            if !resp.is_success() {
                return Err(format!("position query failed: {}", resp.code_str()).into());
            }
            let p = Position::from_senml_cbor(&resp.payload)?;
            match fmt {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&p)?),
                OutputFormat::Human => {
                    if let Some(device) = p.device {
                        println!("  device: {device}");
                    }
                    println!("  lat: {}  lon: {}", p.lat, p.lon);
                    if let Some(alt) = p.alt {
                        println!("  alt: {alt} m");
                    }
                    if let Some(speed) = p.speed {
                        println!("  speed: {speed} m/s");
                    }
                    if let Some(heading) = p.heading {
                        println!("  heading: {heading} deg");
                    }
                    if let Some(time) = p.time {
                        println!("  time: {time}");
                    }
                }
            }
        }
        PositionAction::Broadcast => {
            return Err("position broadcast not implemented".into());
        }
    }
    Ok(())
}
