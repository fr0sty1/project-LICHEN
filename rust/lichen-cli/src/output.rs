//! Output formatting (human-readable vs JSON).

use crate::OutputFormat;
use serde::Serialize;

#[allow(dead_code)]
pub fn print<T: Serialize + std::fmt::Display>(value: &T, fmt: &OutputFormat) {
    match fmt {
        OutputFormat::Human => println!("{value}"),
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(value).unwrap_or_else(|e| e.to_string()))
        }
    }
}

pub fn print_kv(key: &str, value: &str, fmt: &OutputFormat) {
    match fmt {
        OutputFormat::Human => println!("{key}: {value}"),
        OutputFormat::Json => println!("{{\"key\": {key:?}, \"value\": {value:?}}}"),
    }
}

#[allow(dead_code)]
pub fn print_error(msg: &str) {
    eprintln!("error: {msg}");
}
