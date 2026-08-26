// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! CoRE Link Format discovery parsing for `/.well-known/core` responses.
//!
//! The client-facing capability model intentionally exposes the attributes
//! LICHEN applications currently consume: link targets, resource types (`rt`),
//! and the CoAP Observe (`obs`) flag. Other RFC 6690 attributes are accepted
//! and ignored so nodes can extend their advertisements independently.

use std::collections::{BTreeMap, BTreeSet};

/// Resources and capabilities advertised by a CoRE Link Format document.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Capabilities {
    /// Advertised link targets.
    pub resources: BTreeSet<String>,
    /// Link targets carrying the `obs` attribute.
    pub observable: BTreeSet<String>,
    /// Space-separated `rt` values, indexed by link target.
    pub resource_types: BTreeMap<String, Vec<String>>,
}

impl Capabilities {
    /// Return whether `path` was advertised.
    pub fn has(&self, path: &str) -> bool {
        self.resources.contains(path)
    }

    /// Return whether `path` advertises CoAP Observe support.
    pub fn can_observe(&self, path: &str) -> bool {
        self.observable.contains(path)
    }
}

/// A malformed CoRE Link Format document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkFormatError {
    /// Byte offset of the opening quote that was not closed.
    pub unclosed_quote_at: usize,
}

impl core::fmt::Display for LinkFormatError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "malformed link-format: unclosed quote at byte {}",
            self.unclosed_quote_at
        )
    }
}

impl std::error::Error for LinkFormatError {}

/// Parse a CoRE Link Format body into LICHEN client capabilities.
///
/// Entries without an angle-bracketed link target are ignored. This mirrors
/// the existing Python client and lets discovery continue past extensions or
/// malformed entries that do not affect valid links. Unterminated quoted
/// strings are rejected because commas and semicolons within such a string
/// cannot be classified safely as separators.
pub fn parse_link_format(body: &str) -> Result<Capabilities, LinkFormatError> {
    let mut capabilities = Capabilities::default();

    for entry in split_quoted(body, ',')? {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }

        let parameters = split_quoted(entry, ';')?;
        let Some(target) = parameters.first().map(|value| value.trim()) else {
            continue;
        };
        if !(target.starts_with('<') && target.ends_with('>')) {
            continue;
        }

        let path = &target[1..target.len() - 1];
        capabilities.resources.insert(path.to_owned());

        let mut resource_types = Vec::new();
        for parameter in &parameters[1..] {
            let parameter = parameter.trim();
            if parameter == "obs" {
                capabilities.observable.insert(path.to_owned());
            } else if let Some(value) = parameter.strip_prefix("rt=") {
                resource_types.extend(quoted_tokens(value).map(str::to_owned));
            }
        }
        if !resource_types.is_empty() {
            capabilities
                .resource_types
                .insert(path.to_owned(), resource_types);
        }
    }

    Ok(capabilities)
}

fn split_quoted(value: &str, separator: char) -> Result<Vec<&str>, LinkFormatError> {
    let mut parts = Vec::new();
    let mut part_start = 0;
    let mut opening_quote = None;
    let mut escaped = false;

    for (offset, character) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' && opening_quote.is_some() {
            escaped = true;
            continue;
        }
        if character == '"' {
            if opening_quote.is_some() {
                opening_quote = None;
            } else {
                opening_quote = Some(offset);
            }
        } else if character == separator && opening_quote.is_none() {
            parts.push(&value[part_start..offset]);
            part_start = offset + character.len_utf8();
        }
    }

    if let Some(unclosed_quote_at) = opening_quote {
        return Err(LinkFormatError { unclosed_quote_at });
    }
    parts.push(&value[part_start..]);
    Ok(parts)
}

fn quoted_tokens(value: &str) -> impl Iterator<Item = &str> {
    let value = value.trim();
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value);
    value.split_whitespace()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn strings(value: &Value) -> Vec<String> {
        value
            .as_array()
            .expect("expected array")
            .iter()
            .map(|item| item.as_str().expect("expected string").to_owned())
            .collect()
    }

    fn assert_capabilities(actual: &Capabilities, expected: &Value) {
        assert_eq!(
            actual.resources.iter().cloned().collect::<Vec<_>>(),
            strings(&expected["resources"])
        );
        assert_eq!(
            actual.observable.iter().cloned().collect::<Vec<_>>(),
            strings(&expected["observable"])
        );

        let expected_types = expected["resource_types"]
            .as_object()
            .expect("resource_types must be an object");
        assert_eq!(actual.resource_types.len(), expected_types.len());
        for (path, types) in expected_types {
            assert_eq!(actual.resource_types.get(path), Some(&strings(types)));
        }
    }

    #[test]
    fn consumes_shared_parse_and_error_vectors() {
        let document: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test/vectors/core_link_format.json"
        )))
        .expect("parse core_link_format.json");

        for vector in document["vectors"]
            .as_array()
            .expect("vectors must be an array")
        {
            let kind = vector["kind"].as_str().expect("kind must be a string");
            if kind != "parse" && kind != "error" {
                continue;
            }
            let name = vector["name"].as_str().expect("name must be a string");
            let result = parse_link_format(vector["body"].as_str().expect("body must be a string"));
            if vector["expected"].get("raises").is_some() {
                assert!(result.is_err(), "{name}");
            } else {
                assert_capabilities(
                    &result.unwrap_or_else(|error| panic!("{name}: {error}")),
                    &vector["expected"],
                );
            }
        }
    }

    #[test]
    fn consumes_node_emitted_shared_vector() {
        let document: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test/vectors/core_link_format.json"
        )))
        .expect("parse core_link_format.json");
        let vector = document["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|vector| vector["kind"] == "node_emitted")
            .expect("node_emitted vector");
        let body = strings(&vector["links"]).join(",");
        let capabilities = parse_link_format(&body).unwrap();
        let expected = &vector["expected"];

        for path in strings(&expected["resources"]) {
            assert!(capabilities.has(&path), "missing {path}");
        }
        for path in strings(&expected["observable"]) {
            assert!(capabilities.can_observe(&path), "not observable: {path}");
        }
        for (path, types) in expected["resource_types"].as_object().unwrap() {
            let types = strings(types);
            if !types.is_empty() {
                assert_eq!(capabilities.resource_types.get(path), Some(&types));
            }
        }
    }

    #[test]
    fn separators_inside_quoted_attributes_are_not_split() {
        let capabilities = parse_link_format(
            r#"</one>;rt="sensor one";title="comma, semicolon; quote: \"",</two>;obs"#,
        )
        .unwrap();

        assert!(capabilities.has("/one"));
        assert!(capabilities.can_observe("/two"));
        assert_eq!(
            capabilities.resource_types["/one"],
            ["sensor".to_owned(), "one".to_owned()]
        );
    }

    #[test]
    fn reports_unclosed_quote_byte_offset_for_unicode_input() {
        let error = parse_link_format("</café>;title=\"broken").unwrap_err();
        assert_eq!(error.unclosed_quote_at, 15);
    }
}
