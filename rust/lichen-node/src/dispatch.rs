//! CoAP resource dispatch: URI routing to handlers.
//!
//! Provides a simple resource registry mapping URI paths to handler functions.
//!
//! # Compile-Time Dispatch Tables
//!
//! The dispatch table is built entirely at compile time using `const fn`:
//!
//! - [`Resource::new`], [`Resource::get`], [`Resource::put`], [`Resource::post`],
//!   [`Resource::delete`] are all `const fn`, enabling builder-pattern construction
//!   in const contexts.
//! - [`Dispatcher::new`] and [`default_dispatcher`] are `const fn`, so the entire
//!   routing table can be a `static` with zero runtime initialization cost.
//!
//! This is critical for embedded targets where:
//! - RAM is scarce (the table lives in flash, not RAM)
//! - Startup must be deterministic (no heap allocation, no runtime setup)
//! - Code size matters (the compiler can inline and optimize the fixed table)
//!
//! ## Example
//!
//! ```ignore
//! static DISPATCHER: Dispatcher<2> = Dispatcher::new([
//!     Resource::new(&[b"sensors"]).get(handle_sensors),
//!     Resource::new(&[b"config"]).get(handle_config).put(handle_config_put),
//! ]);
//! ```
//!
//! The `DISPATCHER` is computed at compile time and placed in `.rodata`.

#[cfg(all(feature = "defmt", not(feature = "log")))]
use defmt::warn;
#[cfg(all(feature = "log", not(feature = "defmt")))]
use log::warn;

use lichen_coap::codec::{CoapBuilder, CoapPacket};
use lichen_coap::message::{MessageCode, MessageType};
use lichen_coap::option::content_format::CBOR;

/// Maximum URI path depth.
pub const MAX_PATH_DEPTH: usize = 4;

/// Content formats.
pub mod content_format {
    pub const TEXT_PLAIN: u16 = 0;
    pub const APPLICATION_LINK_FORMAT: u16 = 40;
    pub const APPLICATION_JSON: u16 = 50;
    pub const APPLICATION_SENML_JSON: u16 = 110;
    pub const APPLICATION_SENML_CBOR: u16 = 112;
}

/// Handler result.
#[derive(Debug)]
pub struct Response {
    pub code: MessageCode,
    pub content_format: Option<u16>,
    pub payload: [u8; 256],
    pub payload_len: usize,
}

impl Response {
    pub fn content(payload: &[u8]) -> Self {
        let payload_len = payload.len().min(256);
        let mut resp = Self {
            code: MessageCode::CONTENT,
            content_format: Some(CBOR),
            payload: [0u8; 256],
            payload_len,
        };
        resp.payload[..payload_len].copy_from_slice(&payload[..payload_len]);
        resp
    }

    pub fn created() -> Self {
        Self {
            code: MessageCode::CREATED,
            content_format: None,
            payload: [0u8; 256],
            payload_len: 0,
        }
    }

    pub fn changed() -> Self {
        Self {
            code: MessageCode::CHANGED,
            content_format: None,
            payload: [0u8; 256],
            payload_len: 0,
        }
    }

    pub fn not_found() -> Self {
        Self {
            code: MessageCode::NOT_FOUND,
            content_format: None,
            payload: [0u8; 256],
            payload_len: 0,
        }
    }

    pub fn method_not_allowed() -> Self {
        Self {
            code: MessageCode::METHOD_NOT_ALLOWED,
            content_format: None,
            payload: [0u8; 256],
            payload_len: 0,
        }
    }

    pub fn bad_request() -> Self {
        Self {
            code: MessageCode::BAD_REQUEST,
            content_format: None,
            payload: [0u8; 256],
            payload_len: 0,
        }
    }
}

/// Request context passed to handlers.
#[derive(Debug)]
pub struct Request<'a> {
    pub method: MessageCode,
    pub path: [&'a [u8]; MAX_PATH_DEPTH],
    pub path_len: usize,
    pub payload: &'a [u8],
    pub content_format: Option<u16>,
}

impl<'a> Request<'a> {
    /// Parse a CoAP packet into a request.
    pub fn from_coap(pkt: &CoapPacket<'a>) -> Option<Self> {
        let method = pkt.code();
        if method.class() != 0 || method.detail() == 0 {
            return None; // Not a request
        }

        let mut path = [&[][..]; MAX_PATH_DEPTH];
        let mut path_len = 0;
        let mut content_format = None;

        for opt_result in pkt.options() {
            let opt = opt_result.ok()?;
            if opt.is_uri_path() {
                if path_len < MAX_PATH_DEPTH {
                    path[path_len] = opt.value;
                    path_len += 1;
                } else {
                    #[cfg(any(feature = "defmt", feature = "log"))]
                    warn!(
                        "dispatch: dropping URI segment beyond MAX_PATH_DEPTH ({})",
                        MAX_PATH_DEPTH
                    );
                }
            } else if opt.is_content_format() {
                content_format = Some((opt.as_uint().ok()?) as u16);
            }
        }

        Some(Self {
            method,
            path,
            path_len,
            payload: pkt.payload(),
            content_format,
        })
    }

    /// Check if path matches the given segments.
    pub fn path_matches(&self, segments: &[&[u8]]) -> bool {
        self.path_len == segments.len()
            && self.path[..self.path_len]
                .iter()
                .zip(segments)
                .all(|(a, b)| a == b)
    }

    /// Get path segment at index.
    pub fn path_segment(&self, index: usize) -> Option<&'a [u8]> {
        if index < self.path_len {
            Some(self.path[index])
        } else {
            None
        }
    }
}

/// Handler function type.
pub type Handler = fn(&Request) -> Response;

/// A CoAP resource with path and method handlers.
///
/// All builder methods are `const fn` to enable compile-time dispatch table
/// construction. See the [module documentation](self) for rationale.
#[derive(Clone, Copy, Debug)]
pub struct Resource {
    pub path: &'static [&'static [u8]],
    pub get: Option<Handler>,
    pub put: Option<Handler>,
    pub post: Option<Handler>,
    pub delete: Option<Handler>,
}

impl Resource {
    pub const fn new(path: &'static [&'static [u8]]) -> Self {
        Self {
            path,
            get: None,
            put: None,
            post: None,
            delete: None,
        }
    }

    pub const fn get(mut self, handler: Handler) -> Self {
        self.get = Some(handler);
        self
    }

    pub const fn put(mut self, handler: Handler) -> Self {
        self.put = Some(handler);
        self
    }

    pub const fn post(mut self, handler: Handler) -> Self {
        self.post = Some(handler);
        self
    }

    pub const fn delete(mut self, handler: Handler) -> Self {
        self.delete = Some(handler);
        self
    }
}

/// CoAP resource dispatcher with compile-time table construction.
///
/// The generic parameter `N` is the number of resources. Use [`Dispatcher::new`]
/// (a `const fn`) to build the table at compile time as a `static`.
pub struct Dispatcher<const N: usize> {
    resources: [Resource; N],
}

impl<const N: usize> Dispatcher<N> {
    pub const fn new(resources: [Resource; N]) -> Self {
        Self { resources }
    }

    /// Find and invoke the handler for a request.
    pub fn dispatch(&self, req: &Request) -> Response {
        for res in &self.resources {
            if req.path_matches(res.path) {
                let handler = match req.method {
                    MessageCode::GET => res.get,
                    MessageCode::PUT => res.put,
                    MessageCode::POST => res.post,
                    MessageCode::DELETE => res.delete,
                    _ => None,
                };
                return match handler {
                    Some(h) => h(req),
                    None => Response::method_not_allowed(),
                };
            }
        }
        Response::not_found()
    }

    /// Handle a CoAP packet, returning the response bytes if a reply is needed.
    ///
    /// Writes the response CoAP message to `out` and returns the length.
    pub fn handle_coap(&self, coap_bytes: &[u8], out: &mut [u8]) -> Option<usize> {
        let pkt = CoapPacket::from_bytes(coap_bytes).ok()?;
        let req = Request::from_coap(&pkt)?;
        let resp = self.dispatch(&req);

        // Build response
        let msg_type = match pkt.msg_type() {
            MessageType::Confirmable => MessageType::Acknowledgement,
            _ => MessageType::NonConfirmable,
        };

        let mut builder =
            CoapBuilder::new(out, msg_type, resp.code, pkt.message_id(), pkt.token()).ok()?;

        if let Some(cf) = resp.content_format {
            builder.content_format(cf).ok()?;
        }

        if resp.payload_len > 0 {
            builder.payload(&resp.payload[..resp.payload_len]).ok()?;
        }

        Some(builder.finish())
    }
}

// ── Built-in resources ──────────────────────────────────────────────────────

/// Well-known core resource (RFC 6690 discovery).
pub fn handle_well_known_core(_req: &Request) -> Response {
    Response::content(b"</sensors>,</config>")
}

/// Example sensors resource handler.
pub fn handle_sensors_get(_req: &Request) -> Response {
    Response::content(b"{\"temp\":25.0,\"humidity\":50}")
}

/// Example config resource handler.
pub fn handle_config_get(_req: &Request) -> Response {
    Response::content(b"{\"interval\":60}")
}

pub fn handle_config_put(req: &Request) -> Response {
    if req.payload.is_empty() {
        return Response::bad_request();
    }
    Response::changed()
}

/// Default dispatcher with /sensors and /config resources.
pub const fn default_dispatcher() -> Dispatcher<3> {
    Dispatcher::new([
        Resource::new(&[b".well-known", b"core"]).get(handle_well_known_core),
        Resource::new(&[b"sensors"]).get(handle_sensors_get),
        Resource::new(&[b"config"])
            .get(handle_config_get)
            .put(handle_config_put),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_get(path: &[&str], out: &mut [u8]) -> usize {
        let mut builder = CoapBuilder::new(
            out,
            MessageType::Confirmable,
            MessageCode::GET,
            0x1234,
            &[0xAB],
        )
        .unwrap();
        for seg in path {
            builder.uri_path(seg).unwrap();
        }
        builder.finish()
    }

    fn build_put(path: &[&str], payload: &[u8], out: &mut [u8]) -> usize {
        let mut builder = CoapBuilder::new(
            out,
            MessageType::Confirmable,
            MessageCode::PUT,
            0x5678,
            &[0xCD],
        )
        .unwrap();
        for seg in path {
            builder.uri_path(seg).unwrap();
        }
        builder.payload(payload).unwrap();
        builder.finish()
    }

    #[test]
    fn dispatch_sensors_get() {
        let dispatcher = default_dispatcher();
        let mut req_buf = [0u8; 64];
        let req_len = build_get(&["sensors"], &mut req_buf);

        let mut resp_buf = [0u8; 256];
        let resp_len = dispatcher.handle_coap(&req_buf[..req_len], &mut resp_buf);
        assert!(resp_len.is_some());

        let pkt = CoapPacket::from_bytes(&resp_buf[..resp_len.unwrap()]).unwrap();
        assert_eq!(pkt.code(), MessageCode::CONTENT);
        assert!(pkt.payload().starts_with(b"{"));
    }

    #[test]
    fn dispatch_config_put() {
        let dispatcher = default_dispatcher();
        let mut req_buf = [0u8; 64];
        let req_len = build_put(&["config"], b"{\"interval\":120}", &mut req_buf);

        let mut resp_buf = [0u8; 256];
        let resp_len = dispatcher.handle_coap(&req_buf[..req_len], &mut resp_buf);
        assert!(resp_len.is_some());

        let pkt = CoapPacket::from_bytes(&resp_buf[..resp_len.unwrap()]).unwrap();
        assert_eq!(pkt.code(), MessageCode::CHANGED);
    }

    #[test]
    fn dispatch_not_found() {
        let dispatcher = default_dispatcher();
        let mut req_buf = [0u8; 64];
        let req_len = build_get(&["nonexistent"], &mut req_buf);

        let mut resp_buf = [0u8; 256];
        let resp_len = dispatcher.handle_coap(&req_buf[..req_len], &mut resp_buf);
        assert!(resp_len.is_some());

        let pkt = CoapPacket::from_bytes(&resp_buf[..resp_len.unwrap()]).unwrap();
        assert_eq!(pkt.code(), MessageCode::NOT_FOUND);
    }

    #[test]
    fn dispatch_method_not_allowed() {
        let dispatcher = default_dispatcher();
        // POST to /sensors which only has GET
        let mut req_buf = [0u8; 64];
        let mut builder = CoapBuilder::new(
            &mut req_buf,
            MessageType::Confirmable,
            MessageCode::POST,
            0x1234,
            &[],
        )
        .unwrap();
        builder.uri_path("sensors").unwrap();
        builder.payload(b"test").unwrap();
        let req_len = builder.finish();

        let mut resp_buf = [0u8; 256];
        let resp_len = dispatcher.handle_coap(&req_buf[..req_len], &mut resp_buf);
        assert!(resp_len.is_some());

        let pkt = CoapPacket::from_bytes(&resp_buf[..resp_len.unwrap()]).unwrap();
        assert_eq!(pkt.code(), MessageCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn well_known_core_discovery() {
        let dispatcher = default_dispatcher();
        let mut req_buf = [0u8; 64];
        let req_len = build_get(&[".well-known", "core"], &mut req_buf);

        let mut resp_buf = [0u8; 256];
        let resp_len = dispatcher.handle_coap(&req_buf[..req_len], &mut resp_buf);
        assert!(resp_len.is_some());

        let pkt = CoapPacket::from_bytes(&resp_buf[..resp_len.unwrap()]).unwrap();
        assert_eq!(pkt.code(), MessageCode::CONTENT);
        assert!(pkt.payload().starts_with(b"</sensors>"));
    }
}
