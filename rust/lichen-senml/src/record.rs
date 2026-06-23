//! SenML record type (RFC 8428 §4).

/// A single SenML record.
///
/// Fields mirror RFC 8428 §4.3. All string fields are `&str` slices to avoid
/// heap allocation; owned variants can be built with `alloc` (future work).
#[derive(Debug)]
pub struct Record<'a> {
    /// Base name, e.g. `"urn:dev:mac:0123456789abcdef:"`.
    pub base_name: Option<&'a str>,
    /// Base time (Unix seconds, relative or absolute).
    pub base_time: Option<f64>,
    /// Relative name appended to base_name, e.g. `"temp"`.
    pub name: Option<&'a str>,
    /// Relative time offset from base_time.
    pub time: Option<f64>,
    /// Numeric value.
    pub value: Option<f64>,
    /// String value.
    pub string_value: Option<&'a str>,
    /// Boolean value.
    pub bool_value: Option<bool>,
    /// Unit, e.g. `"Cel"` for Celsius.
    pub unit: Option<&'a str>,
}

impl<'a> Record<'a> {
    pub const fn empty() -> Self {
        Self {
            base_name: None,
            base_time: None,
            name: None,
            time: None,
            value: None,
            string_value: None,
            bool_value: None,
            unit: None,
        }
    }
}
