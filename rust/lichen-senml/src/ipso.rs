//! IPSO Smart Object names for SenML records.
//!
//! LwM2M resource paths are `object/instance/resource`. SenML names use the
//! same path without the CoAP URI's leading slash. The compact two-component
//! `object/instance` form is available when a composite profile implies the
//! resource.

use core::fmt;

use crate::Record;

/// IPSO Smart Object identifiers used by the LICHEN sensor profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ObjectId {
    Temperature = 3303,
    Humidity = 3304,
    Accelerometer = 3313,
    Barometer = 3315,
    Pressure = 3323,
    Gyrometer = 3334,
    Location = 3336,
}

/// Reusable IPSO resources used by supported objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ResourceId {
    Timestamp = 5518,
    SensorValue = 5700,
    SensorUnits = 5701,
    XValue = 5702,
    YValue = 5703,
    ZValue = 5704,
    CompassDirection = 5705,
    NumericLatitude = 6051,
    NumericLongitude = 6052,
    NumericUncertainty = 6053,
}

/// Metadata needed to create the primary SenML record for a known object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectDefinition {
    pub id: ObjectId,
    pub name: &'static str,
    pub value_resource: ResourceId,
    pub default_unit: &'static str,
}

/// Objects for which LICHEN defines SenML units and primary resources.
pub const OBJECTS: &[ObjectDefinition] = &[
    ObjectDefinition {
        id: ObjectId::Temperature,
        name: "Temperature",
        value_resource: ResourceId::SensorValue,
        default_unit: "Cel",
    },
    ObjectDefinition {
        id: ObjectId::Humidity,
        name: "Humidity",
        value_resource: ResourceId::SensorValue,
        default_unit: "%RH",
    },
    ObjectDefinition {
        id: ObjectId::Accelerometer,
        name: "Accelerometer",
        value_resource: ResourceId::XValue,
        default_unit: "m/s2",
    },
    ObjectDefinition {
        id: ObjectId::Barometer,
        name: "Barometer",
        value_resource: ResourceId::SensorValue,
        default_unit: "Pa",
    },
    ObjectDefinition {
        id: ObjectId::Pressure,
        name: "Pressure",
        value_resource: ResourceId::SensorValue,
        default_unit: "Pa",
    },
    ObjectDefinition {
        id: ObjectId::Gyrometer,
        name: "Gyrometer",
        value_resource: ResourceId::XValue,
        default_unit: "rad/s",
    },
    ObjectDefinition {
        id: ObjectId::Location,
        name: "Location",
        value_resource: ResourceId::NumericLatitude,
        default_unit: "lat",
    },
];

/// Return metadata for a supported object ID.
pub fn object_definition(object_id: u16) -> Option<&'static ObjectDefinition> {
    OBJECTS
        .iter()
        .find(|definition| definition.id as u16 == object_id)
}

/// Return the LICHEN SenML unit for a known object/resource pair.
pub fn default_unit(object_id: u16, resource_id: u16) -> Option<&'static str> {
    match (object_id, resource_id) {
        (3303, 5700) => Some("Cel"),
        (3304, 5700) => Some("%RH"),
        (3313, 5702..=5704) => Some("m/s2"),
        (3315 | 3323, 5700) => Some("Pa"),
        (3334, 5702..=5704) => Some("rad/s"),
        (3336, 6051) => Some("lat"),
        (3336, 6052) => Some("lon"),
        (3336, 6053) => Some("m"),
        (3336, 5705) => Some("deg"),
        _ => None,
    }
}

/// A canonical IPSO object/instance[/resource] relative path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Path {
    pub object_id: u16,
    pub instance_id: u16,
    pub resource_id: Option<u16>,
}

impl Path {
    /// Create a compact object/instance name.
    pub const fn object_instance(object_id: u16, instance_id: u16) -> Self {
        Self {
            object_id,
            instance_id,
            resource_id: None,
        }
    }

    /// Create a full object/instance/resource name.
    pub const fn resource(object_id: u16, instance_id: u16, resource_id: u16) -> Self {
        Self {
            object_id,
            instance_id,
            resource_id: Some(resource_id),
        }
    }

    /// Create the primary value path for a known object.
    pub fn primary(object_id: u16, instance_id: u16) -> Self {
        let resource_id = object_definition(object_id)
            .map(|definition| definition.value_resource as u16)
            .unwrap_or(ResourceId::SensorValue as u16);
        Self::resource(object_id, instance_id, resource_id)
    }

    /// Parse a canonical relative IPSO path.
    pub fn parse(name: &str) -> Result<Self, PathError> {
        let mut components = name.split('/');
        let object = components.next().ok_or(PathError::InvalidShape)?;
        let instance = components.next().ok_or(PathError::InvalidShape)?;
        let resource = components.next();
        if components.next().is_some() {
            return Err(PathError::InvalidShape);
        }
        if resource.is_none() && (object.is_empty() || instance.is_empty()) {
            return Err(PathError::InvalidComponent);
        }
        Ok(Self {
            object_id: parse_component(object)?,
            instance_id: parse_component(instance)?,
            resource_id: resource.map(parse_component).transpose()?,
        })
    }

    /// Number of ASCII bytes required by the canonical name.
    pub const fn encoded_len(&self) -> usize {
        let mut len = decimal_len(self.object_id) + 1 + decimal_len(self.instance_id);
        if let Some(resource_id) = self.resource_id {
            len += 1 + decimal_len(resource_id);
        }
        len
    }

    /// Write the canonical name into caller-provided storage.
    pub fn write_name<'a>(&self, out: &'a mut [u8]) -> Result<&'a str, NameError> {
        let needed = self.encoded_len();
        if out.len() < needed {
            return Err(NameError::BufferTooSmall {
                needed,
                available: out.len(),
            });
        }

        let mut position = 0;
        position += write_decimal(self.object_id, &mut out[position..]);
        out[position] = b'/';
        position += 1;
        position += write_decimal(self.instance_id, &mut out[position..]);
        if let Some(resource_id) = self.resource_id {
            out[position] = b'/';
            position += 1;
            position += write_decimal(resource_id, &mut out[position..]);
        }

        core::str::from_utf8(&out[..position]).map_err(|_| NameError::InvalidUtf8)
    }

    /// Build a numeric SenML record using caller-owned storage for the name.
    pub fn record<'a>(
        &self,
        name_storage: &'a mut [u8],
        value: f64,
        unit: Option<&'a str>,
    ) -> Result<Record<'a>, NameError> {
        let name = self.write_name(name_storage)?;
        Ok(Record {
            name: Some(name),
            value: Some(value),
            unit,
            ..Record::empty()
        })
    }

    /// Unit inferred for this exact known object/resource pair.
    pub fn default_unit(&self) -> Option<&'static str> {
        self.resource_id
            .and_then(|resource_id| default_unit(self.object_id, resource_id))
    }
}

impl fmt::Display for Path {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.object_id, self.instance_id)?;
        if let Some(resource_id) = self.resource_id {
            write!(formatter, "/{resource_id}")?;
        }
        Ok(())
    }
}

/// IPSO path parsing failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    InvalidShape,
    InvalidComponent,
    NonCanonical,
    OutOfRange,
}

impl fmt::Display for PathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidShape => formatter.write_str("IPSO path must have 2 or 3 components"),
            Self::InvalidComponent => {
                formatter.write_str("IPSO path components must be unsigned decimal integers")
            }
            Self::NonCanonical => {
                formatter.write_str("IPSO path components must use canonical decimal encoding")
            }
            Self::OutOfRange => formatter.write_str("IPSO path component exceeds 65535"),
        }
    }
}

impl core::error::Error for PathError {}

/// IPSO name formatting failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameError {
    BufferTooSmall { needed: usize, available: usize },
    InvalidUtf8,
}

impl fmt::Display for NameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooSmall { needed, available } => write!(
                formatter,
                "IPSO name buffer too small: need {needed} bytes, have {available}"
            ),
            Self::InvalidUtf8 => formatter.write_str("IPSO name was not valid UTF-8"),
        }
    }
}

impl core::error::Error for NameError {}

fn parse_component(component: &str) -> Result<u16, PathError> {
    if component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(PathError::InvalidComponent);
    }
    if component.len() > 1 && component.starts_with('0') {
        return Err(PathError::NonCanonical);
    }
    let mut value = 0_u32;
    for byte in component.bytes() {
        value = value
            .checked_mul(10)
            .and_then(|current| current.checked_add(u32::from(byte - b'0')))
            .ok_or(PathError::OutOfRange)?;
        if value > u32::from(u16::MAX) {
            return Err(PathError::OutOfRange);
        }
    }
    Ok(value as u16)
}

const fn decimal_len(value: u16) -> usize {
    match value {
        0..=9 => 1,
        10..=99 => 2,
        100..=999 => 3,
        1000..=9999 => 4,
        _ => 5,
    }
}

fn write_decimal(value: u16, out: &mut [u8]) -> usize {
    let len = decimal_len(value);
    let mut remaining = value;
    let mut position = len;
    while position > 0 {
        position -= 1;
        out[position] = b'0' + (remaining % 10) as u8;
        remaining /= 10;
    }
    len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maximum_path_fits_seventeen_bytes() {
        let path = Path::resource(u16::MAX, u16::MAX, u16::MAX);
        let mut name = [0_u8; 17];
        assert_eq!(path.write_name(&mut name), Ok("65535/65535/65535"));
    }

    #[test]
    fn record_borrows_formatted_name() {
        let path = Path::primary(ObjectId::Temperature as u16, 0);
        let mut name = [0_u8; 17];
        let record = path.record(&mut name, 23.5, path.default_unit()).unwrap();
        assert_eq!(record.name, Some("3303/0/5700"));
        assert_eq!(record.unit, Some("Cel"));
        assert_eq!(record.value, Some(23.5));
    }
}
