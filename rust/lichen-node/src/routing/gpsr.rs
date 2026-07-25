//! GPSR geographic forwarding (spec 9.7).

use super::neighbor::GeoCoords;

/// Haversine distance in meters between two (lat, lon) points.
pub fn haversine(c1: GeoCoords, c2: GeoCoords) -> f64 {
    const EARTH_RADIUS_M: f64 = 6_371_000.0;

    let (lat1, lon1) = c1;
    let (lat2, lon2) = c2;

    let lat1_rad = lat1.to_radians();
    let lat2_rad = lat2.to_radians();
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();

    let a =
        (dlat / 2.0).sin().powi(2) + lat1_rad.cos() * lat2_rad.cos() * (dlon / 2.0).sin().powi(2);
    // Clamp a to [0, 1] before sqrt to handle floating-point errors
    let c = 2.0 * libm::asin(libm::sqrt(a.min(1.0)));

    EARTH_RADIUS_M * c
}

/// Validate geographic coordinates.
/// Returns false for NaN, inf, out-of-range, or null island (0,0).
pub fn is_valid_coords(coords: GeoCoords) -> bool {
    let (lat, lon) = coords;

    // Check for NaN/inf
    if !lat.is_finite() || !lon.is_finite() {
        return false;
    }

    // Reject null island sentinel (almost always invalid GPS data)
    if lat == 0.0 && lon == 0.0 {
        return false;
    }

    // Check valid geographic ranges
    (-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon)
}
