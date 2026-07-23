// SPDX-License-Identifier: GPL-3.0-or-later

use std::io::{self, Result};
use std::path::Path;

fn main() -> Result<()> {
    let proto_dir = "proto";
    let proto_files = [
        "proto/meshtastic/mesh.proto",
        "proto/meshtastic/portnums.proto",
        "proto/meshtastic/config.proto",
        "proto/meshtastic/telemetry.proto",
        "proto/meshtastic/channel.proto",
        "proto/meshtastic/module_config.proto",
    ];

    if !Path::new(proto_dir).is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("proto directory not found: {}", proto_dir),
        ));
    }

    for &proto in &proto_files {
        if !Path::new(proto).exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("proto file not found: {}", proto),
            ));
        }
        println!("cargo:rerun-if-changed={}", proto);
    }

    prost_build::Config::new()
        .out_dir("src/")
        .compile_protos(&proto_files, &[proto_dir])?;

    Ok(())
}
