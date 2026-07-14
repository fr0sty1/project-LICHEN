// SPDX-License-Identifier: GPL-3.0-or-later

use std::io::Result;

fn main() -> Result<()> {
    let proto_dir = "proto";

    prost_build::Config::new().out_dir("src/").compile_protos(
        &[
            "proto/meshtastic/mesh.proto",
            "proto/meshtastic/portnums.proto",
            "proto/meshtastic/config.proto",
            "proto/meshtastic/telemetry.proto",
            "proto/meshtastic/channel.proto",
            "proto/meshtastic/module_config.proto",
        ],
        &[proto_dir],
    )?;

    println!("cargo:rerun-if-changed={}", proto_dir);
    Ok(())
}
