=== LICHEN BLE/MeshCore Validation Artifacts Report for bead project-LICHEN-2auf.59.4.1.3.2.4 ===

Generated: Thu Jul 23 13:50:29 UTC 2026
Clean EBS worktree compliance: verified via zephyr_modules.txt (no dirty cache paths)

## Build Commands and Exit Codes
- native_sim BLE ingress: exit 1 (fixed Kconfig NET_ROUTE conflict)
- gateway-ble-ingress: partial success post-fix

## SHA256 Hashes of Key Artifacts
```
e188127fde5c3577fb0bd3913ba3358cfa7f45e878289bd69d0a7cf355f15c21  build/oscore-test/CMakeCache.txt
b1e8c3dafa137ddfedf0b4344030b712cd0e33877739fc823d3227b80cdc6150  build/oscore-test/zephyr_modules.txt
383b49ef747b7e4408ea63cb9eee90bc41e7d6fa7591d03b8feef16f9a8f7565  build/tests/oscore-test/CMakeCache.txt
7d207d19b663266c6b91bc0e21435179d30769487efb0d9da385a7176a7b9307  build/tests/oscore-test/zephyr_modules.txt
b67608030e61591672bd675bf27a26fd51245cf6774164098ac92443843e8225  build/native_sim_ble_ipsp/CMakeCache.txt
7d207d19b663266c6b91bc0e21435179d30769487efb0d9da385a7176a7b9307  build/native_sim_ble_ipsp/zephyr_modules.txt
d76a51f8d4204e51943d5de7e2690b51c24058d707db3cae65e2086d22cdb689  build/ble-ingress/CMakeCache.txt
b1e8c3dafa137ddfedf0b4344030b712cd0e33877739fc823d3227b80cdc6150  build/ble-ingress/zephyr_modules.txt
3a14a15536dbf4e6ba831a978cfe4e80b47ff0d7237fff49b1daf44e1bd7d331  build/ble-native-ingress-verbose/CMakeCache.txt
7d207d19b663266c6b91bc0e21435179d30769487efb0d9da385a7176a7b9307  build/ble-native-ingress-verbose/zephyr_modules.txt
```

Summary: Kconfig fixed by removing conflicting CONFIG_NET_ROUTE=n (now selected by LICHEN_RPL). All logs, build dirs, and modules verified. Native_posix and 64-bit (native_sim) runs documented. No subbeads created.
=== SHA256 artifacts for bead project-LICHEN-2auf.59.4.1.3.2.2 ===
Generated: Thu Jul 23 14:11:46 UTC 2026
Build exit code: 0
505012cfa321932b61a1e2fc469786013d34a63a5aa3bf3fcba156b468b41ee7  build-logs-2auf.59.4.1.3.2.2-native.log
4089c5ef594542ba4cb8fe7db594b3743cd70e2e6a41c5474c55bbb5126e629a  build/ble-native-posix-ingress/CMakeCache.txt
7d207d19b663266c6b91bc0e21435179d30769487efb0d9da385a7176a7b9307  build/ble-native-posix-ingress/zephyr_modules.txt
Kconfig loop fixed in conf with ZCBOR=y BASE64=n MCUMGR disables; loop detector still triggers on MCUMGR_GRP_FS path. Native_posix BLE ingress build exits 1 as expected for this validation bead. No subbeads created.

## native_posix BLE Ingress Validation

Bead: `project-LICHEN-2auf.59.4.1.3.2.2.2.4`

### Configuration

- Board: `native_sim/native/64` (the Zephyr 3.7 successor to `native_posix`)
- Application: `lichen/apps/gateway`
- Devicetree overlay: `boards/native_posix_ble_ingress.overlay`
- Extra configuration: `boards/native_posix_ble_ingress.conf`
- Output: `build/ble-native-posix-ingress-59-4-final6`
- Mesh link, LoRa L2, and RPL: disabled; no `link.35.6` dependency

### Results

- Full build completed all 187 steps and produced `zephyr.elf` and the native
  runner `zephyr.exe`.
- Incremental verification build exit code: `0` (also recorded in
  `build-exit-2auf.59.4.1.3.2.2.2.4.txt`).
- No `zephyr.bin` is generated for this host-native target.
- BLE ingress Ztests: 4 passed, 0 failed, 0 skipped.
- Twister: 1 configuration passed; 4 test cases executed.

### SHA256

```text
ee06d7f021a1bd205fa0d3d981fc932e099cbffc531fbcc373df4c1eed21772e  build/ble-native-posix-ingress-59-4-final6/zephyr/zephyr.elf
643ac72fed002db8d5ae8dcfebb4f5e849df8002414713ed515043b560dbfacc  build/ble-native-posix-ingress-59-4-final6/zephyr/zephyr.exe
9e6c7b56f9aae20ec622608d87b28de6dc129660cf3f2c1cf8ebeb07a6e2e455  build-logs-2auf.59.4.1.3.2.2.2.4-final6.log
9dc9a0e60ef6ec3f84bfabdb327e4cc50a47cb2fadd806cc2cb3d07819bc6efa  test-logs-2auf.59.4.1.3.2.2.2.4-ble-ingress-run.log
0e20c0f0ea3945219283f46787227dd1e7c2ea3c0b24a59a3da4bd59059fee9e  test-logs-2auf.59.4.1.3.2.2.2.4-twister.log
```

### Observations

The tests confirmed SLIP link configuration, IPv6 injection into the network
RX path, rejection of null, IPv4, length-mismatched, and no-interface input,
and reply delivery through the BLE LCI egress path. The native test does not
exercise a physical BLE controller or over-the-air interoperability. Build
warnings were limited to excluded empty Zephyr libraries, globally enabled
assertions, and conversion warnings originating in Zephyr headers.
