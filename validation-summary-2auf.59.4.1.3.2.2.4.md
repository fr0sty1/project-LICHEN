<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Validation Summary: native_posix BLE Ingress Runtime (no link.35.6)

**Bead:** project-LICHEN-2auf.59.4.1.3.2.2.4
**Date:** 2026-07-23 (UTC)
**Result:** RUNTIME PASS after one config fix — binary runs stable (15 s soak, exit 124 = timeout SIGINT, 0 fatal errors, 0 link-layer log lines); ztest harness `net.lichen.ble_ingress` 4/4 PASS, no regressions. Full hashes in `artifacts-2auf.59.4.1.3.2.2.4.txt`.

## What was done

1. Verified the previously built binary (`build/ble-native-posix-ingress-59-4-final6`) against the manifest from bead `…2.2.2.4` (SHA256 match on `zephyr.exe` / `zephyr.elf`).
2. Ran it — it **crashed deterministically** immediately after `main()` returned:
   `ZEPHYR FATAL ERROR 2: Stack overflow on CPU 0`, thread `z_idle_threads`, via `__stack_chk_fail` (`kernel/compiler_stack_protect.c:39`).
3. Root-caused with a `CONFIG_ARCH_POSIX_TRAP_ON_FATAL=y` debug build + core dump (parsed NT_PRSTATUS/stack with pyelftools — no gdb on host):
   - The `__stack_chk_fail` executes on the host main thread's stack, above frames `main → nsi_init → nsi_cpu_auto_boot → nsif_cpun_boot → nsif_cpu0_boot → nested _start/__libc_start_main` (native_sim CPU0 boot path).
   - Mechanism: with `CONFIG_STACK_CANARIES=y`, `z_cstart()` re-seeds the compiler canary guard `__stack_chk_guard` at PRE_KERNEL_2 (`kernel/init.c:670-676`). The native simulator's host-side boot frames were compiled with stack-protector and were established *before* that re-seed, with the exec-time guard value 0. The first return through such a pre-seed frame mismatches the new guard and trips `__stack_chk_fail`. Zephyr attributes the fault to the current Zephyr thread, which by then is the idle thread — hence the misleading "stack overflow on z_idle_threads".
   - Isolation builds proved the trigger: `STACK_CANARIES=y` alone crashes; `STACK_CANARIES=n` (sentinel on or off) runs clean. `IDLE_STACK_SIZE` is irrelevant on the POSIX arch (real stacks are host pthread stacks; Zephyr stack holds only thread status).
4. Fix (minimal, in `lichen/apps/gateway/boards/native_posix_ble_ingress.conf` only): `CONFIG_STACK_CANARIES=n` with a comment documenting the native_sim limitation. `STACK_SENTINEL=y`, `ASSERT=y`, `ASSERT_VERBOSE=y` retained and verified clean. The base gateway `prj.conf` never enabled canaries, so this only aligns the validation image; the safety policy is unaffected on real-hardware targets.
5. Rebuilt pristine with the documented command (`build/ble-native-posix-ingress-59-4-224`, exit 0, 186/186 steps) and re-ran.

## Runtime evidence (final image)

`test-logs-2auf.59.4.1.3.2.2.4-native-runtime.log` (15 s run, exit 124 = killed by timeout, i.e. healthy idle):

- `LICHEN gateway starting` → `No LoRa radio configured - CoAP/local-client only` (link layer excluded as configured).
- `bt_enable failed: -19` → `BLE UART init failed — BLE unavailable` — graceful degradation: this host has no Bluetooth controller (`/sys/class/bluetooth` empty, no btproxy/btvirt), and native_sim without `--bt-dev` has no HCI device. The BLE ingress image handles it without a fault.
- `RPL root signalling disabled` (as configured) → `CoAP server on port 5683 (AUTOSTART)`.
- 0 `FATAL` lines; 0 link-layer log lines (`lora_`, `link_`, RX/TX) — no link-layer regressions by construction.
- Cross-check: generated `zephyr.dts` SHA256 `e71b936d…dd32e9` identical to both prior builds (`…2.2.2.3`, `…2.2.2.4`).

## Test-harness evidence (BLE ingress paths)

`west twister -T lichen/tests/ble_ingress -p qemu_x86` → 1/1 configurations passed, **4/4 test cases PASS** (`test-logs-…2.2.4-twister.log`, `…-ble-ingress-qemu.log`):

- `test_ble_lci_iface_is_configured_for_slip_link` PASS
- `test_injects_ipv6_to_rx_path` PASS
- `test_rejects_malformed_ipv6` PASS (null / IPv4 / bad payload length / no netif all rejected)
- `test_reply_exits_ble_lci_egress_path` PASS

The harness exercises the same `ble_ingress.c` / `ble_lci_netif.c` sources built into the native image; the qemu_x86 run is the data-path check, the native run is the boot/stability check. No regressions in either.

## Notes / follow-ups

- `STACK_CANARIES=y` on `native_sim` remains a latent trap for any LICHEN app image that enables it (ztest apps like `link_crypto` pass because their run ends before a pre-seed host frame returns; the gateway app returns from `main()` and idles, which exposes it). Worth a `bd remember` / follow-up if other native app images adopt the safety-policy block.
- Real HCI passthrough (`--bt-dev=hciN`) is not exercisable on this host (no controller, no root); BLE ingress is validated at the LCI/netif boundary via the ztest stub instead.

## Related Beads

- `…2.2.2.4` — produced the original build + summary; its binary is the one that exposed the runtime crash.
- `…2.2.3` — build-log/SHA256 capture sibling.
- Parent `…2.2` — closed as "Decomposed into subtasks".
