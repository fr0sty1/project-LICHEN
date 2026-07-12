# Local Zephyr patches

The `zephyr/` west module is pinned to upstream **v3.7.0** plus the local
changes captured in `zephyr-v3.7.0-local.patch`, and `modules/lib/loramac-node`
carries `loramac-node-local.patch`. `west update` will discard both — re-apply
with:

```bash
cd zephyr && git apply ../patches/zephyr-v3.7.0-local.patch && cd ..
cd modules/lib/loramac-node && git apply ../../../patches/loramac-node-local.patch
```

Zephyr contents (one combined diff, five files):

| File | What / why |
|---|---|
| `drivers/lora/sx126x.c` | `SX126xWaitOnBusy()`: 500 ms deadline + hard radio reset instead of waiting forever on a stuck BUSY line (radio lockup resilience). |
| `drivers/usb/device/usb_dc_nrfx.c` | Old-stack USB fixes for boards whose bootloader leaves USB active (ghost power events, T1000-E bring-up era). |
| `drivers/usb/udc/udc_nrf.c` | NEXT-stack: defer D+ pull-up when the READY power event fires before `udc_nrf_enable()` (ghost event from a USB-active bootloader); assert pull-up unconditionally in enable. |
| `subsys/usb/device_next/class/usbd_cdc_acm.c` | **Priority-inversion livelock fix.** The CDC-ACM workqueue runs at cooperative priority; handlers that couldn't make progress (CDC_ACM_LOCK held by a preemptible thread in `poll_out`/`poll_in`, buf pool empty, or IRQ-pending retry) resubmitted themselves immediately, monopolizing the CPU so the lock holder never ran again — on the T-Echo this starved the WDT heartbeat and hard-reset the SoC ~4 s after *any* host port open (bd `lora_ipv6_mesh-ihm3`). Retry paths now back off one tick via `k_work_delayable`; fresh-event paths are unchanged (`K_NO_WAIT`). Candidate for upstreaming — check whether Zephyr ≥3.8 already restructured this driver before submitting. |
| `drivers/lora/sx12xx_common.c` | **RX window preamble-hold.** `lora_recv()`'s host-side timeout aborted receptions already in progress; with 1 s application windows a ~0.7 s SF10 frame rarely survived the boundary. The recv path now records radio RX activity (via the `RadioRxActivity()` hook patched into loramac-node) and holds the window open — bounded by one max-frame airtime — while a frame is arriving. Raised the bench CoAP first-attempt rate from ~69% to ~93% at 1 s windows (bd `lora_ipv6_mesh-c3wn`). |

loramac-node contents (`loramac-node-local.patch`):

| File | What / why |
|---|---|
| `src/radio/sx126x/radio.c` | Adds a weak no-op `RadioRxActivity()` hook, called from `RadioIrqProcess()` on PREAMBLE_DETECTED / SYNCWORD_VALID / HEADER_VALID (previously ignored). Platforms override it to implement receive-window holding; unpatched consumers are unaffected. |
