# Local Zephyr patches

The `zephyr/` west module is pinned to upstream **v3.7.0** plus the local
changes captured in `zephyr-v3.7.0-local.patch`. `west update` will discard
them — re-apply with:

```bash
cd zephyr && git apply ../patches/zephyr-v3.7.0-local.patch
```

Contents (one combined diff, four files):

| File | What / why |
|---|---|
| `drivers/lora/sx126x.c` | `SX126xWaitOnBusy()`: 500 ms deadline + hard radio reset instead of waiting forever on a stuck BUSY line (radio lockup resilience). |
| `drivers/usb/device/usb_dc_nrfx.c` | Old-stack USB fixes for boards whose bootloader leaves USB active (ghost power events, T1000-E bring-up era). |
| `drivers/usb/udc/udc_nrf.c` | NEXT-stack: defer D+ pull-up when the READY power event fires before `udc_nrf_enable()` (ghost event from a USB-active bootloader); assert pull-up unconditionally in enable. |
| `subsys/usb/device_next/class/usbd_cdc_acm.c` | **Priority-inversion livelock fix.** The CDC-ACM workqueue runs at cooperative priority; handlers that couldn't make progress (CDC_ACM_LOCK held by a preemptible thread in `poll_out`/`poll_in`, buf pool empty, or IRQ-pending retry) resubmitted themselves immediately, monopolizing the CPU so the lock holder never ran again — on the T-Echo this starved the WDT heartbeat and hard-reset the SoC ~4 s after *any* host port open (bd `lora_ipv6_mesh-ihm3`). Retry paths now back off one tick via `k_work_delayable`; fresh-event paths are unchanged (`K_NO_WAIT`). Candidate for upstreaming — check whether Zephyr ≥3.8 already restructured this driver before submitting. |
