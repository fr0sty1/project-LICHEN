"""Record a simulation to a pcapng file for Wireshark analysis.

Runs a two-node exchange and writes each packet to capture.pcapng.
Open the output with Wireshark (link type USER0 / 0x93).

get_rx_result() is called while the TX is in-flight so the packet is
captured before advancing time past the TX end event.
"""

import tempfile
from pathlib import Path

from lichen.sim.pcap import PcapngWriter
from lichen.sim.simulation import Simulation, TimeMode

sim = Simulation(sim_id="pcap-demo", time_mode=TimeMode.BARRIER_SYNC, seed=7)
sim.add_node("a", x=0.0, y=0.0, z=0.0)
sim.add_node("b", x=10.0, y=0.0, z=0.0)

outfile = Path(tempfile.mkdtemp()) / "capture.pcapng"

with PcapngWriter(outfile) as writer:
    for i in range(3):
        msg = f"packet-{i}".encode()
        sim.start_transmission("a", msg)

        # Query reception while TX is in-flight
        result = sim.get_rx_result("b")

        # Let TxEndEvent fire before next iteration
        sim.advance_to(sim.current_time_us + 500_000)

        if result is not None:
            data, rssi, snr = result
            writer.write_packet(
                timestamp_us=sim.current_time_us,
                data=data,
                rssi=rssi,
                snr=snr,
                src_node="a",
                dst_node="b",
            )
            print(f"[t={sim.current_time_us:>10} µs] captured {data!r}")

print(f"\nCapture written to: {outfile}")
print("Open with: wireshark capture.pcapng")
