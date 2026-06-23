"""Basic two-node simulation: transmit and receive a packet.

This example creates a simulation directly (without a running server),
adds two nodes, transmits from node A, and checks that node B receives it.

In BARRIER_SYNC mode, get_rx_result() is checked while the transmission is
still in-flight. Call it before advancing time past the TX end event.
"""

from lichen.sim.simulation import Simulation, TimeMode

sim = Simulation(sim_id="demo", time_mode=TimeMode.BARRIER_SYNC, seed=42)

node_a = sim.add_node("a", x=0.0, y=0.0, z=0.0)
node_b = sim.add_node("b", x=10.0, y=0.0, z=0.0)  # 10 m away

payload = b"hello from a"
sim.start_transmission("a", payload)  # TX begins at t=0

# The packet is in-flight; query reception before advancing past TX end.
result = sim.get_rx_result("b")

# Let TxEndEvent fire to clean up simulator state.
sim.advance_to(sim.current_time_us + 500_000)

if result is not None:
    data, rssi, snr = result
    print(f"node B received: {data!r}  RSSI={rssi} dBm  SNR={snr} dB")
else:
    print("node B received nothing (check distance / propagation model)")
