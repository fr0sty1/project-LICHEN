"""Multi-hop mesh topology: capture a relay scenario.

Three nodes in a line: A – B – C (50 m between each pair).
A transmits; B is in range of A and C; C may or may not be in direct range.
Shows checking reception hop by hop and simulating a relay.
"""

from lichen.sim.simulation import Simulation, TimeMode

sim = Simulation(sim_id="mesh", time_mode=TimeMode.BARRIER_SYNC, seed=1)

# 50 m spacing; LoRa SF10/BW125 urban model has limited range
sim.add_node("a", x=0.0,   y=0.0, z=0.0)
sim.add_node("b", x=50.0,  y=0.0, z=0.0)
sim.add_node("c", x=100.0, y=0.0, z=0.0)

payload = b"hop-me"
sim.start_transmission("a", payload)

# Query reception while TX is in-flight (before TxEndEvent fires)
rx_b = sim.get_rx_result("b")
rx_c_direct = sim.get_rx_result("c")

# Let TxEndEvent fire
sim.advance_to(sim.current_time_us + 500_000)

print(f"A→B direct:  {'ok' if rx_b else 'miss'}")
print(f"A→C direct:  {'ok' if rx_c_direct else 'miss'} (may miss at 100 m)")

# Relay: B re-transmits what it received
if rx_b:
    data, rssi, snr = rx_b
    print(f"  B received {data!r} RSSI={rssi} dBm SNR={snr} dB — relaying…")
    sim.start_transmission("b", data)
    rx_c_relayed = sim.get_rx_result("c")
    sim.advance_to(sim.current_time_us + 500_000)
    print(f"B→C relayed: {'ok' if rx_c_relayed else 'miss'}")

# Overall delivery stats
snap = sim.metrics.snapshot()
print(f"\nMetrics: {snap['transmissions']} tx, {snap['receptions']} rx, "
      f"{snap['collisions']} collisions, "
      f"delivery rate {snap['delivery_rate']:.0%}")
