"""Chaos rules: drop, partition, degrade, jammer, and latency.

Demonstrates how to attach a ChaosEngine to a simulation and use each
rule type to inject network faults for resilience testing.

In BARRIER_SYNC mode, get_rx_result() is called while the TX is in-flight.
LatencyRule affects when a candidate is eligible for delivery; it is checked
by the node_server's RX polling loop rather than in direct simulation mode.
"""

from lichen.sim.chaos import (
    ChaosEngine,
    DegradeRule,
    DropRule,
    JammerRule,
    LatencyRule,
    PartitionRule,
)
from lichen.sim.simulation import Simulation, TimeMode


def run_with_rules(label: str, chaos: ChaosEngine) -> None:
    sim = Simulation(sim_id=label, time_mode=TimeMode.BARRIER_SYNC, chaos_engine=chaos, seed=0)
    sim.add_node("a", x=0.0, y=0.0, z=0.0)
    sim.add_node("b", x=10.0, y=0.0, z=0.0)
    sim.start_transmission("a", b"test")        # TX starts at t=0
    result = sim.get_rx_result("b")             # query while in-flight
    sim.advance_to(sim.current_time_us + 500_000)  # let TxEndEvent fire
    status = "received" if result is not None else "dropped"
    print(f"[{label:20s}] node B: {status}")


# No chaos — baseline
run_with_rules("no chaos", ChaosEngine())

# Drop all packets from node A
engine = ChaosEngine()
engine.add_rule(DropRule(node_id="a", direction="tx"))
run_with_rules("drop tx from a", engine)

# Partition: A and B in separate groups
engine = ChaosEngine()
engine.add_rule(PartitionRule(groups=[{"a"}, {"b"}]))
run_with_rules("partition a|b", engine)

# Degrade signal quality (reduce RSSI by 40 dB)
engine = ChaosEngine()
engine.add_rule(DegradeRule(node_id="b", rssi_penalty_db=40.0))
run_with_rules("degrade b -40 dB", engine)

# Jammer at A's position, 5 m radius (B is at 10 m — outside jam zone)
engine = ChaosEngine()
engine.add_rule(JammerRule(x=0.0, y=0.0, z=0.0, radius_m=5.0))
run_with_rules("jammer r=5m @a", engine)

# Jammer large enough to cover B (15 m radius)
engine = ChaosEngine()
engine.add_rule(JammerRule(x=0.0, y=0.0, z=0.0, radius_m=15.0))
run_with_rules("jammer r=15m @a", engine)

# LatencyRule: adds delivery delay to a candidate's added_latency_us field.
# In the node_server RX polling loop, packets become eligible only after
# end_time_us + added_latency_us has elapsed. Here we just show setup.
engine = ChaosEngine()
rule_id = engine.add_rule(LatencyRule(node_id="b", added_us=500_000))
print(f"[{'latency 500ms':20s}] rule added (id={rule_id[:8]}…); "
      "eligible after TX end + 500 ms in node_server loop")
