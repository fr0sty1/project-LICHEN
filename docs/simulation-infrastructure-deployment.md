# LICHEN Simulation Infrastructure Deployment Guide

This guide provides comprehensive instructions for deploying the LICHEN simulation infrastructure across multiple AWS EC2 instances for large-scale distributed mesh testing.

## Overview

The LICHEN simulation infrastructure supports distributed testing across multiple EC2 instances through:
- A coordinator service running the core simulation engine
- Multiple node types (Python, Rust, C/Zephyr) that connect to the coordinator
- Support for both heterogeneous mesh testing and Renode-based clusters

## Architecture

```
[Coordinator Node] ← TCP → [Python Nodes] 
         ↑
[Redis/MQTT] ← TCP → [Rust Nodes] 
         ↑
[Renode Nodes] ← TCP → [Zephyr Nodes]
```

## Components

1. **lichen-sim (SimulatorServer)**: Central RF propagation and time coordinator (python/src/lichen/sim/server.py):
    - Manages multiple simulations with BARRIER_SYNC or WALLCLOCK time modes
    - TCP node servers (default base port 5555) for SimRadio/Renode clients
    - REST API + WebSocket (port 5556) for control, metrics, chaos rules
    - Built-in chaos engine for drop/partition/jam/degrade rules
    - PCAPng export, structured logging, metrics collection

2. **Heterogeneous Nodes**: Connect via TCP to lichen-sim:
    - Zephyr C (Renode + SX1262.cs peripheral)
    - Rust (native `mesh-sim-node` or `lichend` with SimRadio)
    - Python (`lichen.sim` client libraries)
    - All implementations validated against shared test vectors

3. **Fleet Support**: EC2 instances run multiple node instances per VM using the fleet AMI; SSH tunnels or public binding for coordinator connectivity. No Redis/MQTT or Docker in current implementation.

## Deployment Methods

### Distributed EC2 Heterogeneous Deployment

Uses the fleet launchers for large-scale mixed-implementation testing (Zephyr/Renode + Rust + Python).

#### Prerequisites:
- AWS_PROFILE=personal configured (account 210337117346, us-west-2)
- Fleet AMI `ami-0764d1b512e22671f` (pre-installed Renode 1.16.1, Rust 1.97, Python 3.11+uv)
- Built firmware (`west build` for Zephyr nodes) or compiled Rust/Python packages
- Follow AGENTS.md AWS isolation: only touch `Project=LICHEN` tagged resources
- EBS builder cache `vol-0a95eee8d1d8461eb` for Zephyr builds

#### Deployment Steps (via scripts):
1. Build required firmware/binaries in clean worktree if validating changes (`tools/zephyr-clean-worktree.sh`)
2. Run `./scripts/ec2-hetero-fleet.sh --zephyr 40 --rust 40 --python 40 --duration 300`
3. Script starts lichen-sim coordinator (binds to 0.0.0.0), launches EC2 fleet, establishes tunnels, runs nodes
4. Nodes auto-register, participate in mesh, simulation runs for specified duration
5. Results, logs, metrics collected to local RESULTS_DIR; instances terminated on exit

#### Resource Allocation:
- Coordinator: runs locally or on small EC2 (c7g.xlarge recommended for >100 nodes)
- Fleet instances: c7g.xlarge (ARM64, 4vCPU; ~20 Renodes per instance)
- Scale by adjusting --nodes or per-type counts; monitor with CloudWatch

### AWS Fleet + Renode/Zephyr Deployment (Large Scale Distributed)

**Local Validation First:**
- Zephyr native_sim: `west build -b native_sim lichen/tests/link_crypto && west build -t run`
- Renode local: see `docs/renode-workflow.md`; `python lichen/boards/renode/nrf52840_lichen/run_multi_node.py`
- Use `tools/zephyr-clean-worktree.sh` on EC2 for validation of uncommitted changes.

**Fleet Scripts (Distributed Testing):**
- `ec2-renode-fleet.sh`: Pure Zephyr/Renode fleet (default 20 Renodes per c7g.xlarge)
- `ec2-hetero-fleet.sh`: Mixed Zephyr+ Rust + Python nodes for interop testing
- `ec2-renode-fleet-simple.sh`: Simplified single-command variant
- All launch lichen-sim via SimulatorServer (ports 5555 TCP nodes, 5556 API), use SSH for control/tunneling, collect metrics/PCAP/logs.

Example:
```bash
AWS_PROFILE=personal ./scripts/ec2-hetero-fleet.sh --zephyr 60 --rust 40 --python 40 --duration 600
AWS_PROFILE=personal ./scripts/ec2-renode-fleet.sh --nodes 200 --duration 300 --firmware build/lora_ping/zephyr/zephyr.elf
```

- Instances auto-tagged `Project=LICHEN`, `LaunchedBy=...`
- Fleet AMI: `ami-0764d1b512e22671f` (Renode, Rust, uv, no Docker)
- See `scripts/ec2-*.sh` for full options, cleanup, metrics export.
- Always follow AGENTS.md: verify tags before any destructive ops; use EBS cache for builds.

**Resource Notes:**
- c7g.xlarge for fleet (ARM64 Graviton, good for Renode parallelism)
- Coordinator can run on launch host; scale coordinator vertically for 1000+ nodes
- Use `bd remember` for persistent notes on Renode quirks (nRF52840 easyDMA etc.)

## Scaling Strategies

### Horizontal Scaling:
- Add more node instances to increase mesh density  
- Use Auto Scaling Groups for dynamic scaling based on demand
- Distribute nodes geographically for realistic WAN simulation

### Vertical Scaling:
- Increase instance types for higher computational requirements
- Use compute-optimized instances (c5, c6i) for intensive simulation calculations
- Add GPU instances for specialized packet simulation workloads

## AWS Resource Requirements

### Required Resources:
1. **VPC** with:
   - Public/private subnets
   - Internet Gateway for external access
   - Security groups allowing internal communication

2. **EC2 Instances**:
   - At least one coordinator (t3.medium minimum)
   - Variable number of node instances (depending on scaling needs)

3. **Storage**:
   - EBS volumes for logs and state (100GB minimum)
   - S3 bucket for long-term metric aggregation

### Security Considerations:
1. Restrict inbound access to coordinator ports
2. Use SSH key pairs for secure shell access
3. Implement AWS IAM policies for EC2 access
4. Enable CloudWatch monitoring for all instances

## Best Practices

### Resource Management:
1. Monitor CPU and memory utilization on coordinator instances
2. Set appropriate timeouts for network operations  
3. Implement graceful shutdown procedures
4. Configure health checks for node availability

### Node Placement:
1. Distribute nodes geographically for realistic WAN testing
2. Use same AZ for low-latency communication
3. Maintain balanced load across instances
4. Reserve capacity for future scaling

### Monitoring & Logging:
1. Enable CloudWatch Logs for detailed event visibility
2. Implement centralized metric collection (Prometheus/Grafana)
3. Set up alerting for simulation performance degradation
4. Archive logs for retrospective analysis

### Performance Optimization:
1. Tune simulation parameters based on instance capabilities
2. Adjust network buffer sizes for optimal throughput
3. Use caching where appropriate for repetitive computations
4. Optimize message serialization for reduced overhead

## Automation Commands (AWS Fleet)

```bash
# Heterogeneous interop test (recommended for validation)
AWS_PROFILE=personal ./scripts/ec2-hetero-fleet.sh --zephyr 50 --rust 50 --python 50 --duration 180

# Large Renode fleet
AWS_PROFILE=personal ./scripts/ec2-renode-fleet.sh --nodes 300 --duration 600

# Simple variant or with custom firmware
./scripts/ec2-renode-fleet-simple.sh
```

Local testing:
```bash
# Zephyr native_sim (fast)
west build -b native_sim -d build/native_sim lichen/tests/link_crypto && west build -t run

# Multi-node Renode (see renode-workflow.md)
python -m pytest lichen/boards/renode/nrf52840_lichen/test_mesh.py -q
```

See script headers for all flags (`--help`), AMI details, cleanup behavior, metrics/RESULTS_DIR output. Coordinator uses `SimulatorServer` from `lichen.sim.server`. Follow strict AWS tagging and isolation rules in AGENTS.md.

## Testing Scenarios

### Interoperability Testing:
1. Verify Python-Rust communication
2. Validate C/Zephyr node integration 
3. Test heterogeneous mesh behavior
4. Measure packet delivery consistency

### Load Testing:
1. Simulate varying node densities
2. Test collision handling under stress
3. Evaluate scalability limits
4. Assess performance degradation

### Failure Injection:
1. Simulate node disconnections
2. Test fault recovery mechanisms
3. Verify robustness under network partitioning
4. Validate graceful degradation

## Maintenance Procedures

### Routine Operations:
1. Backup simulation state regularly
2. Rotate log files to prevent disk exhaustion
3. Update node software with security patches
4. Optimize resource utilization based on trends

### Incident Response:
1. Monitor for packet loss spikes
2. Identify connectivity issues between nodes
3. Track performance bottlenecks on coordinator
4. Diagnose implementation-specific failures

## Troubleshooting

### Common Issues:
1. **Node connection failures**: Verify security groups and network ACLs
2. **Insufficient memory**: Scale to larger instance types or optimize allocations
3. **High latency**: Move instances to closer AZs or adjust instance types
4. **Packet loss**: Tune transmission parameters and check network throughput

### Diagnostic Commands:
```bash
# Check instance status
aws ec2 describe-instances --filters "Name=tag:Project,Values=LICHEN"

# Monitor logs
aws logs tail /aws/ecs/lichen-sim

# Check network performance
iostat -x 1 10

# Monitor CPU usage
top -b -n 1 | head -20
```

## Performance Metrics & Monitoring

Track these key metrics:
1. **Throughput**: Packets/sec transmitted/received
2. **Latency**: Transmission delay and propagation time
3. **Availability**: Node uptime and connection stability   
4. **Errors**: Failed transmissions and collision rates
5. **Resource Utilization**: CPU, memory, and disk usage

## Cost Optimization

### Q4 Budget (Seattle default):
- 500-node deployment hardware: $25,000 base ($50/unit)
- Landed cost (Seattle WA taxes + shipping): $27,500 ($55/unit)
- EC2 simulation fleet: ~$4,200/mo (spot t4g.medium coordinator + 20x node instances)
- Total Q4: $32k (hardware + 3mo sim ops buffer)

### Budget Control:
1. Use spot instances for non-critical testing
2. Auto-scale based on workload demands
3. Terminate unused instances after testing
4. Monitor hourly costs using AWS Cost Explorer
5. Implement tagging for easy cost allocation (`Project=LICHEN`)

### Cost Estimation Formula:
``` 
Estimated Monthly Cost = (Coordinator Instances × Hourly Rate) 
                      + (Node Instances × Hourly Rate × Node Count) 
                      + (Storage × Monthly Rate)
```

## Node Distribution Logistics (project-LICHEN-2nnd.3)

**Recommendation: Sell at cost (Option A)** for first demo
- $50-60/unit at booth
- Attendee keeps node (no recovery logistics)
- Simplest, attendees invested, revenue covers costs

**Booth setup:**
- Payment via Square or cash
- Printed quick-start card per box
- QR code linking to mesh join + live viz
- Sticker: "I survived the LICHEN mesh"

**Post-event:** Nodes stay with owners, join local meshes, optional telemetry for global deployment map. Builds community.

## Future Enhancements

Consider these improvements for larger-scale deployments:
1. Kubernetes orchestration for easier scaling
2. Container clustering with Docker Compose
3. Automated backup and restoration procedures
4. Integration with existing CI/CD pipelines
5. Enhanced monitoring using Prometheus/Grafana

## References

- **LICHEN AGENTS.md**: Main project documentation for EC2 setup
- **Scripts**: `ec2-hetero-fleet.sh`, `ec2-renode-fleet.sh`
- **AWS CLI Documentation**: Official AWS EC2 and CloudWatch documentation
- **Simulation Protocol**: `lichen/sim/protocol.py` for wire format details

> **What is a PRFAQ?** A PRFAQ (Press Release / FAQ) is an Amazon-originated product planning technique. It starts with a fictional press release written as if the product has already launched successfully, forcing clarity on customer benefit and desired outcome. The FAQ section then anticipates hard internal and external questions. Writing the press release first ensures the team aligns on what success looks like before committing to implementation.
