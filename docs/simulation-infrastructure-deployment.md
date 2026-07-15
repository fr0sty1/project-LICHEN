# LICHEN Simulation Infrastructure Deployment Guide

This document provides a comprehensive guide for deploying the LICHEN simulation infrastructure across multiple AWS EC2 instances for large-scale distributed testing.

## Overview

LICHEN's simulation infrastructure allows for large-scale distributed mesh testing across heterogenous implementations (Zephyr C, Rust, and Python). The infrastructure leverages AWS EC2 instances to distribute simulation load and test interoperability between different codebases.

## Architecture

```
┌─────────────────┐    ┌─────────────────┐
│  Coordinator    │    │   Coordinator   │
│  (lichen-sim)   │    │  (lichen-sim)   │
│  Single instance│    │  Single instance│
│                 │    │                 │
│  TCP/REST API   │◄──►│  TCP/REST API   │
└─────────┬───────┘    └─────────┬───────┘
          │                        │
          ▼                        ▼
┌─────────────────┐    ┌─────────────────┐
│  Simulation     │    │  Simulation     │
│  Nodes (Zephyr) │    │  Nodes (Rust/   │
│  C firmware)    │    │  Python)        │
└─────────────────┘    └─────────────────┘
        │                       │
        └───────────────────────┘
                     │
        ┌──────────────────────────┐
        │  AWS EC2 Clusters        │
        │  (100+ nodes per cluster)│
        └──────────────────────────┘
```

## Components

### 1. Simulation Coordinator (lichen-sim)
- **Role**: Centralized simulation control and RF propagation
- **Protocol**: TCP (node port) and REST (API port)
- **Implementation**: Python-based simulation server
- **Ports**: Default `5555` (node port), `5556` (API port)

### 2. Simulation Nodes 
- **Zephyr C Implementation**: Running on Renode emulators in EC2
- **Rust Implementation**: Native Rust nodes
- **Python Implementation**: Native Python nodes

### 3. Cluster Management Scripts
Scripts to automate deployment of simulation clusters:
- `ec2-hetero-fleet.sh`: Deploy heterogeneous mesh testing
- `ec2-renode-fleet.sh`: Deploy Renode-based Zephyr nodes  

## Deployment Methodology

### A. Heterogeneous Mesh Testing (Recommended for Large Scale)

Use the `ec2-hetero-fleet.sh` script for comprehensive large-scale testing:

#### Usage:
```bash
./scripts/ec2-hetero-fleet.sh --zephyr 50 --rust 50 --python 50
./scripts/ec2-hetero-fleet.sh --total 150
```

#### Deployment Process:
1. **Initialize Coordinator**:
   - Launch one simulation coordinator instance
   - Start lichen-sim server with REALTIME time mode

2. **Deploy Implementation Nodes**:
   - Zephyr nodes: EC2 instances with Renode emulators
   - Rust nodes: Local native binaries
   - Python nodes: Local native binaries

3. **Connect Nodes**:
   - All nodes connect to coordinator via TCP
   - Simulated RF propagation handles all node communications

#### Key Considerations:
- **Network Partitioning**: Configure AWS security groups to allow traffic between instances
- **Resource Allocation**: 
  - Coordinator: c7g.xlarge (recommended for high node count)
  - Zephyr clusters: c7g.xlarge instances (20 nodes per instance)
- **Instance Limits**: Account for AWS instance limits when scaling

### B. Renode-Based Zephyr Cluster Deployment

Use `ec2-renode-fleet.sh` for Zephyr firmware testing:

#### Usage:
```bash
./scripts/ec2-renode-fleet.sh --cluster 50
```

#### Architecture:
- **Renode Emulation**: Each EC2 instance runs multiple Renode emulators (20 by default)
- **SX1262 Peripheral**: Simulated LoRa radio for accurate RF modeling
- **Zephyr Integration**: Firmware compiled for specific hardware targets

### C. Mixed Implementation Testing

For testing cross-implementation interoperability:
- Combine Zephyr (C), Rust, and Python simulation nodes
- Run all nodes connected to same coordinator
- Monitor packet exchange across implementations

## Scaling Strategies

### 1. Horizontal Scaling
- Increase node count per cluster
- Deploy multiple coordinator instances in different regions
- Use load balancing for high-throughput simulations

### 2. Vertical Scaling
- Up-size EC2 instance types:
  - Standard: c7g.xlarge (default for medium clusters)  
  - High-performance: c7g.2xlarge or c7g.4xlarge
- Optimize node counts per instance (20-50 nodes per EC2 instance)

### 3. Distributed Simulation Clusters
- Multiple coordinators across regions for geo-distributed testing
- Each coordinator manages limited node count for stability

## AWS Resource Requirements

### Recommended Setup
| Component        | Instance Type | Purpose                    |
|------------------|---------------|----------------------------|
| Coordinator      | c7g.xlarge    | Central simulation control |
| Zephyr Cluster   | c7g.xlarge    | Zephyr node emulation      |
| Compute          | c7g.xlarge    | Rust/Python node execution |

### Security Requirements
- Security Group: Allow TCP ports 22 (SSH), 5555 (node), 5556 (API)
- EBS Volume: Shared storage for simulation data (400GB gp3)
- IAM Role: EC2 instances require access to S3/EBS operations

## Best Practices

### 1. Resource Management
- Monitor EC2 instance CPU and memory usage
- Set appropriate timeouts for long-running simulations
- Implement clean shutdown procedures

### 2. Node Distribution
- Distribute nodes spatially to simulate realistic mesh topologies
- Configure varying node densities for different testing scenarios
- Use consistent positioning for reproducible tests

### 3. Monitoring
- Implement logging for all simulation components
- Monitor packet transmission rates across implementations
- Track connection drops and reconnections

## Automation Commands

### Launch Heterogeneous Fleet:
```bash
./scripts/ec2-hetero-fleet.sh --total 200 --duration 600
```

### Deploy Zephyr Cluster:
```bash
./scripts/ec2-renode-fleet.sh --cluster 100
```

### Monitor Simulation:
```bash
# Check node connectivity
watch -n 5 "curl http://COORDINATOR_IP:5556/sim/TEST_SIM/topology"

# Collect test results
scp ec2-user@COORDINATOR_IP:/tmp/simulation-results/* .
```

## Troubleshooting

### Common Issues:
1. **Node Connection Failures**: Check network security groups  
2. **Instance Limit Exceeded**: Request limits increase from AWS
3. **Simulation Crashes**: Monitor coordinator memory usage
4. **Interoperability Issues**: Verify all nodes use same protocol version

### Debugging Tips:
- Use `--debug` flag for verbose logs
- Monitor lichen-sim logs for connection issues
- Validate hardware-specific implementations with smaller node counts first

## Performance Optimization

### 1. Coordinator Tuning:
- Increase virtual memory for high node counts
- Set appropriate TCP buffer sizes
- Enable connection reuse to reduce overhead

### 2. Node Resource Allocation:
- Optimize Renode configuration for Zephyr nodes
- Adjust Python/GIL threads for multi-core processing
- Tune Rust binary compilation flags for performance

### 3. Network Optimization:
- Use instance types in same availability zone
- Minimize instance-to-instance network latency
- Leverage AWS Direct Connect for geographically-separated coordinators

## Testing Scenarios

### 1. Basic Interoperability
- Test node communications across all implementations
- Measure packet delivery rates between C, Rust, and Python nodes

### 2. Scalability Testing
- Gradually increase node count to find limits
- Monitor performance degradation curves
- Validate stability with 1000+ active nodes

### 3. Failure Injection
- Test resilience with simulated network partitions
- Evaluate convergence after link failures
- Validate recovery mechanisms across implementations

## Maintenance Procedures

### Regular Operations:
1. **Daily Check**: Monitor running instances and resource usage
2. **Weekly Cleanup**: Remove terminated instances and obsolete volumes
3. **Monthly Backup**: Backup simulation data and configurations

### Incident Response:
1. **Emergency Shutdown**: Immediately terminate stuck instances
2. **Recovery Planning**: Restore simulation from backups
3. **Post-mortem Analysis**: Document root causes for future prevention
