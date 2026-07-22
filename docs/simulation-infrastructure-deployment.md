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

1. **lichen-sim**: The central simulation coordinator responsible for:
   - Managing time advancement
   - Handling packet propagation and reception
   - Coordinating multiple heterogeneous node types
   - Providing metrics and observability

2. **Implementation Nodes**: Each node type connects to the coordinator:
   - Python: Using `liche-radio` client
   - Rust: Using `lichend` binary
   - C/Zephyr: Using embedded `lichen` stack with Renode bridge
   
3. **Support Services**:
   - Redis/MQTT: For message queuing between nodes (optional)
   - Load balancer: Distributing node connections

## Deployment Methods

### Method 1: Heterogeneous Mesh Testing

This approach uses mixed implementation node types to test cross-platform compatibility.

#### Prerequisites:
- Python (3.9+) on coordinator instance
- Rust compiler for `lichend` on coordinator instance  
- Python virtual environment setup
- Existing Docker image containing simulation services

#### Deployment Steps:
1. Launch coordinator instance with sufficient resources
2. Deploy Python node implementation containers
3. Deploy Rust node implementation containers  
4. Configure node connectivity to coordinator
5. Start all services and monitor metrics

#### Resource Allocation:
- Coordinator: m5.large or m5.xlarge (2vCPU, 8GB RAM minimum)
- Node Instances: t3.medium or t3.large per node (2vCPU, 4GB RAM minimum)
- Additional: t3.small for Redis/MQTT if needed (1vCPU, 2GB RAM)

### Method 2: Renode-Based Zephyr Cluster

This approach emulates Zephyr nodes using Renode peripherals.

#### Prerequisites:
- Renode installation (using provided scripts)
- ARM64 container support for cross-compilation  
- Access to `renode-hetero-fleet.sh` script

#### Deployment Steps:
1. Launch base EC2 instance with Renode support
2. Deploy Renode fleet with `ec2-renode-fleet.sh` command
3. Launch Zephyr node instances using Renode bridge
4. Configure position-based simulation parameters
5. Monitor via logs and metrics exporter

#### Resource Allocation:
- Renode Coordinator: c5.2xlarge or c5.4xlarge (8vCPU, 16GB RAM minimum)
- Zephyr Emulation Instances: m5.large per node (2vCPU, 8GB RAM)
- Storage: EBS 100GB SSD per instance for logs and cache

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

## Deployment Automation

### Example commands:
```bash
# Deploy coordinator node
./ec2-launch-instance.sh --type m5.large --ami ami-12345678 --key my-key

# Deploy Python node fleet
./ec2-hetero-fleet.sh --count 10 --node-type python --region us-east-2

# Deploy Renode Zephyr cluster  
./ec2-renode-fleet.sh --count 5 --region us-west-2

# Deploy with custom parameters
./ec2-deploy-fleet.sh --type c5.2xlarge --count 20 --config simulation-config.yaml
```

### Docker Deployment:
```dockerfile
FROM python:3.9
RUN pip install lichen-sim
COPY ./simulation-scripts/ /app/
CMD ["python", "/app/coordinate.py"]
```

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
