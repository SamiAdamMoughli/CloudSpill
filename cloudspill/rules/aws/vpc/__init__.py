"""AWS VPC / networking security rules.

Covers VPC baseline (default VPC, flow logs), subnet/NACL exposure, routing
(internet gateway, peering, default route table), egress, and endpoints. VPC-004
and VPC-006 share the `routes` helper; VPC-002 and VPC-008 use the graph.

Enable with: --rules vpc

| ID      | Resource type                              | Finding                                  | Severity |
|---------|--------------------------------------------|------------------------------------------|----------|
| VPC-001 | aws_default_vpc                            | Default VPC in use                       | LOW      |
| VPC-002 | aws_vpc                                    | No flow logs                             | MEDIUM   |
| VPC-003 | aws_network_acl(_rule)                     | NACL allows all-protocol ingress from 0/0 | MEDIUM  |
| VPC-004 | aws_route / aws_route_table                | Default route to an internet gateway     | MEDIUM   |
| VPC-005 | aws_default_route_table                    | Default route table used for routing     | LOW      |
| VPC-006 | aws_route / aws_route_table                | Broad CIDR routed over peering           | MEDIUM   |
| VPC-007 | aws_eip                                    | Elastic IP attached directly to instance | LOW      |
| VPC-008 | aws_vpc                                    | No S3/DynamoDB gateway endpoint          | LOW      |
| VPC-009 | aws_security_group(_rule)                  | Placeholder/empty description            | LOW      |
| VPC-010 | aws_subnet                                 | Auto-assigns public IPs                  | MEDIUM   |

Rules are auto-discovered via @register; no manual imports needed here.
"""
