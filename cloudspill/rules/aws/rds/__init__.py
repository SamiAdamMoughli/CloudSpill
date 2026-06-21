"""AWS RDS security rules.

Covers aws_db_instance and aws_rds_cluster, plus parameter groups and subnet
groups. RDS-007 and RDS-010 use the resource graph.

Enable with: --rules rds

| ID      | Resource type                              | Finding                                  | Severity |
|---------|--------------------------------------------|------------------------------------------|----------|
| RDS-001 | aws_db_instance                            | Publicly accessible                      | CRITICAL |
| RDS-002 | aws_db_instance / aws_rds_cluster          | Storage not encrypted                    | HIGH     |
| RDS-003 | aws_db_instance / aws_rds_cluster          | No deletion protection                   | MEDIUM   |
| RDS-004 | aws_db_instance / aws_rds_cluster          | Automated backups disabled (retention 0) | LOW      |
| RDS-005 | aws_db_instance                            | Enhanced monitoring disabled             | LOW      |
| RDS-006 | aws_db_instance                            | Not Multi-AZ                             | LOW      |
| RDS-007 | aws_db_instance                            | No cross-region backup replication       | LOW      |
| RDS-008 | aws_db_instance / aws_rds_cluster          | Master password set as a literal         | HIGH     |
| RDS-009 | aws_db(_cluster)_parameter_group           | SSL/TLS enforcement disabled             | MEDIUM   |
| RDS-010 | aws_db_subnet_group                        | Spans a public subnet                    | MEDIUM   |

Rules are auto-discovered via @register; no manual imports needed here.
"""
