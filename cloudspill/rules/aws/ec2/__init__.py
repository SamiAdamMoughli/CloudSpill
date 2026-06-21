"""AWS EC2 / EBS / SSM security rules.

Covers compute instances, their network exposure and metadata service, block
storage (EBS volumes, snapshots, AMIs), and Systems Manager readiness.

Enable with: --rules ec2,ebs,ssm

| ID       | Resource type                                    | Finding                                        | Severity |
|----------|--------------------------------------------------|------------------------------------------------|----------|
| EC2-001  | aws_security_group(_rule) / vpc_..._ingress_rule | SSH (port 22) open to 0.0.0.0/0                 | CRITICAL |
| EC2-002  | aws_security_group(_rule) / vpc_..._ingress_rule | Internet-wide ingress on a non-SSH port        | HIGH     |
| EC2-003  | aws_instance / aws_launch_template               | IMDSv2 not required (http_tokens != required)   | HIGH     |
| EC2-004  | aws_instance                                     | Public IP associated                           | MEDIUM   |
| EC2-005  | aws_instance                                     | Block device not encrypted                     | MEDIUM   |
| EC2-006  | aws_ami / aws_ami_copy                           | AMI backing snapshot not encrypted             | MEDIUM   |
| EC2-007  | aws_instance                                     | Termination protection disabled                | LOW      |
| EC2-008  | aws_instance                                     | Detailed monitoring disabled                   | LOW      |
| EC2-009  | aws_ebs_encryption_by_default                    | Account-wide EBS default encryption disabled   | MEDIUM   |
| EC2-010  | aws_instance                                     | Launched into default VPC / subnet             | LOW      |
| EC2-011  | aws_iam_instance_profile                         | Profile role grants wildcard admin (hopping)   | HIGH     |
| EBS-001  | aws_ebs_volume                                   | Volume not encrypted                           | MEDIUM   |
| EBS-002  | aws_ebs_snapshot_copy                            | Copied snapshot not encrypted                  | MEDIUM   |
| EBS-003  | aws_ami_launch_permission / snapshot perm        | AMI/snapshot shared publicly (group "all")     | HIGH     |
| EBS-004  | aws_ebs_volume                                   | Not covered by an AWS Backup plan              | LOW      |
| SSM-001  | aws_instance                                     | No instance profile for SSM management         | LOW      |

Rules are auto-discovered via @register; no manual imports needed here.
"""
