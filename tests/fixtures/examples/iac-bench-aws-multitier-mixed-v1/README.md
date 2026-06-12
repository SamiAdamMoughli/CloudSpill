# iac-bench-aws-multitier-mixed-v1

Terraform reference stack for IaC SAST benchmarking.

## Characteristics
- Multi-AZ VPC with public and private subnets
- ALB in front of an ECS application tier
- EC2 Auto Scaling Group as ECS capacity
- RDS PostgreSQL and ElastiCache Redis
- S3 buckets for uploads, logs, assets, and audit artifacts
- Utility Lambda for background processing
- IAM and KMS foundation for platform services

## Deploy
```bash
terraform init
terraform plan
terraform apply
````

## Naming

All resources are derived from `iac-bench-aws-multitier-mixed-v1` for deterministic benchmark runs.
