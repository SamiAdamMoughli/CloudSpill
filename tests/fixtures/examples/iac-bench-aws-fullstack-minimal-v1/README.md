# iac-bench-aws-fullstack-minimal-v1

Minimal fullstack AWS reference stack for IaC SAST benchmarking.

## What it includes
- Multi-AZ VPC with public and private subnets
- Internet gateway and NAT gateway
- Application Load Balancer
- EC2 Auto Scaling Group behind the ALB
- RDS PostgreSQL
- S3 buckets for uploads, logs, and assets
- Utility Lambda function
- Basic IAM and KMS foundation

## Intended use
This repository is designed for static analysis and policy validation exercises.

## Deploy
```bash
terraform init
terraform plan
terraform apply