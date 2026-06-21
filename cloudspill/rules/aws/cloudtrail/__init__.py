"""AWS CloudTrail security rules.

Enable with: --rules trail

| ID         | Resource type   | Finding                                       | Severity |
|------------|-----------------|-----------------------------------------------|----------|
| TRAIL-001  | aws_cloudtrail  | Trail has logging disabled (enable_logging=false) | HIGH |
| TRAIL-002  | aws_cloudtrail  | Log files not encrypted with a KMS key (no kms_key_id) | MEDIUM |
| TRAIL-003  | aws_cloudtrail  | Log bucket is publicly accessible (public canned ACL) | HIGH |
| TRAIL-004  | aws_cloudtrail  | Not integrated with CloudWatch Logs (no cloud_watch_logs_group_arn) | LOW |
| TRAIL-005  | aws_cloudtrail  | Log bucket has no MFA Delete on versioning      | MEDIUM |

Rules are auto-discovered via @register; no manual imports needed here.
"""
