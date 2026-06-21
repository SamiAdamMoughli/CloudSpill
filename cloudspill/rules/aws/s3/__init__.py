"""AWS S3 security rules.

Covers bucket public exposure (ACL, Block Public Access, policy), encryption,
logging, versioning/MFA-delete, object lock, replication, website hosting, and
TLS/upload enforcement. Many rules understand both the legacy inline
``aws_s3_bucket`` arguments and the modern split sibling resources; the graph is
used to find those siblings. Shared logic lives in the `buckets` helper.

Enable with: --rules s3

| ID     | Resource type                                  | Finding                                  | Severity |
|--------|------------------------------------------------|------------------------------------------|----------|
| S3-001 | aws_s3_bucket / aws_s3_bucket_acl              | Public canned ACL                        | CRITICAL |
| S3-002 | aws_s3_bucket_public_access_block              | Block Public Access not fully enabled    | HIGH     |
| S3-003 | aws_s3_bucket                                  | No server-side encryption configured     | HIGH     |
| S3-004 | aws_s3_bucket                                  | No access logging                        | MEDIUM   |
| S3-005 | aws_s3_bucket                                  | No versioning                            | LOW      |
| S3-006 | aws_s3_bucket                                  | No resource policy                       | LOW      |
| S3-007 | aws_s3_bucket_policy / aws_s3_bucket           | Bucket policy grants wildcard principal  | HIGH     |
| S3-008 | aws_s3_bucket_versioning / aws_s3_bucket       | No MFA delete                            | LOW      |
| S3-009 | aws_s3_bucket                                  | No object lock (WORM)                    | LOW      |
| S3-010 | aws_s3_bucket_policy / aws_s3_bucket           | Policy does not deny unencrypted uploads | LOW      |
| S3-011 | aws_s3_bucket_website_configuration            | Direct S3 website hosting (no CloudFront) | MEDIUM  |
| S3-012 | aws_s3_bucket_replication_configuration        | Replication destination not KMS-encrypted | MEDIUM  |
| S3-013 | aws_s3_bucket_policy / aws_s3_bucket           | Policy does not deny non-TLS requests    | MEDIUM   |

Rules are auto-discovered via @register; no manual imports needed here.
"""
