"""AWS CloudFront security rules.

Enable with: --rules cloudfront

| ID              | Resource type               | Finding                                  | Severity |
|-----------------|-----------------------------|------------------------------------------|----------|
| CLOUDFRONT-001  | aws_cloudfront_distribution | viewer_protocol_policy allows plain HTTP | HIGH     |
| CLOUDFRONT-002  | aws_cloudfront_distribution | Minimum TLS protocol version too low     | MEDIUM   |
| CLOUDFRONT-003  | aws_cloudfront_distribution | No WAF web ACL attached                  | MEDIUM   |
| CLOUDFRONT-004  | aws_cloudfront_distribution | Access logging disabled                  | LOW      |
| CLOUDFRONT-005  | aws_cloudfront_distribution | S3 origin without origin access control  | MEDIUM   |
| CLOUDFRONT-006  | aws_cloudfront_distribution | No geo restriction configured            | LOW      |
| CLOUDFRONT-007  | aws_cloudfront_distribution | Query string forwarding disabled         | INFO     |
| CLOUDFRONT-008  | aws_cloudfront_distribution | Cache key missing Host header            | INFO     |

Rules are auto-discovered via @register; no manual imports needed here.
"""
