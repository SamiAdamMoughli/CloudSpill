# CLOUDFRONT-003 fixture: one distribution with no WAF, one with a web ACL.

# VULNERABLE: no web_acl_id.
resource "aws_cloudfront_distribution" "unprotected" {
  enabled = true

  default_cache_behavior {
    target_origin_id       = "origin1"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
  }
}

# CLEAN: WAFv2 web ACL attached.
resource "aws_cloudfront_distribution" "protected" {
  enabled     = true
  web_acl_id  = "arn:aws:wafv2:us-east-1:123456789012:global/webacl/main/abc"

  default_cache_behavior {
    target_origin_id       = "origin1"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
  }
}
