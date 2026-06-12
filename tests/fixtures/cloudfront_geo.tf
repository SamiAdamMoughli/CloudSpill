# CLOUDFRONT-006 fixture: one distribution with geo restriction set to none,
# one with an active whitelist.

# VULNERABLE: geo_restriction set to none.
resource "aws_cloudfront_distribution" "unrestricted" {
  enabled = true

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  default_cache_behavior {
    target_origin_id       = "origin1"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
  }
}

# CLEAN: whitelist of served countries.
resource "aws_cloudfront_distribution" "restricted" {
  enabled = true

  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["US", "CA", "GB"]
    }
  }

  default_cache_behavior {
    target_origin_id       = "origin1"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
  }
}
