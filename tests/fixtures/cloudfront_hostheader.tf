# CLOUDFRONT-008 fixture: one behavior forwarding headers without Host, one
# that includes Host in the cache key.

# INFO: forwards User-Agent but not Host.
resource "aws_cloudfront_distribution" "no_host" {
  enabled = true

  default_cache_behavior {
    target_origin_id       = "custom"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]

    forwarded_values {
      query_string = true
      headers      = ["User-Agent"]

      cookies {
        forward = "none"
      }
    }
  }
}

# CLEAN: Host included in the cache key.
resource "aws_cloudfront_distribution" "with_host" {
  enabled = true

  default_cache_behavior {
    target_origin_id       = "custom"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]

    forwarded_values {
      query_string = true
      headers      = ["Host", "User-Agent"]

      cookies {
        forward = "none"
      }
    }
  }
}
