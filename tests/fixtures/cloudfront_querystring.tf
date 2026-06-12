# CLOUDFRONT-007 fixture: one behavior that drops query strings, one that
# forwards them.

# INFO: forwarded_values.query_string = false.
resource "aws_cloudfront_distribution" "drops_qs" {
  enabled = true

  default_cache_behavior {
    target_origin_id       = "origin1"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }
  }
}

# CLEAN: query strings forwarded.
resource "aws_cloudfront_distribution" "forwards_qs" {
  enabled = true

  default_cache_behavior {
    target_origin_id       = "origin1"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]

    forwarded_values {
      query_string = true

      cookies {
        forward = "none"
      }
    }
  }
}
