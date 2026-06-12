# CLOUDFRONT-001 fixture: one distribution allowing plain HTTP, one enforcing
# HTTPS on every behavior.

# VULNERABLE: default behavior allows HTTP.
resource "aws_cloudfront_distribution" "insecure" {
  enabled = true

  default_cache_behavior {
    target_origin_id       = "origin1"
    viewer_protocol_policy = "allow-all"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
  }
}

# CLEAN: default redirects to HTTPS, ordered behavior is https-only.
resource "aws_cloudfront_distribution" "secure" {
  enabled = true

  default_cache_behavior {
    target_origin_id       = "origin1"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
  }

  ordered_cache_behavior {
    path_pattern           = "/api/*"
    target_origin_id       = "origin1"
    viewer_protocol_policy = "https-only"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
  }
}
