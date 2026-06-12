# CLOUDFRONT-002 fixture: one distribution with a weak TLS floor, one with a
# TLS 1.2 minimum on a custom certificate.

# VULNERABLE: minimum_protocol_version below TLS 1.2.
resource "aws_cloudfront_distribution" "weak_tls" {
  enabled = true

  viewer_certificate {
    acm_certificate_arn      = "arn:aws:acm:us-east-1:123456789012:certificate/abc"
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.1_2016"
  }
}

# CLEAN: custom certificate with a TLS 1.2 minimum.
resource "aws_cloudfront_distribution" "strong_tls" {
  enabled = true

  viewer_certificate {
    acm_certificate_arn      = "arn:aws:acm:us-east-1:123456789012:certificate/def"
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
}
