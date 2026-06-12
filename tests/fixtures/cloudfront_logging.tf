# CLOUDFRONT-004 fixture: one distribution without logging, one with it.

# VULNERABLE: no logging_config block.
resource "aws_cloudfront_distribution" "unlogged" {
  enabled = true

  default_cache_behavior {
    target_origin_id       = "origin1"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
  }
}

# CLEAN: access logs delivered to an S3 bucket.
resource "aws_cloudfront_distribution" "logged" {
  enabled = true

  logging_config {
    bucket          = "my-logs.s3.amazonaws.com"
    include_cookies = false
    prefix          = "cf/"
  }

  default_cache_behavior {
    target_origin_id       = "origin1"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
  }
}
