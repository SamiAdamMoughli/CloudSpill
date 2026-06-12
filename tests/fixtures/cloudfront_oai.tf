# CLOUDFRONT-005 fixture: an S3 origin with no OAC/OAI, plus an OAC-protected
# S3 origin and a custom (non-S3) origin that must stay clean.

# VULNERABLE: S3 origin with an empty origin_access_identity and no OAC.
resource "aws_cloudfront_distribution" "exposed_s3" {
  enabled = true

  origin {
    domain_name = "assets.s3.amazonaws.com"
    origin_id   = "s3origin"

    s3_origin_config {
      origin_access_identity = ""
    }
  }

  default_cache_behavior {
    target_origin_id       = "s3origin"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
  }
}

# CLEAN: S3 origin protected by Origin Access Control.
resource "aws_cloudfront_distribution" "oac_s3" {
  enabled = true

  origin {
    domain_name              = "assets.s3.amazonaws.com"
    origin_id                = "s3origin"
    origin_access_control_id = "E1EXAMPLEOAC"
  }

  default_cache_behavior {
    target_origin_id       = "s3origin"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
  }
}

# CLEAN: custom (non-S3) origin — OAC/OAI does not apply.
resource "aws_cloudfront_distribution" "custom" {
  enabled = true

  origin {
    domain_name = "api.example.com"
    origin_id   = "custom"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id       = "custom"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
  }
}
