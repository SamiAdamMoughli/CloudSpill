# S3-001: Public ACL
# S3-003: No encryption
# S3-004: No logging
# S3-005: No versioning
resource "aws_s3_bucket" "user_uploads" {
  bucket = "${var.project}-user-uploads"
  acl    = "public-read"

  tags = {
    Name        = "${var.project}-user-uploads"
    Environment = var.environment
  }
}

# S3-002: Public access block explicitly disabled
resource "aws_s3_bucket_public_access_block" "user_uploads" {
  bucket = aws_s3_bucket.user_uploads.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Logging bucket — also misconfigured
# S3-003: No encryption
# S3-005: No versioning
resource "aws_s3_bucket" "logs" {
  bucket = "${var.project}-access-logs"

  tags = {
    Name        = "${var.project}-access-logs"
    Environment = var.environment
  }
}

# Application data bucket — public-read-write is catastrophic
# S3-001: Public read-write ACL
# S3-003: No encryption
# S3-004: No logging
# S3-005: No versioning
resource "aws_s3_bucket" "app_data" {
  bucket = "${var.project}-app-data"
  acl    = "public-read-write"

  tags = {
    Name        = "${var.project}-app-data"
    Environment = var.environment
  }
}
