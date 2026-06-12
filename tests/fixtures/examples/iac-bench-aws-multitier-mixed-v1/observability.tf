# Baseline observability and audit output

resource "aws_cloudwatch_log_group" "app" {
  name              = "/app/${local.name_prefix}"
  retention_in_days = 14
}

resource "aws_s3_bucket" "audit" {
  bucket = "${local.name_prefix}-audit"
}

resource "aws_s3_bucket_acl" "audit" {
  bucket = aws_s3_bucket.audit.id
  acl    = "private"
}
