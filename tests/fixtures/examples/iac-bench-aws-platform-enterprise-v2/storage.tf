# Multi-Tier Storage Layout with Embedded Forensic Flaws

# Baseline Compliant Storage Reference
resource "aws_s3_bucket" "audit_compliance_logs" {
  bucket        = "enterprise-platform-compliance-audit-logs"
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "audit_safe" {
  bucket                  = aws_s3_bucket.audit_compliance_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}


# VULNERABILITY SEED: Theme 1 (Forgotten Backup Exposure) & Theme 5 (Recovery Weakness)
resource "aws_s3_bucket" "forgotten_backup_bucket" {
  bucket        = "enterprise-platform-db-backups-archive-historical"
  force_destroy = false
}

resource "aws_s3_bucket_versioning" "backup_versioning" {
  bucket = aws_s3_bucket.forgotten_backup_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Recovery Weakness: No aws_s3_bucket_object_lock_configuration resource applied, enabling ransomware wipeouts
# Exposure Flaw: Missing the public access block resource entirely, alongside a weak bucket policy

resource "aws_s3_bucket_policy" "exposed_backup_policy" {
  bucket = aws_s3_bucket.forgotten_backup_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowHistoricalMigrationAccess"
        Effect    = "Allow"
        Principal = "*" # Critical Public Leak
        Action    = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          aws_s3_bucket.forgotten_backup_bucket.arn,
          "${aws_s3_bucket.forgotten_backup_bucket.arn}/*"
        ]
      }
    ]
  })
}