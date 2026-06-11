# Primary data node to test baseline resource parsing
resource "aws_s3_bucket" "vulnerable_bucket" {
    bucket = "cloudspill-test-public-leak-bucket"

    # S3-001: Legacy configuration style establishing a public-read ACL
    acl = "public-read"

    tags = {
        Environment = "test"
        Engine = "cloudspill-fixture"
    }
}

# Downstream dependent resource block to test DAG edge generation
# This implicitly references aws_s3_bucket.vulnerable_bucket.id
resource "aws_s3_bucket_public_access_block" "leaky_policy" {
    bucket = aws_s3_bucket.vulnerable_bucket.id
    # S3-002: Explicitly opening up configuration parameters to trigger alerts
    block_public_acls       = false
    block_public_policy     = false
    ignore_public_acls      = false
    restrict_public_buckets = false
}