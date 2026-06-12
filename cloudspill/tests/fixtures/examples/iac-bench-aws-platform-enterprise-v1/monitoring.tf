# Audit trails and Visibility Architectures


# VULNERABILITY SEED: Theme 8 (Monitoring Gap)
resource "aws_cloudtrail" "enterprise_tracker" {
  name                          = "platform-governance-trail"
  s3_bucket_name                = "enterprise-platform-compliance-audit-logs"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = false # Monitoring Gap: Allows silent manipulation of log trails

  # Monitoring Gap: Fails to capture event selectors for S3 Object mutations or Lambda invokes
  # No dynamic insight configurations or anomaly notifications attached.
}