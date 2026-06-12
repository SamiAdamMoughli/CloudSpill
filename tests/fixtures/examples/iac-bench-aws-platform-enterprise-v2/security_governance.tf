# Enterprise Threat Detection and Config Compliance Management Baseline

# GuardDuty Threat Intelligence Engine
resource "aws_guardduty_detector" "primary_detector" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  # MONITORING GAP: Advanced protection scopes left unconfigured or missing configuration sub-blocks
  datasources {
    s3_logs {
      enable = false # CRITICAL GAP: Object access threat tracking disabled on corporate buckets
    }
    kubernetes {
      audit_logs {
        enable = false
      }
    }
  }
}

# AWS Config Resource Recorder
resource "aws_config_configuration_recorder" "governance_recorder" {
  name     = "${local.name_prefix}-global-config-recorder"
  role_arn = aws_iam_role.config_governance_role.arn

  # MONITORING GAP: Incomplete baseline recording strategy
  recording_group {
    all_supported                = false # SAST Target: Enterprise baselines must set this to true
    include_global_resource_types = false
    resource_types               = ["AWS::EC2::Instance", "AWS::EC2::SecurityGroup"] # Missing IAM and S3 scopes
  }
}

resource "aws_config_configuration_recorder_status" "recorder_status" {
  name       = aws_config_configuration_recorder.governance_recorder.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.governance_channel]
}

resource "aws_config_delivery_channel" "governance_channel" {
  name           = "${local.name_prefix}-config-delivery"
  s3_bucket_name = aws_s3_bucket.compliance_archive.id
}

resource "aws_iam_role" "config_governance_role" {
  name = "${local.name_prefix}-aws-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "config.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config_policy" {
  role       = aws_iam_role.config_governance_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRole"
}