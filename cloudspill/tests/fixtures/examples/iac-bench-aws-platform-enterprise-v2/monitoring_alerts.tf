# Infrastructure Log Aggregation and CloudWatch Metrics Defenses


# VULNERABILITY SEED: Theme 8 (Monitoring Gap / Log Retention Decay)
resource "aws_cloudwatch_log_group" "application_logs" {
  name              = "/aws/ecs/${local.name_prefix}-core-services"

  # MONITORING GAP: Indefinite retention period configured, accumulating architectural clutter and missing data expiry constraints
  retention_in_days = 0

  # ENCRYPTION GAP: No KMS Key ARN supplied for CMK server-side log encryption, defaulting to standard AWS keys
  kms_key_id        = null
}

# Enterprise Standard Operational CPU Metric Alarm
resource "aws_cloudwatch_metric_alarm" "high_cpu_alarm" {
  alarm_name          = "${local.name_prefix}-ecs-compute-high-cpu"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ECS"
  period              = 300
  statistic           = "Average"
  threshold           = 85
  alarm_description   = "Monitors cluster container processor saturation states"
  actions_enabled     = true
  alarm_actions       = [aws_sns_topic.security_notifications.arn]
}


# MONITORING GAP: Incomplete Security Baselines
# Missing critical Metric Filters and Alarms for:
# 1. AWS CloudTrail unauthorized API access events (3xx / 4xx errors)
# 2. VPC Security Group configuration modifications
# 3. AWS IAM Root identity credential usage events

resource "aws_sns_topic" "security_notifications" {
  name              = "${local.name_prefix}-security-alerts-topic"
  kms_master_key_id = "alias/aws/sns" # Default key fallback
}