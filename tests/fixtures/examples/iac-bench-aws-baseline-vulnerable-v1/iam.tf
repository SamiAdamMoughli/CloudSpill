# Baseline workload identity. The managed policy uses jsonencode and is
# least-privilege; the attachment points at a customer-managed policy.

resource "aws_iam_role" "app" {
  name = "${local.name_prefix}-app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "app_baseline" {
  name = "${local.name_prefix}-app-baseline"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "arn:aws:s3:::${local.name_prefix}-data/*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "app_baseline" {
  role       = aws_iam_role.app.name
  policy_arn = aws_iam_policy.app_baseline.arn
}

resource "aws_iam_instance_profile" "app" {
  name = "${local.name_prefix}-app-profile"
  role = aws_iam_role.app.name
}

resource "aws_iam_role_policy" "service_inline" {
  name   = "${local.name_prefix}-service_inline"
  role   = aws_iam_role.app.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject"
      ],
      "Resource": "arn:aws:s3:::${local.name_prefix}-data/*",
      "Condition": {
        "Bool": {
          "aws:MultiFactorAuthPresent": "true"
        }
      }
    }
  ]
}
EOF
}
