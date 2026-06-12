# Lambda execution role — overpermissive
resource "aws_iam_role" "lambda_exec" {
  name = "${var.project}-lambda-exec"

  assume_role_policy = <<-POLICY
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": { "Service": "lambda.amazonaws.com" },
        "Action": "sts:AssumeRole"
      }
    ]
  }
  POLICY

  tags = {
    Name = "${var.project}-lambda-exec"
  }
}

# IAM-001: Wildcard action — full AWS access
resource "aws_iam_policy" "lambda_full_access" {
  name        = "${var.project}-lambda-full-access"
  description = "Overpermissive policy for Lambda"

  policy = <<-POLICY
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*"
      }
    ]
  }
  POLICY
}

# IAM-003: AdministratorAccess attached to the Lambda role
resource "aws_iam_role_policy_attachment" "lambda_admin" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# EC2 instance role — inline policy
resource "aws_iam_role" "ec2_app" {
  name = "${var.project}-ec2-app"

  assume_role_policy = <<-POLICY
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": { "Service": "ec2.amazonaws.com" },
        "Action": "sts:AssumeRole"
      }
    ]
  }
  POLICY
}

# IAM-005: Inline policy (should be managed)
# IAM-002: Wildcard resource with write actions
resource "aws_iam_role_policy" "ec2_inline" {
  name = "${var.project}-ec2-inline-policy"
  role = aws_iam_role.ec2_app.id

  policy = <<-POLICY
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:GetObject",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem"
        ],
        "Resource": "*"
      }
    ]
  }
  POLICY
}

resource "aws_iam_instance_profile" "ec2_app" {
  name = "${var.project}-ec2-app-profile"
  role = aws_iam_role.ec2_app.name
}
