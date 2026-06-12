# IAM-001: Wildcard action in policy
resource "aws_iam_policy" "overpermissive" {
  name = "overpermissive-policy"

  policy = <<-EOF
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
  EOF
}

# IAM-002: Wildcard resource with write actions
resource "aws_iam_policy" "write_all" {
  name = "write-all-policy"

  policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": ["s3:PutObject", "s3:DeleteObject"],
        "Resource": "*"
      }
    ]
  }
  EOF
}

# IAM-003: AdministratorAccess attached
resource "aws_iam_role" "admin_role" {
  name = "admin-role"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy_attachment" "admin_attach" {
  role       = aws_iam_role.admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# IAM-005: Inline policy
resource "aws_iam_role_policy" "inline_example" {
  name = "inline-policy"
  role = aws_iam_role.admin_role.id

  policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": ["s3:GetObject"],
        "Resource": "arn:aws:s3:::my-bucket/*"
      }
    ]
  }
  EOF
}
