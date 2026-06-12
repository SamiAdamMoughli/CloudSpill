# Enterprise Core Identities and Broken Trust Demarcations

# =========================================================================
# VULNERABILITY SEED: Theme 2 (CI/CD Privilege Escalation Path)
# =========================================================================
resource "aws_iam_role" "cicd_deployment_role" {
  name = "enterprise-gh-actions-deploy-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::123456789012:root" # Broad cross-account trust boundary
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "cicd_excessive_permissions" {
  name = "enterprise-migration-ci-policy"
  role = aws_iam_role.cicd_deployment_role.id

  # Critical Finding: Wildcard resources chained with dangerous actions allowing full control
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "DeploymentWildcards"
        Effect = "Allow"
        Action = [
          "iam:CreateRole",
          "iam:AttachRolePolicy",
          "iam:PutRolePolicy",
          "iam:PassRole",
          "ec2:*",
          "s3:*",
          "rds:*"
        ]
        Resource = "*"
      }
    ]
  })
}


# VULNERABILITY SEED: Theme 3 (Forgotten IAM User / Access Path)
resource "aws_iam_user" "legacy_migration_user" {
  name = "legacy-cloud-migration-automation"
  tags = merge(local.tags, { DeprecationDate = "2024-11-12" })
}

resource "aws_iam_access_key" "legacy_active_key" {
  user   = aws_iam_user.legacy_migration_user.name
  status = "Active" # Left active and unrotated
}

resource "aws_iam_user_policy_attachment" "legacy_admin" {
  user       = aws_iam_user.legacy_migration_user.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}