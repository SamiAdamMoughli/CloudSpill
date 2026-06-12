# Platform Cryptography and Secret Lifecycle Orchestration


# VULNERABILITY SEED: Theme 11 (KMS Policy Mistake)
resource "aws_kms_key" "storage_encryption_key" {
  description             = "Master key for enterprise storage layer encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true # Hard setting configured correctly...
}

resource "aws_kms_key_policy" "overprivileged_kms_policy" {
  key_id = aws_kms_key.storage_encryption_key.id

  # Policy Flaw: Granting structural administrative control blindly to internal account spaces
  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "kms-broad-access"
    Statement = [
      {
        Sid    = "AllowAllActionsToAccountPrincipals"
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })
}


# VULNERABILITY SEED: Theme 7 (Secrets Lifecycle Problem)
resource "aws_secretsmanager_secret" "database_credentials" {
  name                    = "prd-postgres-admin-credentials-legacy"
  recovery_window_in_days = 0 # No defensive recovery buffer
}

# Left active and unchanged without rotation policy schedules attached
resource "aws_secretsmanager_secret_version" "legacy_secret_payload" {
  secret_id     = aws_secretsmanager_secret.database_credentials.id
  secret_string = jsonencode({
    username = "db_root_admin"
    password = "StaticMasterEnterprisePassword2022!"
  })
}