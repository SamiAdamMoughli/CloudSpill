variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "project_name" {
  type    = string
  default = "iac-bench-aws-fullstack-vulnerable"
}

variable "environment" {
  type    = string
  default = "v2"
}

variable "vpc_cidr" {
  type    = string
  default = "10.60.0.0/16"
}

variable "management_cidr" {
  description = "Trusted CIDR permitted to reach management and edge services."
  type        = string
  default     = "10.0.0.0/8"
}

variable "db_password" {
  description = "Database master password. Supply via a secrets backend, not here."
  type        = string
  sensitive   = true
  default     = "replace-via-secrets-manager"
}

# ----------------------------------------------------------------------
# Security control toggles. Each defaults to its most secure posture.
# A case degrades exactly one (see terraform.tfvars); the corresponding
# resource below is rendered with the matching literal misconfiguration.
# ----------------------------------------------------------------------
variable "iam_restrict_cross_account" {
  type    = bool
  default = true
}

variable "iam_enforce_resource_scoping" {
  type    = bool
  default = true
}

variable "iam_access_key_status" {
  type    = string
  default = "Inactive"
}

variable "iam_restrict_service_wildcards" {
  type    = bool
  default = true
}

variable "iam_block_escalation_actions" {
  type    = bool
  default = true
}

variable "net_restrict_public_management" {
  type    = bool
  default = true
}

variable "net_permissive_egress" {
  type    = bool
  default = false
}

variable "net_enable_subnet_isolation" {
  type    = bool
  default = true
}

variable "net_strict_tier_ingress" {
  type    = bool
  default = true
}

variable "net_enforce_alb_tls" {
  type    = bool
  default = true
}

variable "data_encrypt_volumes" {
  type    = bool
  default = true
}

variable "data_restrict_kms_wildcards" {
  type    = bool
  default = true
}

variable "data_enable_s3_public_block" {
  type    = bool
  default = true
}

variable "data_secure_bucket_policy" {
  type    = bool
  default = true
}

variable "data_encrypt_transit_mesh" {
  type    = bool
  default = true
}
