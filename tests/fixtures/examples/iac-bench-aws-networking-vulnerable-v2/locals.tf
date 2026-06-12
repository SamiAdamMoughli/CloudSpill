locals {
  name_prefix = "${var.project_name}-${var.environment}"

  tags = {
    Project   = var.project_name
    Domain    = "aws"
    Scope     = "networking"
    Variant   = "vulnerable"
    Version   = "v2"
    ManagedBy = "Terraform"
  }
}
