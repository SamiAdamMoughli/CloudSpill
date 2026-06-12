locals {
  name_prefix = "${var.project_name}-${var.environment}"

  tags = {
    Project   = var.project_name
    Domain    = "aws"
    Scope     = "baseline"
    Variant   = "vulnerable"
    Version   = "v1"
    ManagedBy = "Terraform"
  }
}
