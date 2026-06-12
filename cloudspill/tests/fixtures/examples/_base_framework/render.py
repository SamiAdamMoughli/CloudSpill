#!/usr/bin/env python3
"""iac-bench dataset generator.

Single source of truth for the iac-bench AWS benchmark stacks.

Why a generator instead of a Terraform module?
---------------------------------------------
CloudSpill is a *static* HCL reader. It does not resolve `module` blocks,
evaluate `var.*`/conditional expressions, or read `terraform.tfvars`
(verified against cloudspill/parsers/terraform.py). A "secure-by-default
module + one tfvars toggle" design would therefore produce **zero findings**:
the scanner never descends into the module and never evaluates the ternary
that would degrade the control.

So the parameterization lives at *generation time* instead of Terraform
runtime. This script holds one canonical, secure-by-default baseline and a
manifest of 15 cases. For each case it renders a fully self-contained,
deployable Terraform stack that is secure everywhere except for the single
control named by the case — which is baked in as a *literal* misconfiguration
the scanner can actually see. Each case yields exactly one finding.

The single degraded control is still declared as a real (secure-default)
variable and overridden in the case's `terraform.tfvars`, so the dataset
keeps the "exactly one toggle isolates the case" semantics and every stack
stays valid `terraform validate`-able HCL.

Run:  python render.py        # (re)writes every case dir under examples/
"""

from __future__ import annotations

import json
from pathlib import Path

EXAMPLES_DIR = Path(__file__).resolve().parent.parent

# --------------------------------------------------------------------------- #
# Toggle catalogue: every infrastructure control, with its secure default.
# Declared in every stack; each case overrides exactly one in terraform.tfvars.
# --------------------------------------------------------------------------- #
TOGGLES: list[tuple[str, str, str]] = [
    # (name, type, secure_default_literal)
    ("iam_restrict_cross_account", "bool", "true"),
    ("iam_enforce_resource_scoping", "bool", "true"),
    ("iam_access_key_status", "string", '"Inactive"'),
    ("iam_restrict_service_wildcards", "bool", "true"),
    ("iam_block_escalation_actions", "bool", "true"),
    ("net_restrict_public_management", "bool", "true"),
    ("net_permissive_egress", "bool", "false"),
    ("net_enable_subnet_isolation", "bool", "true"),
    ("net_strict_tier_ingress", "bool", "true"),
    ("net_enforce_alb_tls", "bool", "true"),
    ("data_encrypt_volumes", "bool", "true"),
    ("data_restrict_kms_wildcards", "bool", "true"),
    ("data_enable_s3_public_block", "bool", "true"),
    ("data_secure_bucket_policy", "bool", "true"),
    ("data_encrypt_transit_mesh", "bool", "true"),
]

# --------------------------------------------------------------------------- #
# Case manifest: dirname -> the single degraded control + insecure value.
# `vuln` keys the literal misconfiguration injected by the file builders.
# `expects` documents the single rule each case must trip.
# --------------------------------------------------------------------------- #
CASES: list[dict] = [
    # Group 1 — Identity & Access Management
    dict(
        name="iac-bench-aws-platform-vulnerable-v1",
        scope="platform",
        version="v1",
        toggle="iam_restrict_cross_account",
        value="false",
        vuln="iam_restrict_cross_account",
        expects="IAM-001 (CRITICAL) — wildcard action on cross-account role",
    ),
    dict(
        name="iac-bench-aws-fullstack-vulnerable-v1",
        scope="fullstack",
        version="v1",
        toggle="iam_enforce_resource_scoping",
        value="false",
        vuln="iam_enforce_resource_scoping",
        expects="IAM-002 (HIGH) — write action on Resource '*'",
    ),
    dict(
        name="iac-bench-aws-compute-vulnerable-v1",
        scope="compute",
        version="v1",
        toggle="iam_access_key_status",
        value='"Active"',
        vuln="iam_access_key_status",
        expects="IAM-004 (MEDIUM) — active credential policy without MFA",
    ),
    dict(
        name="iac-bench-aws-baseline-vulnerable-v1",
        scope="baseline",
        version="v1",
        toggle="iam_restrict_service_wildcards",
        value="false",
        vuln="iam_restrict_service_wildcards",
        expects="IAM-005 (LOW) — inline policy instead of managed",
    ),
    dict(
        name="iac-bench-aws-multitier-vulnerable-v1",
        scope="multitier",
        version="v1",
        toggle="iam_block_escalation_actions",
        value="false",
        vuln="iam_block_escalation_actions",
        expects="IAM-003 (HIGH) — AdministratorAccess attached",
    ),
    # Group 2 — Network Topology & Segmentation
    dict(
        name="iac-bench-aws-networking-vulnerable-v1",
        scope="networking",
        version="v1",
        toggle="net_restrict_public_management",
        value="false",
        vuln="net_restrict_public_management",
        expects="EC2-001 (CRITICAL) — SSH open to 0.0.0.0/0",
    ),
    dict(
        name="iac-bench-aws-edge-vulnerable-v1",
        scope="edge",
        version="v1",
        toggle="net_permissive_egress",
        value="true",
        vuln="net_permissive_egress",
        expects="EC2-002 (HIGH) — unrestricted ingress to 0.0.0.0/0",
    ),
    dict(
        name="iac-bench-aws-data-vulnerable-v1",
        scope="data",
        version="v1",
        toggle="net_enable_subnet_isolation",
        value="false",
        vuln="net_enable_subnet_isolation",
        expects="EC2-004 (MEDIUM) — instance assigned a public IP",
    ),
    dict(
        name="iac-bench-aws-platform-vulnerable-v2",
        scope="platform",
        version="v2",
        toggle="net_strict_tier_ingress",
        value="false",
        vuln="net_strict_tier_ingress",
        expects="EC2-002 (HIGH) — app tier ingress open to 0.0.0.0/0",
    ),
    dict(
        name="iac-bench-aws-networking-vulnerable-v2",
        scope="networking",
        version="v2",
        toggle="net_enforce_alb_tls",
        value="false",
        vuln="net_enforce_alb_tls",
        expects="EC2-002 (HIGH) — plaintext HTTP exposed to 0.0.0.0/0",
    ),
    # Group 3 — Data Protection & Cryptography
    dict(
        name="iac-bench-aws-data-vulnerable-v2",
        scope="data",
        version="v2",
        toggle="data_encrypt_volumes",
        value="false",
        vuln="data_encrypt_volumes",
        expects="RDS-002 (HIGH) — storage encryption disabled",
    ),
    dict(
        name="iac-bench-aws-baseline-vulnerable-v2",
        scope="baseline",
        version="v2",
        toggle="data_restrict_kms_wildcards",
        value="false",
        vuln="data_restrict_kms_wildcards",
        expects="IAM-002 (HIGH) — KMS write action on Resource '*'",
    ),
    dict(
        name="iac-bench-aws-fullstack-vulnerable-v2",
        scope="fullstack",
        version="v2",
        toggle="data_enable_s3_public_block",
        value="false",
        vuln="data_enable_s3_public_block",
        expects="S3-002 (HIGH) — public access block disabled",
    ),
    dict(
        name="iac-bench-aws-platform-vulnerable-v3",
        scope="platform",
        version="v3",
        toggle="data_secure_bucket_policy",
        value="false",
        vuln="data_secure_bucket_policy",
        expects="S3-001 (CRITICAL) — bucket ACL public-read",
    ),
    dict(
        name="iac-bench-aws-multitier-vulnerable-v2",
        scope="multitier",
        version="v2",
        toggle="data_encrypt_transit_mesh",
        value="false",
        vuln="data_encrypt_transit_mesh",
        expects="RDS-001 (CRITICAL) — database publicly accessible",
    ),
]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _heredoc_policy(
    tf_name: str, actions, resource: str, *, mfa: bool, inline_role: str | None = None
) -> str:
    """Render an IAM policy resource with a literal heredoc JSON document.

    Heredoc (not jsonencode) so CloudSpill's parser can read the statements.
    `mfa=True` adds an MFA condition, which suppresses IAM-004 so the case
    trips only its intended rule.
    """
    statement: dict = {"Effect": "Allow", "Action": actions, "Resource": resource}
    if mfa:
        statement["Condition"] = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
    document = json.dumps({"Version": "2012-10-17", "Statement": [statement]}, indent=2)
    if inline_role:
        return (
            f'resource "aws_iam_role_policy" "{tf_name}" {{\n'
            f'  name   = "${{local.name_prefix}}-{tf_name}"\n'
            f"  role   = {inline_role}\n"
            f"  policy = <<EOF\n{document}\nEOF\n}}\n"
        )
    return (
        f'resource "aws_iam_policy" "{tf_name}" {{\n'
        f'  name   = "${{local.name_prefix}}-{tf_name}"\n'
        f"  policy = <<EOF\n{document}\nEOF\n}}\n"
    )


# --------------------------------------------------------------------------- #
# Static files (identical across every case)
# --------------------------------------------------------------------------- #
VERSIONS_TF = """\
terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = local.tags
  }
}
"""

NETWORK_TF = """\
# Core network fabric. None of these constructs carry a security control
# the benchmark toggles; they exist so the stack is a realistic, deployable
# topology that the scanned resources can attach to.

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${local.name_prefix}-vpc"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${local.name_prefix}-igw"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 0)
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false

  tags = {
    Name = "${local.name_prefix}-public"
    Tier = "public"
  }
}

resource "aws_subnet" "private" {
  count = 2

  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index + 10)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = false

  tags = {
    Name = "${local.name_prefix}-private-${count.index + 1}"
    Tier = "private"
  }
}
"""

OUTPUTS_TF = """\
output "vpc_id" {
  value = aws_vpc.main.id
}

output "data_bucket" {
  value = aws_s3_bucket.data.id
}

output "db_endpoint" {
  value = aws_db_instance.main.endpoint
}
"""


# --------------------------------------------------------------------------- #
# Per-case files
# --------------------------------------------------------------------------- #
def variables_tf(case: dict) -> str:
    lines = [
        'variable "aws_region" {',
        "  type    = string",
        '  default = "us-east-1"',
        "}",
        "",
        'variable "project_name" {',
        "  type    = string",
        f'  default = "iac-bench-aws-{case["scope"]}-vulnerable"',
        "}",
        "",
        'variable "environment" {',
        "  type    = string",
        f'  default = "{case["version"]}"',
        "}",
        "",
        'variable "vpc_cidr" {',
        "  type    = string",
        '  default = "10.60.0.0/16"',
        "}",
        "",
        'variable "management_cidr" {',
        '  description = "Trusted CIDR permitted to reach management and edge services."',
        "  type        = string",
        '  default     = "10.0.0.0/8"',
        "}",
        "",
        'variable "db_password" {',
        '  description = "Database master password. Supply via a secrets backend, not here."',
        "  type        = string",
        "  sensitive   = true",
        '  default     = "replace-via-secrets-manager"',
        "}",
        "",
        "# ----------------------------------------------------------------------",
        "# Security control toggles. Each defaults to its most secure posture.",
        "# A case degrades exactly one (see terraform.tfvars); the corresponding",
        "# resource below is rendered with the matching literal misconfiguration.",
        "# ----------------------------------------------------------------------",
    ]
    for name, vtype, default in TOGGLES:
        lines += [
            f'variable "{name}" {{',
            f"  type    = {vtype}",
            f"  default = {default}",
            "}",
            "",
        ]
    return "\n".join(lines).rstrip() + "\n"


def locals_tf(case: dict) -> str:
    return (
        "locals {\n"
        '  name_prefix = "${var.project_name}-${var.environment}"\n'
        "\n"
        "  tags = {\n"
        "    Project   = var.project_name\n"
        '    Domain    = "aws"\n'
        f'    Scope     = "{case["scope"]}"\n'
        '    Variant   = "vulnerable"\n'
        f'    Version   = "{case["version"]}"\n'
        '    ManagedBy = "Terraform"\n'
        "  }\n"
        "}\n"
    )


def security_tf(vuln: str) -> str:
    # Baseline: management/edge access scoped to var.management_cidr (the scanner
    # sees "${var.management_cidr}", never 0.0.0.0/0). A vuln swaps in a literal
    # open CIDR on exactly one security group.
    admin_ssh_cidr = (
        '["0.0.0.0/0"]'
        if vuln == "net_restrict_public_management"
        else "[var.management_cidr]"
    )
    app_ingress = (
        (
            "  ingress {\n"
            '    description = "App port exposed to the internet"\n'
            "    from_port   = 8080\n"
            "    to_port     = 8080\n"
            '    protocol    = "tcp"\n'
            '    cidr_blocks = ["0.0.0.0/0"]\n'
            "  }\n"
        )
        if vuln == "net_strict_tier_ingress"
        else (
            "  ingress {\n"
            '    description     = "App port from the load balancer only"\n'
            "    from_port       = 8080\n"
            "    to_port         = 8080\n"
            '    protocol        = "tcp"\n'
            "    security_groups = [aws_security_group.alb.id]\n"
            "  }\n"
        )
    )
    alb_extra = (
        (
            "\n"
            "  ingress {\n"
            '    description = "Plaintext HTTP exposed to the internet"\n'
            "    from_port   = 80\n"
            "    to_port     = 80\n"
            '    protocol    = "tcp"\n'
            '    cidr_blocks = ["0.0.0.0/0"]\n'
            "  }\n"
        )
        if vuln == "net_enforce_alb_tls"
        else ""
    )
    permissive_sg = (
        (
            "\n"
            'resource "aws_security_group" "mesh" {\n'
            '  name        = "${local.name_prefix}-mesh-sg"\n'
            '  description = "Service mesh data plane"\n'
            "  vpc_id      = aws_vpc.main.id\n"
            "\n"
            "  ingress {\n"
            '    description = "Unrestricted mesh ingress"\n'
            "    from_port   = 0\n"
            "    to_port     = 65535\n"
            '    protocol    = "tcp"\n'
            '    cidr_blocks = ["0.0.0.0/0"]\n'
            "  }\n"
            "\n"
            "  egress {\n"
            "    from_port   = 0\n"
            "    to_port     = 0\n"
            '    protocol    = "-1"\n'
            '    cidr_blocks = ["0.0.0.0/0"]\n'
            "  }\n"
            "}\n"
        )
        if vuln == "net_permissive_egress"
        else ""
    )

    return (
        "# Security groups. Edge and management ingress is scoped to the trusted\n"
        "# management CIDR; tiers reference one another rather than opening CIDRs.\n"
        "\n"
        'resource "aws_security_group" "alb" {\n'
        '  name        = "${local.name_prefix}-alb-sg"\n'
        '  description = "Public application load balancer"\n'
        "  vpc_id      = aws_vpc.main.id\n"
        "\n"
        "  ingress {\n"
        '    description = "HTTPS from trusted networks"\n'
        "    from_port   = 443\n"
        "    to_port     = 443\n"
        '    protocol    = "tcp"\n'
        "    cidr_blocks = [var.management_cidr]\n"
        "  }\n"
        f"{alb_extra}"
        "\n"
        "  egress {\n"
        "    from_port   = 0\n"
        "    to_port     = 0\n"
        '    protocol    = "-1"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        "  }\n"
        "}\n"
        "\n"
        'resource "aws_security_group" "app" {\n'
        '  name        = "${local.name_prefix}-app-sg"\n'
        '  description = "Application tier"\n'
        "  vpc_id      = aws_vpc.main.id\n"
        "\n"
        f"{app_ingress}"
        "\n"
        "  egress {\n"
        "    from_port   = 0\n"
        "    to_port     = 0\n"
        '    protocol    = "-1"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        "  }\n"
        "}\n"
        "\n"
        'resource "aws_security_group" "admin" {\n'
        '  name        = "${local.name_prefix}-admin-sg"\n'
        '  description = "Administrative / break-glass access"\n'
        "  vpc_id      = aws_vpc.main.id\n"
        "\n"
        "  ingress {\n"
        '    description = "SSH from trusted networks"\n'
        "    from_port   = 22\n"
        "    to_port     = 22\n"
        '    protocol    = "tcp"\n'
        f"    cidr_blocks = {admin_ssh_cidr}\n"
        "  }\n"
        "\n"
        "  egress {\n"
        "    from_port   = 0\n"
        "    to_port     = 0\n"
        '    protocol    = "-1"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        "  }\n"
        "}\n"
        f"{permissive_sg}"
    )


def compute_tf(vuln: str) -> str:
    public_ip = "true" if vuln == "net_enable_subnet_isolation" else "false"
    return (
        'data "aws_ami" "al2023" {\n'
        "  most_recent = true\n"
        '  owners      = ["amazon"]\n'
        "\n"
        "  filter {\n"
        '    name   = "name"\n'
        '    values = ["al2023-ami-*-x86_64"]\n'
        "  }\n"
        "}\n"
        "\n"
        'resource "aws_instance" "app" {\n'
        "  ami                         = data.aws_ami.al2023.id\n"
        '  instance_type               = "t3.micro"\n'
        "  subnet_id                   = aws_subnet.private[0].id\n"
        f"  associate_public_ip_address = {public_ip}\n"
        "  vpc_security_group_ids      = [aws_security_group.app.id]\n"
        "  iam_instance_profile        = aws_iam_instance_profile.app.name\n"
        "\n"
        "  metadata_options {\n"
        '    http_endpoint = "enabled"\n'
        '    http_tokens   = "required"\n'
        "  }\n"
        "\n"
        "  root_block_device {\n"
        "    encrypted = true\n"
        "  }\n"
        "\n"
        "  tags = {\n"
        '    Name = "${local.name_prefix}-app"\n'
        '    Role = "application"\n'
        "  }\n"
        "}\n"
    )


def iam_tf(vuln: str) -> str:
    # Baseline role + least-privilege managed policy via jsonencode. jsonencode
    # is opaque to the static parser, so the baseline policy is invisible to the
    # rule engine (clean). Vuln policies use literal heredoc JSON to be seen.
    baseline = (
        "# Baseline workload identity. The managed policy uses jsonencode and is\n"
        "# least-privilege; the attachment points at a customer-managed policy.\n"
        "\n"
        'resource "aws_iam_role" "app" {\n'
        '  name = "${local.name_prefix}-app-role"\n'
        "\n"
        "  assume_role_policy = jsonencode({\n"
        '    Version = "2012-10-17"\n'
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Principal = { Service = "ec2.amazonaws.com" }\n'
        '      Action    = "sts:AssumeRole"\n'
        "    }]\n"
        "  })\n"
        "}\n"
        "\n"
        'resource "aws_iam_policy" "app_baseline" {\n'
        '  name = "${local.name_prefix}-app-baseline"\n'
        "\n"
        "  policy = jsonencode({\n"
        '    Version = "2012-10-17"\n'
        "    Statement = [{\n"
        '      Effect   = "Allow"\n'
        '      Action   = ["s3:GetObject"]\n'
        '      Resource = "arn:aws:s3:::${local.name_prefix}-data/*"\n'
        "    }]\n"
        "  })\n"
        "}\n"
        "\n"
        'resource "aws_iam_role_policy_attachment" "app_baseline" {\n'
        "  role       = aws_iam_role.app.name\n"
        "  policy_arn = aws_iam_policy.app_baseline.arn\n"
        "}\n"
        "\n"
        'resource "aws_iam_instance_profile" "app" {\n'
        '  name = "${local.name_prefix}-app-profile"\n'
        "  role = aws_iam_role.app.name\n"
        "}\n"
    )

    extra = ""
    if vuln == "iam_restrict_cross_account":
        extra = "\n" + _heredoc_policy(
            "cross_account",
            "*",
            "arn:aws:iam::210987654321:role/partner-access",
            mfa=True,
        )
    elif vuln == "iam_enforce_resource_scoping":
        extra = "\n" + _heredoc_policy(
            "broad_scope", ["s3:PutObject", "s3:DeleteObject"], "*", mfa=True
        )
    elif vuln == "iam_access_key_status":
        # Active long-lived credential whose policy lacks an MFA condition.
        extra = "\n" + _heredoc_policy(
            "compute_keys",
            ["s3:GetObject", "s3:ListBucket"],
            "arn:aws:s3:::${local.name_prefix}-data",
            mfa=False,
        )
    elif vuln == "iam_restrict_service_wildcards":
        # Inline (unmanaged) policy — trips IAM-005; MFA keeps IAM-004 quiet.
        extra = "\n" + _heredoc_policy(
            "service_inline",
            ["s3:GetObject"],
            "arn:aws:s3:::${local.name_prefix}-data/*",
            mfa=True,
            inline_role="aws_iam_role.app.id",
        )
    elif vuln == "iam_block_escalation_actions":
        extra = (
            "\n"
            'resource "aws_iam_role_policy_attachment" "escalation" {\n'
            "  role       = aws_iam_role.app.name\n"
            '  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"\n'
            "}\n"
        )
    elif vuln == "data_restrict_kms_wildcards":
        extra = "\n" + _heredoc_policy(
            "kms_broad", ["kms:PutKeyPolicy", "kms:ScheduleKeyDeletion"], "*", mfa=True
        )

    return baseline + extra


def storage_tf(vuln: str) -> str:
    acl = '"public-read"' if vuln == "data_secure_bucket_policy" else '"private"'
    block_acls = "false" if vuln == "data_enable_s3_public_block" else "true"
    return (
        'resource "aws_s3_bucket" "data" {\n'
        '  bucket = "${local.name_prefix}-data"\n'
        f"  acl    = {acl}\n"
        "\n"
        "  server_side_encryption_configuration {\n"
        "    rule {\n"
        "      apply_server_side_encryption_by_default {\n"
        '        sse_algorithm = "AES256"\n'
        "      }\n"
        "    }\n"
        "  }\n"
        "\n"
        "  logging {\n"
        '    target_bucket = "${local.name_prefix}-logs"\n'
        '    target_prefix = "s3/"\n'
        "  }\n"
        "\n"
        "  versioning {\n"
        "    enabled = true\n"
        "  }\n"
        "\n"
        "  tags = local.tags\n"
        "}\n"
        "\n"
        'resource "aws_s3_bucket_public_access_block" "data" {\n'
        "  bucket = aws_s3_bucket.data.id\n"
        "\n"
        f"  block_public_acls       = {block_acls}\n"
        "  block_public_policy     = true\n"
        "  ignore_public_acls      = true\n"
        "  restrict_public_buckets = true\n"
        "}\n"
    )


def database_tf(vuln: str) -> str:
    encrypted = "false" if vuln == "data_encrypt_volumes" else "true"
    public = "true" if vuln == "data_encrypt_transit_mesh" else "false"
    return (
        'resource "aws_db_subnet_group" "main" {\n'
        '  name       = "${local.name_prefix}-db-subnets"\n'
        "  subnet_ids = aws_subnet.private[*].id\n"
        "\n"
        "  tags = local.tags\n"
        "}\n"
        "\n"
        'resource "aws_db_instance" "main" {\n'
        '  identifier              = "${local.name_prefix}-db"\n'
        '  engine                  = "postgres"\n'
        '  engine_version          = "16"\n'
        '  instance_class          = "db.t3.micro"\n'
        "  allocated_storage       = 20\n"
        '  db_name                 = "appdb"\n'
        '  username                = "appadmin"\n'
        "  password                = var.db_password\n"
        "  db_subnet_group_name    = aws_db_subnet_group.main.name\n"
        "  vpc_security_group_ids   = [aws_security_group.app.id]\n"
        f"  publicly_accessible     = {public}\n"
        f"  storage_encrypted       = {encrypted}\n"
        "  deletion_protection     = true\n"
        "  backup_retention_period = 7\n"
        "  skip_final_snapshot     = false\n"
        "\n"
        "  tags = local.tags\n"
        "}\n"
    )


def tfvars(case: dict) -> str:
    return (
        "# iac-bench single-control override.\n"
        "#\n"
        "# This stack is secure-by-default. The line below names the one control\n"
        f'# degraded for this case ({case["expects"]}).\n'
        "# The matching resource is rendered with that misconfiguration baked in\n"
        "# as a literal value so static analysis can detect it.\n"
        "\n"
        f'{case["toggle"]} = {case["value"]}\n'
    )


def readme(case: dict) -> str:
    return (
        f'# {case["name"]}\n'
        "\n"
        "AWS Terraform benchmark stack for IaC SAST evaluation, generated from\n"
        "the canonical `_base_framework` template.\n"
        "\n"
        "## Naming\n"
        "\n"
        "`iac-bench-<domain>-<scope>-<variant>-v<version>` — see\n"
        "[CONTRIBUTING.md](../../../../../CONTRIBUTING.md#iac-bench-naming-convention).\n"
        "\n"
        f"- **domain:** aws\n"
        f'- **scope:** {case["scope"]}\n'
        f"- **variant:** vulnerable\n"
        f'- **version:** {case["version"]}\n'
        "\n"
        "## Degraded control\n"
        "\n"
        f"| Toggle | Value | Expected finding |\n"
        f"|---|---|---|\n"
        f'| `{case["toggle"]}` | `{case["value"]}` | {case["expects"]} |\n'
        "\n"
        "Every other control is at its secure default, so a conforming scanner\n"
        "reports **exactly one** finding for this stack.\n"
        "\n"
        "## Scan\n"
        "\n"
        "```bash\n"
        f"cloudspill .\n"
        "```\n"
    )


FILES = {
    "versions.tf": lambda c: VERSIONS_TF,
    "variables.tf": variables_tf,
    "locals.tf": locals_tf,
    "network.tf": lambda c: NETWORK_TF,
    "security.tf": lambda c: security_tf(c["vuln"]),
    "compute.tf": lambda c: compute_tf(c["vuln"]),
    "iam.tf": lambda c: iam_tf(c["vuln"]),
    "storage.tf": lambda c: storage_tf(c["vuln"]),
    "database.tf": lambda c: database_tf(c["vuln"]),
    "outputs.tf": lambda c: OUTPUTS_TF,
    "terraform.tfvars": tfvars,
    "README.md": readme,
}


def render() -> None:
    for case in CASES:
        case_dir = EXAMPLES_DIR / case["name"]
        case_dir.mkdir(parents=True, exist_ok=True)
        for filename, builder in FILES.items():
            content = builder(case)
            (case_dir / filename).write_text(content, encoding="utf-8")
        print(f"rendered {case['name']:42s} -> {case['expects']}")


if __name__ == "__main__":
    render()
    print(f"\n{len(CASES)} cases written under {EXAMPLES_DIR}")
