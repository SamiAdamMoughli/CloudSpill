# iac-bench single-control override.
#
# This stack is secure-by-default. The line below names the one control
# degraded for this case (IAM-001 (CRITICAL) — wildcard action on cross-account role).
# The matching resource is rendered with that misconfiguration baked in
# as a literal value so static analysis can detect it.

iam_restrict_cross_account = false
