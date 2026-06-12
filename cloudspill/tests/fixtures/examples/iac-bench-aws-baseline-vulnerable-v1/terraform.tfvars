# iac-bench single-control override.
#
# This stack is secure-by-default. The line below names the one control
# degraded for this case (IAM-005 (LOW) — inline policy instead of managed).
# The matching resource is rendered with that misconfiguration baked in
# as a literal value so static analysis can detect it.

iam_restrict_service_wildcards = false
