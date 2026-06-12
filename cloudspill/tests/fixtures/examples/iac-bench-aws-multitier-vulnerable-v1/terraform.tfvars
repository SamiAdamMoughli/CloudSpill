# iac-bench single-control override.
#
# This stack is secure-by-default. The line below names the one control
# degraded for this case (IAM-003 (HIGH) — AdministratorAccess attached).
# The matching resource is rendered with that misconfiguration baked in
# as a literal value so static analysis can detect it.

iam_block_escalation_actions = false
