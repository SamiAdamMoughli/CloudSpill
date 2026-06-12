# iac-bench single-control override.
#
# This stack is secure-by-default. The line below names the one control
# degraded for this case (EC2-001 (CRITICAL) — SSH open to 0.0.0.0/0).
# The matching resource is rendered with that misconfiguration baked in
# as a literal value so static analysis can detect it.

net_restrict_public_management = false
