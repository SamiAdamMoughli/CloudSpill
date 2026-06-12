# iac-bench single-control override.
#
# This stack is secure-by-default. The line below names the one control
# degraded for this case (EC2-002 (HIGH) — app tier ingress open to 0.0.0.0/0).
# The matching resource is rendered with that misconfiguration baked in
# as a literal value so static analysis can detect it.

net_strict_tier_ingress = false
