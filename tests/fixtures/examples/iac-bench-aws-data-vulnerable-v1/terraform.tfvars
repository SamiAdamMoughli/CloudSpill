# iac-bench single-control override.
#
# This stack is secure-by-default. The line below names the one control
# degraded for this case (EC2-004 (MEDIUM) — instance assigned a public IP).
# The matching resource is rendered with that misconfiguration baked in
# as a literal value so static analysis can detect it.

net_enable_subnet_isolation = false
