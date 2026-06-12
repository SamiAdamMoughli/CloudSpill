# iac-bench single-control override.
#
# This stack is secure-by-default. The line below names the one control
# degraded for this case (RDS-001 (CRITICAL) — database publicly accessible).
# The matching resource is rendered with that misconfiguration baked in
# as a literal value so static analysis can detect it.

data_encrypt_transit_mesh = false
