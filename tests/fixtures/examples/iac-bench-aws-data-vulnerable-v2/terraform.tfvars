# iac-bench single-control override.
#
# This stack is secure-by-default. The line below names the one control
# degraded for this case (RDS-002 (HIGH) — storage encryption disabled).
# The matching resource is rendered with that misconfiguration baked in
# as a literal value so static analysis can detect it.

data_encrypt_volumes = false
