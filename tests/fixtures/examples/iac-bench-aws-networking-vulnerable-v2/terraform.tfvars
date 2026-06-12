# iac-bench single-control override.
#
# This stack is secure-by-default. The line below names the one control
# degraded for this case (EC2-002 (HIGH) — plaintext HTTP exposed to 0.0.0.0/0).
# The matching resource is rendered with that misconfiguration baked in
# as a literal value so static analysis can detect it.

net_enforce_alb_tls = false
