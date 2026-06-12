# iac-bench single-control override.
#
# This stack is secure-by-default. The line below names the one control
# degraded for this case (S3-002 (HIGH) — public access block disabled).
# The matching resource is rendered with that misconfiguration baked in
# as a literal value so static analysis can detect it.

data_enable_s3_public_block = false
