# iac-bench single-control override.
#
# This stack is secure-by-default. The line below names the one control
# degraded for this case (S3-001 (CRITICAL) — bucket ACL public-read).
# The matching resource is rendered with that misconfiguration baked in
# as a literal value so static analysis can detect it.

data_secure_bucket_policy = false
