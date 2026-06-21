"""AWS IAM security rules.

Covers identity policies, role trust policies, attachments, credentials, and
account-baseline IAM controls. Policy/trust parsing is shared via the
`policy_docs` helper (built on utils/policy.py).

Enable with: --rules iam

| ID       | Resource type                              | Finding                                        | Severity |
|----------|--------------------------------------------|------------------------------------------------|----------|
| IAM-001  | identity policy                            | Wildcard action (Action "*")                   | CRITICAL |
| IAM-002  | identity policy                            | Wildcard resource + write action               | HIGH     |
| IAM-003  | *_policy_attachment                        | AdministratorAccess / PowerUserAccess attached | HIGH     |
| IAM-004  | identity policy                            | Privileged statement without MFA condition     | MEDIUM   |
| IAM-005  | aws_iam_*_policy (inline)                   | Inline policy instead of managed               | LOW      |
| IAM-006  | aws_iam_role                               | Cross-account trust without external ID        | MEDIUM   |
| IAM-007  | aws_iam_role / identity policy             | Account-root principal used                    | LOW      |
| IAM-008  | aws_iam_access_key                         | Static (long-lived) access key                 | LOW      |
| IAM-009  | aws_iam_account_password_policy            | Weak password policy                           | MEDIUM   |
| IAM-010  | aws_iam_role                               | Trust allows any principal ("*")               | HIGH     |
| IAM-011  | identity policy                            | Wildcard Principal in identity policy          | HIGH     |
| IAM-012  | aws_iam_role / aws_iam_user                | No permissions boundary                        | LOW      |
| IAM-013  | aws_iam_role                               | Non-restrictive trust condition (wildcard)     | MEDIUM   |
| IAM-014  | aws_iam_user_login_profile                 | Long-lived console credential                  | LOW      |
| IAM-015  | identity policy                            | Account-wide security-group modification       | MEDIUM   |
| IAM-016  | aws_account_alternate_contact (SECURITY)   | Security contact incomplete                     | LOW      |
| IAM-017  | aws_iam_role / identity policy             | Account root trusted without MFA               | MEDIUM   |

"identity policy" = aws_iam_policy + inline aws_iam_{role,user,group}_policy.
Rules are auto-discovered via @register; no manual imports needed here.
"""
