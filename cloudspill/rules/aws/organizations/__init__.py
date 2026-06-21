"""AWS Organizations security rules.

Covers organization-wide governance: feature set, SCPs, and the optional policy
types. The policy-type rules share the `org_helpers` module and stay quiet on a
consolidated-billing-only org (ORG-003 is the single finding for that case).

Enable with: --rules org

| ID      | Resource type                    | Finding                                     | Severity |
|---------|----------------------------------|---------------------------------------------|----------|
| ORG-001 | aws_organizations_organization   | Service Control Policies not enabled        | MEDIUM   |
| ORG-002 | aws_organizations_policy (SCP)   | SCP allows everything (no guardrail)        | MEDIUM   |
| ORG-003 | aws_organizations_organization   | Consolidated-billing features only          | MEDIUM   |
| ORG-004 | aws_organizations_organization   | Tag policies not enabled                    | LOW      |
| ORG-005 | aws_organizations_organization   | Backup policies not enabled                 | LOW      |
| ORG-006 | aws_organizations_organization   | AI services opt-out policy not enabled      | LOW      |

Rules are auto-discovered via @register; no manual imports needed here.
"""
