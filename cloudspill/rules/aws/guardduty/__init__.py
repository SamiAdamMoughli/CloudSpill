"""AWS GuardDuty security rules.

Covers the detector itself and its optional protection features. Feature rules
(GD-002..GD-005) understand both the modern aws_guardduty_detector_feature
resource and the legacy datasources block, via the shared `features` helper.

Enable with: --rules gd

| ID      | Resource type                               | Finding                                  | Severity |
|---------|---------------------------------------------|------------------------------------------|----------|
| GD-001  | aws_guardduty_detector                      | Detector disabled (enable = false)       | HIGH     |
| GD-002  | aws_guardduty_detector(_feature)            | S3 protection disabled                    | MEDIUM   |
| GD-003  | aws_guardduty_detector(_feature)            | Malware protection disabled               | MEDIUM   |
| GD-004  | aws_guardduty_detector(_feature)            | Kubernetes (EKS) audit-log protection off | MEDIUM   |
| GD-005  | aws_guardduty_detector_feature              | Runtime monitoring disabled               | MEDIUM   |
| GD-006  | aws_guardduty_organization_configuration    | Members not auto-enabled                  | MEDIUM   |

Rules are auto-discovered via @register; no manual imports needed here.
"""
