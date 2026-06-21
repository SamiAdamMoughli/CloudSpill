"""AWS DynamoDB security rules.

Enable with: --rules ddb

| ID       | Resource type                  | Finding                                      | Severity |
|----------|--------------------------------|----------------------------------------------|----------|
| DDB-001  | aws_dynamodb_table             | Point-in-time recovery disabled              | MEDIUM   |
| DDB-002  | aws_dynamodb_table             | Not encrypted with a customer-managed CMK    | MEDIUM   |
| DDB-003  | aws_dynamodb_table             | No TTL configured                            | LOW      |
| DDB-004  | aws_dynamodb_table             | Streams disabled                             | LOW      |
| DDB-005  | aws_dynamodb_table             | GSIs present but no customer-managed CMK     | MEDIUM   |
| DDB-006  | aws_dynamodb_resource_policy   | Resource policy grants public API access     | HIGH     |

Rules are auto-discovered via @register; no manual imports needed here.
"""
