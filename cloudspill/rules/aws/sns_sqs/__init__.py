"""AWS SNS / SQS security rules.

Covers messaging-resource exposure (public policies), encryption with CMKs, and
delivery/retention resilience. The two public-policy rules share the `messaging`
helper.

Enable with: --rules sns,sqs

| ID      | Resource type                              | Finding                                  | Severity |
|---------|--------------------------------------------|------------------------------------------|----------|
| SNS-001 | aws_sns_topic_policy / aws_sns_topic       | Topic policy allows public access        | HIGH     |
| SNS-002 | aws_sns_topic                              | Not encrypted with a customer-managed CMK | MEDIUM  |
| SNS-003 | aws_sns_topic_subscription                 | No dead-letter queue (redrive_policy)    | LOW      |
| SQS-001 | aws_sqs_queue_policy / aws_sqs_queue       | Queue policy allows public access        | HIGH     |
| SQS-002 | aws_sqs_queue                              | Not encrypted with a customer-managed CMK | MEDIUM  |
| SQS-003 | aws_sqs_queue                              | Message retention below one day          | LOW      |

Rules are auto-discovered via @register; no manual imports needed here.
"""
