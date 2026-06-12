# APIGW-004 fixture: one REST API with an open wildcard resource policy,
# one whose wildcard is constrained by a Condition (the safe pattern).

# VULNERABLE: Principal "*" with no Condition — anyone can invoke.
resource "aws_api_gateway_rest_api" "open" {
  name = "cloudspill-test-open"

  policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": "*",
        "Action": "execute-api:Invoke",
        "Resource": "*"
      }
    ]
  }
  EOF
}

# CLEAN: wildcard principal narrowed to a VPC endpoint via Condition.
resource "aws_api_gateway_rest_api" "private" {
  name = "cloudspill-test-private"

  policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": "*",
        "Action": "execute-api:Invoke",
        "Resource": "*",
        "Condition": {
          "StringEquals": {
            "aws:SourceVpce": "vpce-1234567890abcdef0"
          }
        }
      }
    ]
  }
  EOF
}
