# APIGW-005 fixture: integrations using default credential behavior vs an
# explicit execution role.

resource "aws_api_gateway_rest_api" "api" {
  name = "cloudspill-test-api"
}

# VULNERABLE: caller-credentials passthrough — backend inherits caller perms.
resource "aws_api_gateway_integration" "passthrough" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  resource_id = "r-fixture"
  http_method = "GET"
  type        = "AWS"
  credentials = "arn:aws:iam::*:user/*"
}

# CLEAN: explicit, dedicated execution role.
resource "aws_api_gateway_integration" "scoped" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  resource_id = "r-fixture"
  http_method = "POST"
  type        = "AWS"
  credentials = "arn:aws:iam::123456789012:role/apigw-exec"
}

# CLEAN: Lambda proxy integration — permission granted via aws_lambda_permission,
# so a missing credentials field is expected, not a finding.
resource "aws_api_gateway_integration" "lambda" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  resource_id = "r-fixture"
  http_method = "PUT"
  type        = "AWS_PROXY"
}
