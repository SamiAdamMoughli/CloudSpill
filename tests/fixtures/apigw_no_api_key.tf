# APIGW-006 fixture: a method without API key enforcement, plus a
# key-required method and a CORS preflight that must stay clean.

resource "aws_api_gateway_rest_api" "api" {
  name = "cloudspill-test-api"
}

resource "aws_api_gateway_resource" "res" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  parent_id   = aws_api_gateway_rest_api.api.root_resource_id
  path_part   = "items"
}

# VULNERABLE: no api_key_required (defaults to false).
resource "aws_api_gateway_method" "unmetered" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  resource_id   = aws_api_gateway_resource.res.id
  http_method   = "GET"
  authorization = "AWS_IAM"
}

# CLEAN: API key enforced.
resource "aws_api_gateway_method" "metered" {
  rest_api_id      = aws_api_gateway_rest_api.api.id
  resource_id      = aws_api_gateway_resource.res.id
  http_method      = "POST"
  authorization    = "AWS_IAM"
  api_key_required = true
}

# CLEAN: CORS preflight cannot carry an API key.
resource "aws_api_gateway_method" "preflight" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  resource_id   = aws_api_gateway_resource.res.id
  http_method   = "OPTIONS"
  authorization = "NONE"
}
