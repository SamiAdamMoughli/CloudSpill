# APIGW-001 fixture: unauthenticated method + route, plus authorized/preflight
# counterparts that must stay clean.

resource "aws_api_gateway_rest_api" "api" {
  name = "cloudspill-test-api"
}

resource "aws_api_gateway_resource" "res" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  parent_id   = aws_api_gateway_rest_api.api.root_resource_id
  path_part   = "items"
}

# VULNERABLE: REST method with no authorization.
resource "aws_api_gateway_method" "open" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  resource_id   = aws_api_gateway_resource.res.id
  http_method   = "POST"
  authorization = "NONE"
}

# CLEAN: IAM-authorized method.
resource "aws_api_gateway_method" "secured" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  resource_id   = aws_api_gateway_resource.res.id
  http_method   = "GET"
  authorization = "AWS_IAM"
}

# CLEAN: CORS preflight is unauthenticated by design.
resource "aws_api_gateway_method" "preflight" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  resource_id   = aws_api_gateway_resource.res.id
  http_method   = "OPTIONS"
  authorization = "NONE"
}
