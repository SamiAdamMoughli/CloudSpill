# APIGW-003 fixture: one stage without access logging, one with it configured.

resource "aws_api_gateway_rest_api" "api" {
  name = "cloudspill-test-api"
}

resource "aws_cloudwatch_log_group" "api" {
  name = "/aws/apigw/cloudspill-test"
}

# VULNERABLE: no access_log_settings block.
resource "aws_api_gateway_stage" "unlogged" {
  stage_name    = "prod"
  rest_api_id   = aws_api_gateway_rest_api.api.id
  deployment_id = "d-fixture"
}

# CLEAN: access logging delivered to a CloudWatch log group.
resource "aws_api_gateway_stage" "logged" {
  stage_name    = "staging"
  rest_api_id   = aws_api_gateway_rest_api.api.id
  deployment_id = "d-fixture"

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api.arn
    format          = "$context.requestId $context.status"
  }
}
