# APIGW-002 fixture: one REST stage left unprotected, one protected by WAF.

resource "aws_api_gateway_rest_api" "api" {
  name = "cloudspill-test-api"
}

# VULNERABLE: no aws_wafv2_web_acl_association references this stage.
resource "aws_api_gateway_stage" "unprotected" {
  stage_name    = "prod"
  rest_api_id   = aws_api_gateway_rest_api.api.id
  deployment_id = "d-fixture"
}

# CLEAN: this stage is bound to a WAF Web ACL via an association resource,
# which produces an incoming edge on the stage node.
resource "aws_api_gateway_stage" "protected" {
  stage_name    = "staging"
  rest_api_id   = aws_api_gateway_rest_api.api.id
  deployment_id = "d-fixture"
}

resource "aws_wafv2_web_acl" "main" {
  name  = "cloudspill-test-acl"
  scope = "REGIONAL"
}

resource "aws_wafv2_web_acl_association" "protect_staging" {
  resource_arn = aws_api_gateway_stage.protected.arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}
