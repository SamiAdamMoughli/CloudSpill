"""AWS API Gateway security rules.

Covers both REST APIs (API Gateway v1, ``aws_api_gateway_*``) and HTTP/
WebSocket APIs (API Gateway v2, ``aws_apigatewayv2_*``).

Enable with: --rules apigw

| ID         | Resource type                               | Finding                                     | Severity |
|------------|---------------------------------------------|---------------------------------------------|----------|
| APIGW-001  | aws_api_gateway_method / apigatewayv2_route | Method/route has no authorization           | HIGH     |
| APIGW-002  | aws_api_gateway_stage                       | No WAF web ACL attached (REST only)         | MEDIUM   |
| APIGW-003  | aws_api_gateway_stage / aws_apigatewayv2_stage | Access logging disabled                  | MEDIUM   |
| APIGW-004  | aws_api_gateway_rest_api                     | Resource policy grants wildcard principal (no condition) | HIGH |
| APIGW-005  | aws_api_gateway_integration                  | Default execution credentials used         | LOW      |
| APIGW-006  | aws_api_gateway_method                       | No API key required                        | LOW      |

Rules are auto-discovered via @register; no manual imports needed here.
"""
