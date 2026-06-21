"""Tests for AWS API Gateway security rules + fixture integration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cloudspill.engine.rule_engine import RuleEngine
from cloudspill.models.findings import Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.parsers.terraform import TerraformParser
from cloudspill.rules import RuleRegistry
from cloudspill.rules.aws.api_gateway.apigw_001_no_authorization import (
    APIGatewayNoAuthorization,
)
from cloudspill.rules.aws.api_gateway.apigw_002_no_waf_attached import (
    APIGateWayNoWafAttached,
)
from cloudspill.rules.aws.api_gateway.apigw_003_logging_disabled import (
    APIGatewayLoggingDisabled,
)
from cloudspill.rules.aws.api_gateway.apigw_004_no_resource_policy_wildcard import (
    APIGatewayResourcePolicyWildcard,
)
from cloudspill.rules.aws.api_gateway.apigw_005_default_execution_role_used import (
    APIGatewayDefaultExecutionRole,
)
from cloudspill.rules.aws.api_gateway.apigw_006_no_api_key_required import (
    APIGatewayNoApiKeyRequired,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _make_node(
    node_id: str,
    resource_type: str,
    attributes: dict[str, Any] | None = None,
    children: tuple[IaCNode, ...] = (),
) -> IaCNode:
    return IaCNode(
        node_id=node_id,
        node_type="resource",
        resource_type=resource_type,
        name=node_id.split(".")[-1],
        attributes=attributes or {},
        children=children,
        source_file="test.tf",
        line=1,
    )


def _empty_graph() -> ResourceGraph:
    return ResourceGraph()


# ─── Discovery / filtering ───────────────────────────────────────────


class TestAPIGWDiscovery:
    def test_apigw_category_filter(self) -> None:
        registry = RuleRegistry(enabled={"apigw"})
        ids = {r.rule_id for r in registry.rules}
        assert {
            "APIGW-001",
            "APIGW-002",
            "APIGW-003",
            "APIGW-004",
            "APIGW-005",
            "APIGW-006",
        } <= ids
        for rule in registry.rules:
            assert rule.rule_id.startswith("APIGW")


# ─── APIGW-002: No WAF attached ──────────────────────────────────────


class TestAPIGWNoWaf:
    def test_stage_without_association_triggers(self) -> None:
        node = _make_node(
            "aws_api_gateway_stage.prod",
            "aws_api_gateway_stage",
            {"stage_name": "prod"},
        )
        graph = ResourceGraph.build([node])
        findings = APIGateWayNoWafAttached().check(node, graph)
        assert len(findings) == 1
        assert findings[0].rule_id == "APIGW-002"
        assert findings[0].severity == Severity.MEDIUM

    def test_stage_with_wafv2_association_clean(self) -> None:
        stage = _make_node(
            "aws_api_gateway_stage.prod",
            "aws_api_gateway_stage",
            {"stage_name": "prod"},
        )
        assoc = _make_node(
            "aws_wafv2_web_acl_association.a",
            "aws_wafv2_web_acl_association",
            {"resource_arn": "aws_api_gateway_stage.prod.arn"},
        )
        graph = ResourceGraph.build([stage, assoc])
        assert APIGateWayNoWafAttached().check(stage, graph) == []

    def test_stage_with_waf_classic_association_clean(self) -> None:
        stage = _make_node(
            "aws_api_gateway_stage.prod",
            "aws_api_gateway_stage",
            {"stage_name": "prod"},
        )
        assoc = _make_node(
            "aws_wafregional_web_acl_association.a",
            "aws_wafregional_web_acl_association",
            {"resource_arn": "aws_api_gateway_stage.prod.arn"},
        )
        graph = ResourceGraph.build([stage, assoc])
        assert APIGateWayNoWafAttached().check(stage, graph) == []

    def test_unrelated_association_still_triggers(self) -> None:
        # Association points at a *different* stage; this one is unprotected.
        stage = _make_node(
            "aws_api_gateway_stage.prod",
            "aws_api_gateway_stage",
            {"stage_name": "prod"},
        )
        other = _make_node(
            "aws_api_gateway_stage.staging",
            "aws_api_gateway_stage",
            {"stage_name": "staging"},
        )
        assoc = _make_node(
            "aws_wafv2_web_acl_association.a",
            "aws_wafv2_web_acl_association",
            {"resource_arn": "aws_api_gateway_stage.staging.arn"},
        )
        graph = ResourceGraph.build([stage, other, assoc])
        assert len(APIGateWayNoWafAttached().check(stage, graph)) == 1

    def test_http_api_v2_stage_skipped(self) -> None:
        # AWS WAF does not support HTTP APIs — must not flag v2 stages.
        node = _make_node(
            "aws_apigatewayv2_stage.prod",
            "aws_apigatewayv2_stage",
            {"name": "prod"},
        )
        graph = ResourceGraph.build([node])
        assert APIGateWayNoWafAttached().check(node, graph) == []

    def test_wrong_resource_type_skipped(self) -> None:
        node = _make_node("aws_s3_bucket.b", "aws_s3_bucket", {})
        assert APIGateWayNoWafAttached().check(node, _empty_graph()) == []


# ─── APIGW-001: No authorization (smoke) ─────────────────────────────


class TestAPIGWNoAuthorization:
    def test_none_authorization_triggers(self) -> None:
        node = _make_node(
            "aws_api_gateway_method.m",
            "aws_api_gateway_method",
            {"http_method": "POST", "authorization": "NONE"},
        )
        findings = APIGatewayNoAuthorization().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "APIGW-001"
        assert findings[0].severity == Severity.HIGH

    def test_missing_authorization_triggers(self) -> None:
        # Absent attribute defaults to "" which means NONE.
        node = _make_node(
            "aws_api_gateway_method.m",
            "aws_api_gateway_method",
            {"http_method": "POST"},
        )
        assert len(APIGatewayNoAuthorization().check(node, _empty_graph())) == 1

    def test_iam_authorization_clean(self) -> None:
        node = _make_node(
            "aws_api_gateway_method.m",
            "aws_api_gateway_method",
            {"http_method": "POST", "authorization": "AWS_IAM"},
        )
        assert APIGatewayNoAuthorization().check(node, _empty_graph()) == []

    def test_options_preflight_skipped(self) -> None:
        node = _make_node(
            "aws_api_gateway_method.m",
            "aws_api_gateway_method",
            {"http_method": "OPTIONS", "authorization": "NONE"},
        )
        assert APIGatewayNoAuthorization().check(node, _empty_graph()) == []

    def test_v2_route_none_triggers(self) -> None:
        node = _make_node(
            "aws_apigatewayv2_route.r",
            "aws_apigatewayv2_route",
            {"route_key": "GET /items", "authorization_type": "NONE"},
        )
        assert len(APIGatewayNoAuthorization().check(node, _empty_graph())) == 1

    def test_v2_route_jwt_clean(self) -> None:
        node = _make_node(
            "aws_apigatewayv2_route.r",
            "aws_apigatewayv2_route",
            {"route_key": "GET /items", "authorization_type": "JWT"},
        )
        assert APIGatewayNoAuthorization().check(node, _empty_graph()) == []

    def test_v2_options_route_skipped(self) -> None:
        node = _make_node(
            "aws_apigatewayv2_route.r",
            "aws_apigatewayv2_route",
            {"route_key": "OPTIONS /items", "authorization_type": "NONE"},
        )
        assert APIGatewayNoAuthorization().check(node, _empty_graph()) == []

    def test_wrong_resource_type_skipped(self) -> None:
        node = _make_node("aws_s3_bucket.b", "aws_s3_bucket", {})
        assert APIGatewayNoAuthorization().check(node, _empty_graph()) == []


# ─── APIGW-003: Access logging disabled ──────────────────────────────


class TestAPIGWLoggingDisabled:
    def test_stage_without_logging_triggers(self) -> None:
        node = _make_node(
            "aws_api_gateway_stage.prod",
            "aws_api_gateway_stage",
            {"stage_name": "prod"},
        )
        findings = APIGatewayLoggingDisabled().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "APIGW-003"
        assert findings[0].severity == Severity.MEDIUM

    def test_logging_as_dict_clean(self) -> None:
        node = _make_node(
            "aws_api_gateway_stage.prod",
            "aws_api_gateway_stage",
            {
                "access_log_settings": {
                    "destination_arn": "arn:aws:logs:::lg",
                    "format": "x",
                }
            },
        )
        assert APIGatewayLoggingDisabled().check(node, _empty_graph()) == []

    def test_logging_as_list_clean(self) -> None:
        node = _make_node(
            "aws_api_gateway_stage.prod",
            "aws_api_gateway_stage",
            {"access_log_settings": [{"destination_arn": "arn:aws:logs:::lg"}]},
        )
        assert APIGatewayLoggingDisabled().check(node, _empty_graph()) == []

    def test_logging_as_child_block_clean(self) -> None:
        child = _make_node(
            "aws_api_gateway_stage.prod.access_log_settings",
            "access_log_settings",
            {"destination_arn": "arn:aws:logs:::lg"},
        )
        node = _make_node(
            "aws_api_gateway_stage.prod",
            "aws_api_gateway_stage",
            {},
            children=(child,),
        )
        assert APIGatewayLoggingDisabled().check(node, _empty_graph()) == []

    def test_empty_destination_arn_triggers(self) -> None:
        node = _make_node(
            "aws_api_gateway_stage.prod",
            "aws_api_gateway_stage",
            {"access_log_settings": {"destination_arn": "", "format": "x"}},
        )
        assert len(APIGatewayLoggingDisabled().check(node, _empty_graph())) == 1

    def test_v2_stage_without_logging_triggers(self) -> None:
        node = _make_node(
            "aws_apigatewayv2_stage.prod",
            "aws_apigatewayv2_stage",
            {"name": "prod"},
        )
        assert len(APIGatewayLoggingDisabled().check(node, _empty_graph())) == 1

    def test_wrong_resource_type_skipped(self) -> None:
        node = _make_node("aws_s3_bucket.b", "aws_s3_bucket", {})
        assert APIGatewayLoggingDisabled().check(node, _empty_graph()) == []


# ─── APIGW-004: Resource policy wildcard principal ───────────────────


class TestAPIGWResourcePolicyWildcard:
    _DOC = '{"Version":"2012-10-17","Statement":[%s]}'

    def _api(self, statement_json: str) -> IaCNode:
        return _make_node(
            "aws_api_gateway_rest_api.api",
            "aws_api_gateway_rest_api",
            {"policy": self._DOC % statement_json},
        )

    def test_string_wildcard_principal_triggers(self) -> None:
        node = self._api(
            '{"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke"}'
        )
        findings = APIGatewayResourcePolicyWildcard().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "APIGW-004"
        assert findings[0].severity == Severity.HIGH

    def test_aws_dict_wildcard_principal_triggers(self) -> None:
        node = self._api(
            '{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"execute-api:Invoke"}'
        )
        assert len(APIGatewayResourcePolicyWildcard().check(node, _empty_graph())) == 1

    def test_aws_list_wildcard_principal_triggers(self) -> None:
        node = self._api(
            '{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":"execute-api:Invoke"}'
        )
        assert len(APIGatewayResourcePolicyWildcard().check(node, _empty_graph())) == 1

    def test_wildcard_with_condition_clean(self) -> None:
        node = self._api(
            '{"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke",'
            '"Condition":{"StringEquals":{"aws:SourceVpce":"vpce-1"}}}'
        )
        assert APIGatewayResourcePolicyWildcard().check(node, _empty_graph()) == []

    def test_specific_principal_clean(self) -> None:
        node = self._api(
            '{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123:root"},'
            '"Action":"execute-api:Invoke"}'
        )
        assert APIGatewayResourcePolicyWildcard().check(node, _empty_graph()) == []

    def test_deny_wildcard_clean(self) -> None:
        node = self._api(
            '{"Effect":"Deny","Principal":"*","Action":"execute-api:Invoke"}'
        )
        assert APIGatewayResourcePolicyWildcard().check(node, _empty_graph()) == []

    def test_no_policy_clean(self) -> None:
        node = _make_node(
            "aws_api_gateway_rest_api.api", "aws_api_gateway_rest_api", {}
        )
        assert APIGatewayResourcePolicyWildcard().check(node, _empty_graph()) == []

    def test_dict_policy_supported(self) -> None:
        node = _make_node(
            "aws_api_gateway_rest_api.api",
            "aws_api_gateway_rest_api",
            {
                "policy": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "x"}],
                }
            },
        )
        assert len(APIGatewayResourcePolicyWildcard().check(node, _empty_graph())) == 1

    def test_wrong_resource_type_skipped(self) -> None:
        node = _make_node("aws_s3_bucket.b", "aws_s3_bucket", {})
        assert APIGatewayResourcePolicyWildcard().check(node, _empty_graph()) == []


# ─── APIGW-005: Default execution credentials ────────────────────────


class TestAPIGWDefaultExecutionRole:
    def _integration(self, **attrs: Any) -> IaCNode:
        return _make_node(
            "aws_api_gateway_integration.i",
            "aws_api_gateway_integration",
            attrs,
        )

    def test_caller_passthrough_triggers(self) -> None:
        node = self._integration(type="AWS", credentials="arn:aws:iam::*:user/*")
        findings = APIGatewayDefaultExecutionRole().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "APIGW-005"
        assert findings[0].severity == Severity.LOW

    def test_caller_passthrough_on_proxy_triggers(self) -> None:
        node = self._integration(type="AWS_PROXY", credentials="arn:aws:iam::*:user/*")
        assert len(APIGatewayDefaultExecutionRole().check(node, _empty_graph())) == 1

    def test_aws_integration_missing_credentials_triggers(self) -> None:
        node = self._integration(type="AWS")
        assert len(APIGatewayDefaultExecutionRole().check(node, _empty_graph())) == 1

    def test_explicit_role_clean(self) -> None:
        node = self._integration(
            type="AWS", credentials="arn:aws:iam::123456789012:role/exec"
        )
        assert APIGatewayDefaultExecutionRole().check(node, _empty_graph()) == []

    def test_proxy_missing_credentials_clean(self) -> None:
        # Lambda proxy grants access via aws_lambda_permission, not credentials.
        node = self._integration(type="AWS_PROXY")
        assert APIGatewayDefaultExecutionRole().check(node, _empty_graph()) == []

    def test_http_integration_skipped(self) -> None:
        node = self._integration(type="HTTP_PROXY")
        assert APIGatewayDefaultExecutionRole().check(node, _empty_graph()) == []

    def test_mock_integration_skipped(self) -> None:
        node = self._integration(type="MOCK")
        assert APIGatewayDefaultExecutionRole().check(node, _empty_graph()) == []

    def test_wrong_resource_type_skipped(self) -> None:
        node = _make_node("aws_s3_bucket.b", "aws_s3_bucket", {})
        assert APIGatewayDefaultExecutionRole().check(node, _empty_graph()) == []


# ─── APIGW-006: No API key required ──────────────────────────────────


class TestAPIGWNoApiKeyRequired:
    def _method(self, **attrs: Any) -> IaCNode:
        return _make_node("aws_api_gateway_method.m", "aws_api_gateway_method", attrs)

    def test_missing_api_key_triggers(self) -> None:
        node = self._method(http_method="GET")
        findings = APIGatewayNoApiKeyRequired().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "APIGW-006"
        assert findings[0].severity == Severity.LOW

    def test_api_key_false_triggers(self) -> None:
        node = self._method(http_method="GET", api_key_required=False)
        assert len(APIGatewayNoApiKeyRequired().check(node, _empty_graph())) == 1

    def test_api_key_required_clean(self) -> None:
        node = self._method(http_method="GET", api_key_required=True)
        assert APIGatewayNoApiKeyRequired().check(node, _empty_graph()) == []

    def test_options_preflight_skipped(self) -> None:
        node = self._method(http_method="OPTIONS")
        assert APIGatewayNoApiKeyRequired().check(node, _empty_graph()) == []

    def test_wrong_resource_type_skipped(self) -> None:
        node = _make_node("aws_s3_bucket.b", "aws_s3_bucket", {})
        assert APIGatewayNoApiKeyRequired().check(node, _empty_graph()) == []


# ─── Fixture integration ─────────────────────────────────────────────


class TestAPIGWFixture:
    def _findings(self, fixture: str, rule_id: str) -> list:
        nodes = TerraformParser().parse(FIXTURES / fixture)
        graph = ResourceGraph.build(nodes)
        findings = RuleEngine(RuleRegistry(enabled={"apigw"})).evaluate(nodes, graph)
        return [f for f in findings if f.rule_id == rule_id]

    def test_exactly_one_unprotected_stage_flagged(self) -> None:
        findings = self._findings("apigw_no_waf.tf", "APIGW-002")
        assert len(findings) == 1
        assert "aws_api_gateway_stage.unprotected" == findings[0].resource

    def test_exactly_one_unlogged_stage_flagged(self) -> None:
        findings = self._findings("apigw_no_logging.tf", "APIGW-003")
        assert len(findings) == 1
        assert "aws_api_gateway_stage.unlogged" == findings[0].resource

    def test_exactly_one_unauthenticated_method_flagged(self) -> None:
        findings = self._findings("apigw_no_auth.tf", "APIGW-001")
        assert len(findings) == 1
        assert "aws_api_gateway_method.open" == findings[0].resource

    def test_exactly_one_wildcard_policy_flagged(self) -> None:
        findings = self._findings("apigw_policy_wildcard.tf", "APIGW-004")
        assert len(findings) == 1
        assert "aws_api_gateway_rest_api.open" == findings[0].resource

    def test_exactly_one_default_role_integration_flagged(self) -> None:
        findings = self._findings("apigw_default_role.tf", "APIGW-005")
        assert len(findings) == 1
        assert "aws_api_gateway_integration.passthrough" == findings[0].resource

    def test_exactly_one_method_without_api_key_flagged(self) -> None:
        findings = self._findings("apigw_no_api_key.tf", "APIGW-006")
        assert len(findings) == 1
        assert "aws_api_gateway_method.unmetered" == findings[0].resource
