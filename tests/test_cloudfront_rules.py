"""Tests for AWS CloudFront security rules + fixture integration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cloudspill.engine.rule_engine import RuleEngine
from cloudspill.models.findings import Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.parsers.terraform import TerraformParser
from cloudspill.rules import RuleRegistry
from cloudspill.rules.aws.cloudfront.cloudfront_001_no_https_redirect import (
    CloudFrontNoHttpsRedirect,
)
from cloudspill.rules.aws.cloudfront.cloudfront_002_tls_version_low import (
    CloudFrontTlsVersionLow,
)
from cloudspill.rules.aws.cloudfront.cloudfront_003_no_waf_attached import (
    CloudFrontNoWafAttached,
)
from cloudspill.rules.aws.cloudfront.cloudfront_004_logging_disabled import (
    CloudFrontLoggingDisabled,
)
from cloudspill.rules.aws.cloudfront.cloudfront_005_origin_access_identity_missing import (
    CloudFrontOriginAccessIdentityMissing,
)
from cloudspill.rules.aws.cloudfront.cloudfront_006_no_geo_restriction import (
    CloudFrontNoGeoRestriction,
)
from cloudspill.rules.aws.cloudfront.cloudfront_007_query_string_forwarding_disabled import (
    CloudFrontQueryStringForwardingDisabled,
)
from cloudspill.rules.aws.cloudfront.cloudfront_008_cache_key_missing_host_header import (
    CloudFrontCacheKeyMissingHostHeader,
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


class TestCloudFrontDiscovery:
    def test_cloudfront_category_filter(self) -> None:
        registry = RuleRegistry(enabled={"cloudfront"})
        ids = {r.rule_id for r in registry.rules}
        assert {
            "CLOUDFRONT-001",
            "CLOUDFRONT-002",
            "CLOUDFRONT-003",
            "CLOUDFRONT-004",
            "CLOUDFRONT-005",
            "CLOUDFRONT-006",
            "CLOUDFRONT-007",
            "CLOUDFRONT-008",
        } <= ids
        for rule in registry.rules:
            assert rule.rule_id.startswith("CLOUDFRONT")


# ─── CLOUDFRONT-001: No HTTPS redirect ───────────────────────────────


class TestCloudFrontNoHttpsRedirect:
    def _dist(self, **attrs: Any) -> IaCNode:
        return _make_node(
            "aws_cloudfront_distribution.d",
            "aws_cloudfront_distribution",
            attrs,
        )

    def test_default_allow_all_triggers(self) -> None:
        node = self._dist(
            default_cache_behavior={"viewer_protocol_policy": "allow-all"}
        )
        findings = CloudFrontNoHttpsRedirect().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "CLOUDFRONT-001"
        assert findings[0].severity == Severity.HIGH

    def test_default_block_as_list_triggers(self) -> None:
        node = self._dist(
            default_cache_behavior=[{"viewer_protocol_policy": "allow-all"}]
        )
        assert len(CloudFrontNoHttpsRedirect().check(node, _empty_graph())) == 1

    def test_ordered_behavior_allow_all_triggers(self) -> None:
        node = self._dist(
            default_cache_behavior={"viewer_protocol_policy": "redirect-to-https"},
            ordered_cache_behavior=[{"viewer_protocol_policy": "allow-all"}],
        )
        assert len(CloudFrontNoHttpsRedirect().check(node, _empty_graph())) == 1

    def test_child_block_allow_all_triggers(self) -> None:
        child = _make_node(
            "aws_cloudfront_distribution.d.default_cache_behavior",
            "default_cache_behavior",
            {"viewer_protocol_policy": "allow-all"},
        )
        node = _make_node(
            "aws_cloudfront_distribution.d",
            "aws_cloudfront_distribution",
            {},
            children=(child,),
        )
        assert len(CloudFrontNoHttpsRedirect().check(node, _empty_graph())) == 1

    def test_redirect_to_https_clean(self) -> None:
        node = self._dist(
            default_cache_behavior={"viewer_protocol_policy": "redirect-to-https"}
        )
        assert CloudFrontNoHttpsRedirect().check(node, _empty_graph()) == []

    def test_https_only_clean(self) -> None:
        node = self._dist(
            default_cache_behavior={"viewer_protocol_policy": "https-only"}
        )
        assert CloudFrontNoHttpsRedirect().check(node, _empty_graph()) == []

    def test_unknown_policy_triggers(self) -> None:
        # Anything outside the secure allowlist (typo, future value) is flagged.
        node = self._dist(
            default_cache_behavior={"viewer_protocol_policy": "http-and-https"}
        )
        assert len(CloudFrontNoHttpsRedirect().check(node, _empty_graph())) == 1

    def test_missing_policy_clean(self) -> None:
        # An absent policy is not judged (avoids false positives on partial config).
        node = self._dist(default_cache_behavior={"target_origin_id": "o1"})
        assert CloudFrontNoHttpsRedirect().check(node, _empty_graph()) == []

    def test_wrong_resource_type_skipped(self) -> None:
        node = _make_node("aws_s3_bucket.b", "aws_s3_bucket", {})
        assert CloudFrontNoHttpsRedirect().check(node, _empty_graph()) == []


# ─── CLOUDFRONT-002: TLS version low ─────────────────────────────────


class TestCloudFrontTlsVersionLow:
    def _dist(self, **attrs: Any) -> IaCNode:
        return _make_node(
            "aws_cloudfront_distribution.d",
            "aws_cloudfront_distribution",
            attrs,
        )

    def test_below_tls12_triggers(self) -> None:
        node = self._dist(
            viewer_certificate={"minimum_protocol_version": "TLSv1.1_2016"}
        )
        findings = CloudFrontTlsVersionLow().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "CLOUDFRONT-002"
        assert findings[0].severity == Severity.MEDIUM

    def test_legacy_tlsv1_triggers(self) -> None:
        node = self._dist(viewer_certificate={"minimum_protocol_version": "TLSv1"})
        assert len(CloudFrontTlsVersionLow().check(node, _empty_graph())) == 1

    def test_default_certificate_triggers(self) -> None:
        node = self._dist(viewer_certificate={"cloudfront_default_certificate": True})
        assert len(CloudFrontTlsVersionLow().check(node, _empty_graph())) == 1

    def test_tls12_clean(self) -> None:
        node = self._dist(
            viewer_certificate={"minimum_protocol_version": "TLSv1.2_2021"}
        )
        assert CloudFrontTlsVersionLow().check(node, _empty_graph()) == []

    def test_block_as_list_clean(self) -> None:
        node = self._dist(
            viewer_certificate=[{"minimum_protocol_version": "TLSv1.2_2019"}]
        )
        assert CloudFrontTlsVersionLow().check(node, _empty_graph()) == []

    def test_missing_version_custom_cert_clean(self) -> None:
        node = self._dist(
            viewer_certificate={"acm_certificate_arn": "arn:aws:acm:::cert/x"}
        )
        assert CloudFrontTlsVersionLow().check(node, _empty_graph()) == []

    def test_wrong_resource_type_skipped(self) -> None:
        node = _make_node("aws_s3_bucket.b", "aws_s3_bucket", {})
        assert CloudFrontTlsVersionLow().check(node, _empty_graph()) == []


# ─── CLOUDFRONT-003: No WAF attached ─────────────────────────────────


class TestCloudFrontNoWafAttached:
    def _dist(self, **attrs: Any) -> IaCNode:
        return _make_node(
            "aws_cloudfront_distribution.d",
            "aws_cloudfront_distribution",
            attrs,
        )

    def test_no_web_acl_triggers(self) -> None:
        node = self._dist(enabled=True)
        findings = CloudFrontNoWafAttached().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "CLOUDFRONT-003"
        assert findings[0].severity == Severity.MEDIUM

    def test_empty_web_acl_triggers(self) -> None:
        node = self._dist(web_acl_id="")
        assert len(CloudFrontNoWafAttached().check(node, _empty_graph())) == 1

    def test_wafv2_arn_clean(self) -> None:
        node = self._dist(
            web_acl_id="arn:aws:wafv2:us-east-1:123:global/webacl/main/abc"
        )
        assert CloudFrontNoWafAttached().check(node, _empty_graph()) == []

    def test_waf_classic_id_clean(self) -> None:
        node = self._dist(web_acl_id="a1b2c3d4-5678-90ab-cdef-EXAMPLE11111")
        assert CloudFrontNoWafAttached().check(node, _empty_graph()) == []

    def test_wrong_resource_type_skipped(self) -> None:
        node = _make_node("aws_s3_bucket.b", "aws_s3_bucket", {})
        assert CloudFrontNoWafAttached().check(node, _empty_graph()) == []


# ─── CLOUDFRONT-004: Logging disabled ────────────────────────────────


class TestCloudFrontLoggingDisabled:
    def _dist(self, **attrs: Any) -> IaCNode:
        return _make_node(
            "aws_cloudfront_distribution.d",
            "aws_cloudfront_distribution",
            attrs,
        )

    def test_no_logging_config_triggers(self) -> None:
        node = self._dist(enabled=True)
        findings = CloudFrontLoggingDisabled().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "CLOUDFRONT-004"
        assert findings[0].severity == Severity.LOW

    def test_logging_config_without_bucket_triggers(self) -> None:
        node = self._dist(logging_config={"include_cookies": False})
        assert len(CloudFrontLoggingDisabled().check(node, _empty_graph())) == 1

    def test_logging_config_dict_clean(self) -> None:
        node = self._dist(logging_config={"bucket": "logs.s3.amazonaws.com"})
        assert CloudFrontLoggingDisabled().check(node, _empty_graph()) == []

    def test_logging_config_list_clean(self) -> None:
        node = self._dist(logging_config=[{"bucket": "logs.s3.amazonaws.com"}])
        assert CloudFrontLoggingDisabled().check(node, _empty_graph()) == []

    def test_logging_config_child_block_clean(self) -> None:
        child = _make_node(
            "aws_cloudfront_distribution.d.logging_config",
            "logging_config",
            {"bucket": "logs.s3.amazonaws.com"},
        )
        node = _make_node(
            "aws_cloudfront_distribution.d",
            "aws_cloudfront_distribution",
            {},
            children=(child,),
        )
        assert CloudFrontLoggingDisabled().check(node, _empty_graph()) == []

    def test_wrong_resource_type_skipped(self) -> None:
        node = _make_node("aws_s3_bucket.b", "aws_s3_bucket", {})
        assert CloudFrontLoggingDisabled().check(node, _empty_graph()) == []


# ─── CLOUDFRONT-005: Origin access identity missing ──────────────────


class TestCloudFrontOriginAccessIdentityMissing:
    def _dist(self, origin: Any) -> IaCNode:
        return _make_node(
            "aws_cloudfront_distribution.d",
            "aws_cloudfront_distribution",
            {"origin": origin},
        )

    def test_s3_origin_empty_oai_triggers(self) -> None:
        node = self._dist(
            {
                "domain_name": "assets.s3.amazonaws.com",
                "s3_origin_config": {"origin_access_identity": ""},
            }
        )
        findings = CloudFrontOriginAccessIdentityMissing().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "CLOUDFRONT-005"
        assert findings[0].severity == Severity.MEDIUM

    def test_s3_origin_by_domain_no_protection_triggers(self) -> None:
        node = self._dist({"domain_name": "assets.s3.amazonaws.com"})
        assert (
            len(CloudFrontOriginAccessIdentityMissing().check(node, _empty_graph()))
            == 1
        )

    def test_oai_present_clean(self) -> None:
        node = self._dist(
            {
                "domain_name": "assets.s3.amazonaws.com",
                "s3_origin_config": {
                    "origin_access_identity": (
                        "origin-access-identity/cloudfront/E1EXAMPLE"
                    )
                },
            }
        )
        assert CloudFrontOriginAccessIdentityMissing().check(node, _empty_graph()) == []

    def test_oac_present_clean(self) -> None:
        node = self._dist(
            {
                "domain_name": "assets.s3.amazonaws.com",
                "origin_access_control_id": "E1EXAMPLEOAC",
            }
        )
        assert CloudFrontOriginAccessIdentityMissing().check(node, _empty_graph()) == []

    def test_custom_origin_skipped(self) -> None:
        node = self._dist(
            {
                "domain_name": "api.example.com",
                "custom_origin_config": {"origin_protocol_policy": "https-only"},
            }
        )
        assert CloudFrontOriginAccessIdentityMissing().check(node, _empty_graph()) == []

    def test_multiple_origins_one_exposed_triggers(self) -> None:
        node = self._dist(
            [
                {
                    "domain_name": "ok.s3.amazonaws.com",
                    "origin_access_control_id": "E1OAC",
                },
                {
                    "domain_name": "bad.s3.amazonaws.com",
                    "s3_origin_config": {"origin_access_identity": ""},
                },
            ]
        )
        assert (
            len(CloudFrontOriginAccessIdentityMissing().check(node, _empty_graph()))
            == 1
        )

    def test_wrong_resource_type_skipped(self) -> None:
        node = _make_node("aws_s3_bucket.b", "aws_s3_bucket", {})
        assert CloudFrontOriginAccessIdentityMissing().check(node, _empty_graph()) == []


# ─── CLOUDFRONT-006: No geo restriction ──────────────────────────────


class TestCloudFrontNoGeoRestriction:
    def _dist(self, **attrs: Any) -> IaCNode:
        return _make_node(
            "aws_cloudfront_distribution.d",
            "aws_cloudfront_distribution",
            attrs,
        )

    def test_no_restrictions_block_triggers(self) -> None:
        node = self._dist(enabled=True)
        findings = CloudFrontNoGeoRestriction().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "CLOUDFRONT-006"
        assert findings[0].severity == Severity.LOW

    def test_restriction_type_none_triggers(self) -> None:
        node = self._dist(
            restrictions={"geo_restriction": {"restriction_type": "none"}}
        )
        assert len(CloudFrontNoGeoRestriction().check(node, _empty_graph())) == 1

    def test_whitelist_clean(self) -> None:
        node = self._dist(
            restrictions={
                "geo_restriction": {
                    "restriction_type": "whitelist",
                    "locations": ["US"],
                }
            }
        )
        assert CloudFrontNoGeoRestriction().check(node, _empty_graph()) == []

    def test_blacklist_clean(self) -> None:
        node = self._dist(
            restrictions={
                "geo_restriction": {
                    "restriction_type": "blacklist",
                    "locations": ["KP"],
                }
            }
        )
        assert CloudFrontNoGeoRestriction().check(node, _empty_graph()) == []

    def test_nested_blocks_as_lists_clean(self) -> None:
        node = self._dist(
            restrictions=[{"geo_restriction": [{"restriction_type": "whitelist"}]}]
        )
        assert CloudFrontNoGeoRestriction().check(node, _empty_graph()) == []

    def test_wrong_resource_type_skipped(self) -> None:
        node = _make_node("aws_s3_bucket.b", "aws_s3_bucket", {})
        assert CloudFrontNoGeoRestriction().check(node, _empty_graph()) == []


# ─── CLOUDFRONT-007: Query string forwarding disabled ────────────────


class TestCloudFrontQueryStringForwardingDisabled:
    def _dist(self, **attrs: Any) -> IaCNode:
        return _make_node(
            "aws_cloudfront_distribution.d",
            "aws_cloudfront_distribution",
            attrs,
        )

    def test_query_string_false_triggers(self) -> None:
        node = self._dist(
            default_cache_behavior={"forwarded_values": {"query_string": False}}
        )
        findings = CloudFrontQueryStringForwardingDisabled().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "CLOUDFRONT-007"
        assert findings[0].severity == Severity.INFO

    def test_ordered_behavior_query_string_false_triggers(self) -> None:
        node = self._dist(
            default_cache_behavior={"forwarded_values": {"query_string": True}},
            ordered_cache_behavior=[{"forwarded_values": {"query_string": False}}],
        )
        assert (
            len(CloudFrontQueryStringForwardingDisabled().check(node, _empty_graph()))
            == 1
        )

    def test_query_string_true_clean(self) -> None:
        node = self._dist(
            default_cache_behavior={"forwarded_values": {"query_string": True}}
        )
        assert (
            CloudFrontQueryStringForwardingDisabled().check(node, _empty_graph()) == []
        )

    def test_cache_policy_behavior_skipped(self) -> None:
        # Modern cache-policy behaviors don't use forwarded_values.
        node = self._dist(default_cache_behavior={"cache_policy_id": "policy-123"})
        assert (
            CloudFrontQueryStringForwardingDisabled().check(node, _empty_graph()) == []
        )

    def test_no_forwarded_values_clean(self) -> None:
        node = self._dist(default_cache_behavior={"target_origin_id": "o1"})
        assert (
            CloudFrontQueryStringForwardingDisabled().check(node, _empty_graph()) == []
        )

    def test_wrong_resource_type_skipped(self) -> None:
        node = _make_node("aws_s3_bucket.b", "aws_s3_bucket", {})
        assert (
            CloudFrontQueryStringForwardingDisabled().check(node, _empty_graph()) == []
        )


# ─── CLOUDFRONT-008: Cache key missing Host header ───────────────────


class TestCloudFrontCacheKeyMissingHostHeader:
    def _dist(self, **attrs: Any) -> IaCNode:
        return _make_node(
            "aws_cloudfront_distribution.d",
            "aws_cloudfront_distribution",
            attrs,
        )

    def test_headers_without_host_triggers(self) -> None:
        node = self._dist(
            default_cache_behavior={"forwarded_values": {"headers": ["User-Agent"]}}
        )
        findings = CloudFrontCacheKeyMissingHostHeader().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "CLOUDFRONT-008"
        assert findings[0].severity == Severity.INFO

    def test_host_present_clean(self) -> None:
        node = self._dist(
            default_cache_behavior={
                "forwarded_values": {"headers": ["Host", "User-Agent"]}
            }
        )
        assert CloudFrontCacheKeyMissingHostHeader().check(node, _empty_graph()) == []

    def test_host_case_insensitive_clean(self) -> None:
        node = self._dist(
            default_cache_behavior={"forwarded_values": {"headers": ["host"]}}
        )
        assert CloudFrontCacheKeyMissingHostHeader().check(node, _empty_graph()) == []

    def test_wildcard_headers_clean(self) -> None:
        node = self._dist(
            default_cache_behavior={"forwarded_values": {"headers": ["*"]}}
        )
        assert CloudFrontCacheKeyMissingHostHeader().check(node, _empty_graph()) == []

    def test_no_headers_clean(self) -> None:
        # Forwarding no headers is normal for static content — not flagged.
        node = self._dist(
            default_cache_behavior={"forwarded_values": {"query_string": True}}
        )
        assert CloudFrontCacheKeyMissingHostHeader().check(node, _empty_graph()) == []

    def test_cache_policy_behavior_skipped(self) -> None:
        node = self._dist(default_cache_behavior={"cache_policy_id": "policy-123"})
        assert CloudFrontCacheKeyMissingHostHeader().check(node, _empty_graph()) == []

    def test_wrong_resource_type_skipped(self) -> None:
        node = _make_node("aws_s3_bucket.b", "aws_s3_bucket", {})
        assert CloudFrontCacheKeyMissingHostHeader().check(node, _empty_graph()) == []


# ─── Fixture integration ─────────────────────────────────────────────


class TestCloudFrontFixture:
    def test_exactly_one_insecure_distribution_flagged(self) -> None:
        nodes = TerraformParser().parse(FIXTURES / "cloudfront_http.tf")
        graph = ResourceGraph.build(nodes)
        findings = RuleEngine(RuleRegistry(enabled={"cloudfront"})).evaluate(
            nodes, graph
        )
        cf001 = [f for f in findings if f.rule_id == "CLOUDFRONT-001"]
        assert len(cf001) == 1
        assert cf001[0].resource == "aws_cloudfront_distribution.insecure"

    def test_exactly_one_weak_tls_distribution_flagged(self) -> None:
        nodes = TerraformParser().parse(FIXTURES / "cloudfront_tls.tf")
        graph = ResourceGraph.build(nodes)
        findings = RuleEngine(RuleRegistry(enabled={"cloudfront"})).evaluate(
            nodes, graph
        )
        cf002 = [f for f in findings if f.rule_id == "CLOUDFRONT-002"]
        assert len(cf002) == 1
        assert cf002[0].resource == "aws_cloudfront_distribution.weak_tls"

    def test_exactly_one_unprotected_distribution_flagged(self) -> None:
        nodes = TerraformParser().parse(FIXTURES / "cloudfront_waf.tf")
        graph = ResourceGraph.build(nodes)
        findings = RuleEngine(RuleRegistry(enabled={"cloudfront"})).evaluate(
            nodes, graph
        )
        cf003 = [f for f in findings if f.rule_id == "CLOUDFRONT-003"]
        assert len(cf003) == 1
        assert cf003[0].resource == "aws_cloudfront_distribution.unprotected"

    def test_exactly_one_unlogged_distribution_flagged(self) -> None:
        nodes = TerraformParser().parse(FIXTURES / "cloudfront_logging.tf")
        graph = ResourceGraph.build(nodes)
        findings = RuleEngine(RuleRegistry(enabled={"cloudfront"})).evaluate(
            nodes, graph
        )
        cf004 = [f for f in findings if f.rule_id == "CLOUDFRONT-004"]
        assert len(cf004) == 1
        assert cf004[0].resource == "aws_cloudfront_distribution.unlogged"

    def test_exactly_one_exposed_s3_origin_flagged(self) -> None:
        nodes = TerraformParser().parse(FIXTURES / "cloudfront_oai.tf")
        graph = ResourceGraph.build(nodes)
        findings = RuleEngine(RuleRegistry(enabled={"cloudfront"})).evaluate(
            nodes, graph
        )
        cf005 = [f for f in findings if f.rule_id == "CLOUDFRONT-005"]
        assert len(cf005) == 1
        assert cf005[0].resource == "aws_cloudfront_distribution.exposed_s3"

    def test_exactly_one_unrestricted_distribution_flagged(self) -> None:
        nodes = TerraformParser().parse(FIXTURES / "cloudfront_geo.tf")
        graph = ResourceGraph.build(nodes)
        findings = RuleEngine(RuleRegistry(enabled={"cloudfront"})).evaluate(
            nodes, graph
        )
        cf006 = [f for f in findings if f.rule_id == "CLOUDFRONT-006"]
        assert len(cf006) == 1
        assert cf006[0].resource == "aws_cloudfront_distribution.unrestricted"

    def test_exactly_one_query_string_dropping_behavior_flagged(self) -> None:
        nodes = TerraformParser().parse(FIXTURES / "cloudfront_querystring.tf")
        graph = ResourceGraph.build(nodes)
        findings = RuleEngine(RuleRegistry(enabled={"cloudfront"})).evaluate(
            nodes, graph
        )
        cf007 = [f for f in findings if f.rule_id == "CLOUDFRONT-007"]
        assert len(cf007) == 1
        assert cf007[0].resource == "aws_cloudfront_distribution.drops_qs"

    def test_exactly_one_missing_host_header_behavior_flagged(self) -> None:
        nodes = TerraformParser().parse(FIXTURES / "cloudfront_hostheader.tf")
        graph = ResourceGraph.build(nodes)
        findings = RuleEngine(RuleRegistry(enabled={"cloudfront"})).evaluate(
            nodes, graph
        )
        cf008 = [f for f in findings if f.rule_id == "CLOUDFRONT-008"]
        assert len(cf008) == 1
        assert cf008[0].resource == "aws_cloudfront_distribution.no_host"
