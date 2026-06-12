"""Unit tests for the HCL expression evaluator."""

from __future__ import annotations

import pytest

from cloudspill.engine.hcl_expr import Unresolvable, evaluate

_VARS = {
    "var.flag": True,
    "var.off": False,
    "var.mode": "Active",
    "var.cidr": "0.0.0.0/0",
    "local.prefix": "app-prod",
}


def _resolve(ref):
    if ref in _VARS:
        return _VARS[ref]
    raise Unresolvable(ref)


@pytest.mark.parametrize(
    "expr,expected",
    [
        ("var.flag", True),
        ("var.mode", "Active"),
        ('"literal"', "literal"),
        ("true", True),
        ("false", False),
        ("42", 42),
        ('var.flag ? "a" : "b"', "a"),
        ('var.off ? "a" : "b"', "b"),
        ('var.mode == "Active" ? "yes" : "no"', "yes"),
        ('var.mode == "Inactive" ? "yes" : "no"', "no"),
        ('var.mode != "Active"', False),
        ("!var.off", True),
        ("!var.flag", False),
        ("var.flag && var.off", False),
        ("var.flag || var.off", True),
        ('(var.off ? "x" : "y")', "y"),
        ('var.flag ? var.cidr : "10.0.0.0/8"', "0.0.0.0/0"),
    ],
)
def test_evaluate(expr, expected):
    assert evaluate(expr, _resolve) == expected


@pytest.mark.parametrize(
    "expr",
    [
        "var.missing",
        "data.aws_ami.x.id",
        "cidrsubnet(var.cidr, 8, 0)",
        "aws_s3_bucket.b.arn",
    ],
)
def test_unresolvable(expr):
    with pytest.raises(Unresolvable):
        evaluate(expr, _resolve)
