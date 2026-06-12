"""Tests for ConfigResolver — variable / local / conditional / module resolution."""

from __future__ import annotations

from pathlib import Path

from cloudspill.engine.resolver import ConfigResolver
from cloudspill.parsers.terraform import TerraformParser


def _resolve_dir(directory: Path):
    nodes = []
    for tf in sorted(directory.glob("*.tf")):
        nodes.extend(TerraformParser().parse(tf))
    return ConfigResolver().resolve(nodes)


def _find(nodes, node_id):
    return next(n for n in nodes if n.node_id == node_id)


def test_variable_default_resolves(tmp_path):
    (tmp_path / "main.tf").write_text(
        'variable "acl" { default = "public-read" }\n'
        'resource "aws_s3_bucket" "b" { acl = var.acl }\n'
    )
    bucket = _find(_resolve_dir(tmp_path), "aws_s3_bucket.b")
    assert bucket.attributes["acl"] == "public-read"


def test_tfvars_overrides_default(tmp_path):
    (tmp_path / "main.tf").write_text(
        'variable "acl" { default = "private" }\n'
        'resource "aws_s3_bucket" "b" { acl = var.acl }\n'
    )
    (tmp_path / "terraform.tfvars").write_text('acl = "public-read"\n')
    bucket = _find(_resolve_dir(tmp_path), "aws_s3_bucket.b")
    assert bucket.attributes["acl"] == "public-read"


def test_conditional_picks_branch(tmp_path):
    (tmp_path / "main.tf").write_text(
        'variable "public" { default = true }\n'
        'resource "aws_s3_bucket" "b" {\n'
        '  acl = var.public ? "public-read" : "private"\n'
        "}\n"
    )
    bucket = _find(_resolve_dir(tmp_path), "aws_s3_bucket.b")
    assert bucket.attributes["acl"] == "public-read"


def test_conditional_secure_branch(tmp_path):
    (tmp_path / "main.tf").write_text(
        'variable "public" { default = false }\n'
        'resource "aws_s3_bucket" "b" {\n'
        '  acl = var.public ? "public-read" : "private"\n'
        "}\n"
    )
    bucket = _find(_resolve_dir(tmp_path), "aws_s3_bucket.b")
    assert bucket.attributes["acl"] == "private"


def test_list_with_variable(tmp_path):
    (tmp_path / "main.tf").write_text(
        'variable "cidr" { default = "0.0.0.0/0" }\n'
        'resource "aws_security_group" "sg" {\n'
        "  ingress {\n"
        "    from_port   = 22\n"
        "    to_port     = 22\n"
        '    protocol    = "tcp"\n'
        "    cidr_blocks = [var.cidr]\n"
        "  }\n"
        "}\n"
    )
    sg = _find(_resolve_dir(tmp_path), "aws_security_group.sg")
    ingress = sg.attributes["ingress"]
    block = ingress[0] if isinstance(ingress, list) else ingress
    assert block["cidr_blocks"] == ["0.0.0.0/0"]


def test_local_and_chained_interpolation(tmp_path):
    (tmp_path / "main.tf").write_text(
        'variable "env" { default = "prod" }\n'
        "locals {\n"
        '  prefix = "app-${var.env}"\n'
        '  bucket = "${local.prefix}-data"\n'
        "}\n"
        'resource "aws_s3_bucket" "b" { bucket = local.bucket }\n'
    )
    bucket = _find(_resolve_dir(tmp_path), "aws_s3_bucket.b")
    assert bucket.attributes["bucket"] == "app-prod-data"


def test_unresolvable_left_intact(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "b" { bucket = data.aws_caller.x.id }\n'
    )
    bucket = _find(_resolve_dir(tmp_path), "aws_s3_bucket.b")
    assert bucket.attributes["bucket"] == "${data.aws_caller.x.id}"


def test_local_module_expansion_threads_argument(tmp_path):
    module = tmp_path / "modules" / "bucket"
    module.mkdir(parents=True)
    (module / "main.tf").write_text(
        'variable "acl" { default = "private" }\n'
        'resource "aws_s3_bucket" "b" { acl = var.acl }\n'
    )
    root = tmp_path / "root"
    root.mkdir()
    (root / "main.tf").write_text(
        'module "bucket" {\n'
        '  source = "../modules/bucket"\n'
        '  acl    = "public-read"\n'
        "}\n"
    )
    nodes = _resolve_dir(root)
    bucket = _find(nodes, "aws_s3_bucket.b")
    assert bucket.attributes["acl"] == "public-read"


def test_remote_module_skipped(tmp_path):
    (tmp_path / "main.tf").write_text(
        'module "vpc" {\n'
        '  source = "terraform-aws-modules/vpc/aws"\n'
        '  cidr   = "10.0.0.0/16"\n'
        "}\n"
    )
    # Remote module cannot be fetched; resolver yields no resource nodes for it.
    assert _resolve_dir(tmp_path) == []
