"""Tests for CloudSpill parsers."""

from __future__ import annotations

from pathlib import Path

import pytest

from cloudspill.models.nodes import IaCNode
from cloudspill.parsers.docker import DockerfileParser
from cloudspill.parsers.registry import ParserRegistry
from cloudspill.parsers.terraform import TerraformParser

FIXTURES = Path(__file__).parent / "fixtures"


# ─── TerraformParser ────────────────────────────────────────────────


class TestTerraformParserCanParse:
    def test_accepts_tf_files(self) -> None:
        parser = TerraformParser()
        assert parser.can_parse(Path("main.tf")) is True

    def test_rejects_non_tf_files(self) -> None:
        parser = TerraformParser()
        assert parser.can_parse(Path("Dockerfile")) is False
        assert parser.can_parse(Path("main.py")) is False
        assert parser.can_parse(Path("config.json")) is False


class TestTerraformParserBasicParsing:
    @pytest.fixture()
    def nodes(self) -> list[IaCNode]:
        parser = TerraformParser()
        return parser.parse(FIXTURES / "s3_public.tf")

    def test_returns_two_resources(self, nodes: list[IaCNode]) -> None:
        assert len(nodes) == 2

    def test_node_ids(self, nodes: list[IaCNode]) -> None:
        ids = {n.node_id for n in nodes}
        assert "aws_s3_bucket.vulnerable_bucket" in ids
        assert "aws_s3_bucket_public_access_block.leaky_policy" in ids

    def test_node_type_is_resource(self, nodes: list[IaCNode]) -> None:
        for node in nodes:
            assert node.node_type == "resource"

    def test_resource_types(self, nodes: list[IaCNode]) -> None:
        types = {n.resource_type for n in nodes}
        assert "aws_s3_bucket" in types
        assert "aws_s3_bucket_public_access_block" in types

    def test_names(self, nodes: list[IaCNode]) -> None:
        names = {n.name for n in nodes}
        assert "vulnerable_bucket" in names
        assert "leaky_policy" in names

    def test_source_file(self, nodes: list[IaCNode]) -> None:
        for node in nodes:
            assert node.source_file.endswith("s3_public.tf")


class TestTerraformParserLineNumbers:
    @pytest.fixture()
    def nodes(self) -> list[IaCNode]:
        parser = TerraformParser()
        return parser.parse(FIXTURES / "s3_public.tf")

    def test_bucket_line(self, nodes: list[IaCNode]) -> None:
        bucket = next(n for n in nodes if n.name == "vulnerable_bucket")
        assert bucket.line == 2

    def test_access_block_line(self, nodes: list[IaCNode]) -> None:
        block = next(n for n in nodes if n.name == "leaky_policy")
        assert block.line == 16


class TestTerraformParserAttributes:
    @pytest.fixture()
    def bucket(self) -> IaCNode:
        parser = TerraformParser()
        nodes = parser.parse(FIXTURES / "s3_public.tf")
        return next(n for n in nodes if n.name == "vulnerable_bucket")

    @pytest.fixture()
    def access_block(self) -> IaCNode:
        parser = TerraformParser()
        nodes = parser.parse(FIXTURES / "s3_public.tf")
        return next(n for n in nodes if n.name == "leaky_policy")

    def test_bucket_name_attribute(self, bucket: IaCNode) -> None:
        assert bucket.attributes["bucket"] == "cloudspill-test-public-leak-bucket"

    def test_acl_attribute_cleaned(self, bucket: IaCNode) -> None:
        """hcl2 v8 wraps strings in extra quotes — parser must strip them."""
        acl = bucket.attributes["acl"]
        assert acl == "public-read"
        assert not acl.startswith('"')

    def test_tags_present(self, bucket: IaCNode) -> None:
        tags = bucket.attributes.get("tags")
        assert tags is not None
        assert tags["Environment"] == "test"
        assert tags["Engine"] == "cloudspill-fixture"

    def test_boolean_attributes(self, access_block: IaCNode) -> None:
        assert access_block.attributes["block_public_acls"] is False
        assert access_block.attributes["block_public_policy"] is False
        assert access_block.attributes["ignore_public_acls"] is False
        assert access_block.attributes["restrict_public_buckets"] is False

    def test_reference_preserved(self, access_block: IaCNode) -> None:
        """Cross-resource references must survive parsing for DAG construction."""
        ref = access_block.attributes["bucket"]
        assert "aws_s3_bucket.vulnerable_bucket" in ref


class TestTerraformParserFrozen:
    def test_node_is_immutable(self) -> None:
        parser = TerraformParser()
        nodes = parser.parse(FIXTURES / "s3_public.tf")
        with pytest.raises(AttributeError):
            nodes[0].name = "hacked"  # type: ignore[misc]


class TestTerraformParserChildren:
    def test_children_is_tuple(self) -> None:
        parser = TerraformParser()
        nodes = parser.parse(FIXTURES / "s3_public.tf")
        for node in nodes:
            assert isinstance(node.children, tuple)


class TestTerraformParserEdgeCases:
    def test_empty_file(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty.tf"
        empty.write_text("")
        parser = TerraformParser()
        assert parser.parse(empty) == []

    def test_comments_only(self, tmp_path: Path) -> None:
        comments = tmp_path / "comments.tf"
        comments.write_text("# This file has no resources\n# Just comments\n")
        parser = TerraformParser()
        assert parser.parse(comments) == []


# ─── DockerfileParser ────────────────────────────────────────────────


class TestDockerfileParserCanParse:
    def test_accepts_dockerfile(self) -> None:
        parser = DockerfileParser()
        assert parser.can_parse(Path("Dockerfile")) is True

    def test_accepts_dockerfile_with_suffix(self) -> None:
        parser = DockerfileParser()
        assert parser.can_parse(Path("Dockerfile.prod")) is True
        assert parser.can_parse(Path("dockerfile.dev")) is True

    def test_rejects_non_dockerfile(self) -> None:
        parser = DockerfileParser()
        assert parser.can_parse(Path("main.tf")) is False
        assert parser.can_parse(Path("docker-compose.yml")) is False


# ─── ParserRegistry ──────────────────────────────────────────────────


class TestParserRegistry:
    def test_registry_has_parsers(self) -> None:
        registry = ParserRegistry()
        assert len(registry._parsers) >= 2


# ─── DockerfileParser — Parsing ──────────────────────────────────────


class TestDockerfileParserBasicParsing:
    @pytest.fixture()
    def nodes(self) -> list[IaCNode]:
        parser = DockerfileParser()
        return parser.parse(FIXTURES / "Dockerfile.vulnerable")

    def test_instruction_count(self, nodes: list[IaCNode]) -> None:
        assert len(nodes) == 13

    def test_node_type_is_instruction(self, nodes: list[IaCNode]) -> None:
        for node in nodes:
            assert node.node_type == "instruction"

    def test_source_file(self, nodes: list[IaCNode]) -> None:
        for node in nodes:
            assert node.source_file.endswith("Dockerfile.vulnerable")

    def test_children_are_empty_tuples(self, nodes: list[IaCNode]) -> None:
        for node in nodes:
            assert node.children == ()


class TestDockerfileParserNodeIds:
    @pytest.fixture()
    def nodes(self) -> list[IaCNode]:
        parser = DockerfileParser()
        return parser.parse(FIXTURES / "Dockerfile.vulnerable")

    def test_ids_are_unique(self, nodes: list[IaCNode]) -> None:
        ids = [n.node_id for n in nodes]
        assert len(ids) == len(set(ids))

    def test_id_format(self, nodes: list[IaCNode]) -> None:
        for node in nodes:
            parts = node.node_id.split(".")
            assert len(parts) == 4
            assert parts[0] == "dockerfile"

    def test_sequential_indexing(self, nodes: list[IaCNode]) -> None:
        run_nodes = [n for n in nodes if n.resource_type == "RUN"]
        indices = [int(n.node_id.split(".")[-1]) for n in run_nodes]
        assert indices == [0, 1, 2, 3]


class TestDockerfileParserLineNumbers:
    @pytest.fixture()
    def nodes(self) -> list[IaCNode]:
        parser = DockerfileParser()
        return parser.parse(FIXTURES / "Dockerfile.vulnerable")

    def test_from_line(self, nodes: list[IaCNode]) -> None:
        node = nodes[0]
        assert node.resource_type == "FROM"
        assert node.line == 2

    def test_first_env_line(self, nodes: list[IaCNode]) -> None:
        env_nodes = [n for n in nodes if n.resource_type == "ENV"]
        assert env_nodes[0].line == 5

    def test_cmd_line(self, nodes: list[IaCNode]) -> None:
        cmd = next(n for n in nodes if n.resource_type == "CMD")
        assert cmd.line == 25


class TestDockerfileParserFromInstruction:
    @pytest.fixture()
    def from_node(self) -> IaCNode:
        parser = DockerfileParser()
        nodes = parser.parse(FIXTURES / "Dockerfile.vulnerable")
        return next(n for n in nodes if n.resource_type == "FROM")

    def test_image_name(self, from_node: IaCNode) -> None:
        assert from_node.attributes["image"] == "python"

    def test_tag_extracted(self, from_node: IaCNode) -> None:
        assert from_node.attributes["tag"] == "latest"

    def test_from_no_tag_defaults_to_latest(self, tmp_path: Path) -> None:
        df = tmp_path / "Dockerfile"
        df.write_text("FROM alpine\n")
        node = DockerfileParser().parse(df)[0]
        assert node.attributes["tag"] == "latest"

    def test_from_with_digest(self, tmp_path: Path) -> None:
        df = tmp_path / "Dockerfile"
        df.write_text("FROM python@sha256:abcdef1234567890\n")
        node = DockerfileParser().parse(df)[0]
        assert node.attributes["image"] == "python"
        assert node.attributes["digest"] == "sha256:abcdef1234567890"

    def test_from_with_alias(self, tmp_path: Path) -> None:
        df = tmp_path / "Dockerfile"
        df.write_text("FROM python:3.12-slim AS builder\n")
        node = DockerfileParser().parse(df)[0]
        assert node.attributes["image"] == "python"
        assert node.attributes["tag"] == "3.12-slim"
        assert node.attributes["alias"] == "builder"


class TestDockerfileParserEnvInstruction:
    @pytest.fixture()
    def env_nodes(self) -> list[IaCNode]:
        parser = DockerfileParser()
        nodes = parser.parse(FIXTURES / "Dockerfile.vulnerable")
        return [n for n in nodes if n.resource_type == "ENV"]

    def test_secret_key_parsed(self, env_nodes: list[IaCNode]) -> None:
        attrs = env_nodes[0].attributes
        assert "AWS_SECRET_ACCESS_KEY" in attrs
        assert attrs["AWS_SECRET_ACCESS_KEY"] == "AKIAIOSFODNN7EXAMPLE"

    def test_database_url_parsed(self, env_nodes: list[IaCNode]) -> None:
        attrs = env_nodes[1].attributes
        assert "DATABASE_URL" in attrs
        assert "supersecret" in attrs["DATABASE_URL"]

    def test_safe_env_parsed(self, env_nodes: list[IaCNode]) -> None:
        attrs = env_nodes[2].attributes
        assert attrs["APP_NAME"] == "cloudspill"


class TestDockerfileParserRunInstruction:
    @pytest.fixture()
    def run_nodes(self) -> list[IaCNode]:
        parser = DockerfileParser()
        nodes = parser.parse(FIXTURES / "Dockerfile.vulnerable")
        return [n for n in nodes if n.resource_type == "RUN"]

    def test_run_count(self, run_nodes: list[IaCNode]) -> None:
        assert len(run_nodes) == 4

    def test_command_attribute(self, run_nodes: list[IaCNode]) -> None:
        assert run_nodes[0].attributes["command"] == "apt-get update"
        assert "curl wget" in run_nodes[1].attributes["command"]


class TestDockerfileParserAddCopy:
    @pytest.fixture()
    def nodes(self) -> list[IaCNode]:
        parser = DockerfileParser()
        return parser.parse(FIXTURES / "Dockerfile.vulnerable")

    def test_add_attributes(self, nodes: list[IaCNode]) -> None:
        add_node = next(n for n in nodes if n.resource_type == "ADD")
        assert add_node.attributes["src"] == "./app"
        assert add_node.attributes["dst"] == "/opt/app"

    def test_copy_attributes(self, nodes: list[IaCNode]) -> None:
        copy_node = next(n for n in nodes if n.resource_type == "COPY")
        assert copy_node.attributes["src"] == "./config"
        assert copy_node.attributes["dst"] == "/opt/config"


class TestDockerfileParserEdgeCases:
    def test_empty_dockerfile(self, tmp_path: Path) -> None:
        df = tmp_path / "Dockerfile"
        df.write_text("")
        assert DockerfileParser().parse(df) == []

    def test_comments_only(self, tmp_path: Path) -> None:
        df = tmp_path / "Dockerfile"
        df.write_text("# just a comment\n# another comment\n")
        assert DockerfileParser().parse(df) == []

    def test_multiline_continuation(self, tmp_path: Path) -> None:
        df = tmp_path / "Dockerfile"
        df.write_text(
            "FROM alpine:3.18\nRUN apk add --no-cache \\\n    curl \\\n    wget\n"
        )
        nodes = DockerfileParser().parse(df)
        run_node = next(n for n in nodes if n.resource_type == "RUN")
        assert "curl" in run_node.attributes["command"]
        assert "wget" in run_node.attributes["command"]
        assert run_node.line == 2

    def test_user_instruction_parsed(self, tmp_path: Path) -> None:
        df = tmp_path / "Dockerfile"
        df.write_text("FROM alpine\nUSER nobody\n")
        nodes = DockerfileParser().parse(df)
        user_node = next(n for n in nodes if n.resource_type == "USER")
        assert user_node.attributes["user"] == "nobody"

    def test_node_is_immutable(self, tmp_path: Path) -> None:
        df = tmp_path / "Dockerfile"
        df.write_text("FROM alpine\n")
        nodes = DockerfileParser().parse(df)
        with pytest.raises(AttributeError):
            nodes[0].name = "hacked"  # type: ignore[misc]
