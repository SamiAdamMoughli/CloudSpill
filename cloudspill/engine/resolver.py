"""ConfigResolver — resolves variables, locals, conditionals, and local modules.

CloudSpill parses HCL into typed nodes but does not, on its own, evaluate any
expressions: a security group whose CIDR is ``[var.ssh_cidr]`` reaches the rules
as the literal string ``"${var.ssh_cidr}"``, so the rule never fires even when
the resolved value is ``0.0.0.0/0``. That is a false negative on the kind of
parameterised configuration almost all real Terraform uses.

This pass closes that gap. After parsing and before graph construction it:

  1. Builds a variable scope per root directory from ``variable`` defaults
     overridden by ``*.tfvars`` / ``*.auto.tfvars``.
  2. Evaluates ``locals`` against that scope.
  3. Expands local ``module`` blocks (``./`` or ``../`` sources): the module's
     files are parsed and resolved in their own scope, seeded by the module
     block's arguments.
  4. Rewrites every resource/data attribute by evaluating interpolation
     expressions (``${...}``) against the scope.

Anything it cannot resolve (remote modules, function calls, unknown refs) is
left exactly as it was, so the pass is safe and purely additive: literal
configurations are unchanged.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import hcl2

from cloudspill.engine.hcl_expr import Unresolvable, evaluate
from cloudspill.models.nodes import IaCNode
from cloudspill.parsers.terraform import (
    TerraformParser,
    _clean_value,
    _strip_hcl2_quotes,
)

logger = logging.getLogger(__name__)

_INTERP_RE = re.compile(r"\$\{([^{}]*)\}")
_FULL_INTERP_RE = re.compile(r"^\$\{([^{}]*)\}$", re.DOTALL)


@dataclass(frozen=True)
class _Scope:
    """Resolved variable and local values for a single module instance."""

    variables: dict[str, Any] = field(default_factory=dict)
    locals: dict[str, Any] = field(default_factory=dict)

    def resolve_ref(self, ref: str) -> Any:
        if ref.startswith("var."):
            key = ref[4:]
            if key in self.variables:
                return self.variables[key]
        elif ref.startswith("local."):
            key = ref[6:]
            if key in self.locals:
                return self.locals[key]
        raise Unresolvable(ref)


class ConfigResolver:
    """Resolves expressions in parsed nodes. See module docstring."""

    def __init__(self) -> None:
        self._parser = TerraformParser()
        self._raw_cache: dict[Path, list[dict[str, Any]]] = {}

    # -- public API -------------------------------------------------------- #
    def resolve(self, nodes: list[IaCNode]) -> list[IaCNode]:
        """Return a new node list with expressions resolved where possible."""
        terraform, other = self._partition(nodes)
        resolved: list[IaCNode] = list(other)

        for directory, dir_nodes in self._group_by_dir(terraform).items():
            resolved.extend(
                self._resolve_directory(dir_nodes, directory, visited={directory})
            )

        return resolved

    def _resolve_directory(
        self,
        dir_nodes: list[IaCNode],
        directory: Path,
        visited: set[Path],
        arg_overrides: dict[str, Any] | None = None,
    ) -> list[IaCNode]:
        scope = self._build_scope(directory, arg_overrides)
        out: list[IaCNode] = []

        # The parser cannot represent `module` blocks (it shreds their arguments
        # into bogus nodes), so those nodes are dropped and modules are expanded
        # from raw HCL below.
        for node in dir_nodes:
            if node.node_type == "module":
                continue
            out.append(self._resolve_node(node, scope))

        for args in self._collect_modules(directory):
            out.extend(self._expand_module(args, directory, scope, visited))

        return out

    # -- scope construction ------------------------------------------------ #
    def _build_scope(
        self, directory: Path, arg_overrides: dict[str, Any] | None = None
    ) -> _Scope:
        variables: dict[str, Any] = {}
        local_exprs: dict[str, Any] = {}

        for raw in self._dir_raw(directory):
            self._collect_variables(raw, variables)
            self._collect_locals(raw, local_exprs)

        variables.update(self._load_tfvars(directory))
        if arg_overrides:
            variables.update(arg_overrides)

        scope = _Scope(variables=variables, locals={})
        scope = replace(scope, locals=self._evaluate_locals(local_exprs, scope))
        return scope

    def _collect_variables(self, raw: dict[str, Any], out: dict[str, Any]) -> None:
        for block in raw.get("variable", []):
            if not isinstance(block, dict):
                continue
            for raw_name, body in block.items():
                name = _strip_hcl2_quotes(raw_name)
                if name.startswith("__") or not isinstance(body, dict):
                    continue
                if "default" in body:
                    out[name] = _clean_value(body["default"])

    def _collect_locals(self, raw: dict[str, Any], out: dict[str, Any]) -> None:
        for block in raw.get("locals", []):
            if not isinstance(block, dict):
                continue
            for raw_name, expr in block.items():
                name = _strip_hcl2_quotes(raw_name)
                if name.startswith("__"):
                    continue
                out[name] = _clean_value(expr)

    def _collect_modules(self, directory: Path) -> list[dict[str, Any]]:
        """Return each module block in a directory as a cleaned arg dict."""
        modules: list[dict[str, Any]] = []
        for raw in self._dir_raw(directory):
            for block in raw.get("module", []):
                if not isinstance(block, dict):
                    continue
                for raw_name, body in block.items():
                    name = _strip_hcl2_quotes(raw_name)
                    if name.startswith("__") or not isinstance(body, dict):
                        continue
                    modules.append(
                        {
                            _strip_hcl2_quotes(k): _clean_value(v)
                            for k, v in body.items()
                            if not k.startswith("__")
                        }
                    )
        return modules

    def _evaluate_locals(self, exprs: dict[str, Any], scope: _Scope) -> dict[str, Any]:
        """Resolve locals iteratively so they can reference one another."""
        resolved: dict[str, Any] = {}
        pending = dict(exprs)
        for _ in range(len(pending) + 1):
            if not pending:
                break
            current = _Scope(variables=scope.variables, locals=resolved)
            progressed = False
            for name, expr in list(pending.items()):
                value = self._eval_value(expr, current)
                if not _still_unresolved(value, expr):
                    resolved[name] = value
                    del pending[name]
                    progressed = True
            if not progressed:
                break
        for name, expr in pending.items():  # best-effort partial resolution
            resolved[name] = self._eval_value(expr, _Scope(scope.variables, resolved))
        return resolved

    def _load_tfvars(self, directory: Path) -> dict[str, Any]:
        values: dict[str, Any] = {}
        files = sorted(directory.glob("*.auto.tfvars")) + [
            directory / "terraform.tfvars"
        ]
        for path in files:
            if not path.exists():
                continue
            try:
                with open(path, encoding="utf-8") as handle:
                    raw = hcl2.load(handle)
            except (OSError, ValueError) as exc:
                logger.warning("Could not read tfvars %s: %s", path, exc)
                continue
            except Exception as exc:  # pylint: disable=broad-except
                logger.warning("Could not parse tfvars %s: %s", path, exc)
                continue
            for key, value in raw.items():
                if key.startswith("__"):
                    continue
                values[_strip_hcl2_quotes(key)] = _clean_value(value)
        return values

    # -- module expansion -------------------------------------------------- #
    _MODULE_META = frozenset(
        {"source", "version", "providers", "count", "for_each", "depends_on"}
    )

    def _expand_module(
        self,
        args: dict[str, Any],
        base_dir: Path,
        parent_scope: _Scope,
        visited: set[Path],
    ) -> list[IaCNode]:
        source = args.get("source")
        clean_source = self._eval_value(source, parent_scope)
        if not isinstance(clean_source, str) or not clean_source.startswith((".", "/")):
            logger.debug("Skipping non-local module source: %r", source)
            return []  # remote / registry module — out of scope

        module_dir = (base_dir / clean_source).resolve()
        if module_dir in visited:
            logger.debug("Skipping already-visited module: %s", module_dir)
            return []
        if not module_dir.is_dir():
            logger.warning(
                "Local module source not found: %s (referenced from %s)",
                module_dir,
                base_dir,
            )
            return []

        logger.debug("Expanding module %s", module_dir)
        arg_overrides = {
            key: self._eval_value(val, parent_scope)
            for key, val in args.items()
            if key not in self._MODULE_META
        }

        module_nodes: list[IaCNode] = []
        for tf_file in sorted(module_dir.glob("*.tf")):
            module_nodes.extend(self._parser.parse(tf_file))

        terraform, _ = self._partition(module_nodes)
        return self._resolve_directory(
            terraform, module_dir, visited | {module_dir}, arg_overrides
        )

    def _resolve_node(self, node: IaCNode, scope: _Scope) -> IaCNode:
        new_attrs = {k: self._eval_value(v, scope) for k, v in node.attributes.items()}
        new_children = tuple(self._resolve_node(c, scope) for c in node.children)
        return replace(node, attributes=new_attrs, children=new_children)

    # -- expression evaluation -------------------------------------------- #
    def _eval_value(self, value: Any, scope: _Scope) -> Any:
        if isinstance(value, list):
            return [self._eval_value(item, scope) for item in value]
        if isinstance(value, dict):
            return {k: self._eval_value(v, scope) for k, v in value.items()}
        if not isinstance(value, str) or "${" not in value:
            return value

        full = _FULL_INTERP_RE.match(value)
        if full:
            try:
                return evaluate(full.group(1).strip(), scope.resolve_ref)
            except Unresolvable:
                return value

        # Mixed string: substitute each interpolation we can resolve.
        def _sub(match: re.Match[str]) -> str:
            try:
                return str(evaluate(match.group(1).strip(), scope.resolve_ref))
            except Unresolvable:
                return match.group(0)

        return _INTERP_RE.sub(_sub, value)

    # -- helpers ----------------------------------------------------------- #
    @staticmethod
    def _partition(nodes: list[IaCNode]) -> tuple[list[IaCNode], list[IaCNode]]:
        terraform: list[IaCNode] = []
        other: list[IaCNode] = []
        for node in nodes:
            bucket = terraform if str(node.source_file).endswith(".tf") else other
            bucket.append(node)
        return terraform, other

    @staticmethod
    def _group_by_dir(nodes: list[IaCNode]) -> dict[Path, list[IaCNode]]:
        grouped: dict[Path, list[IaCNode]] = {}
        for node in nodes:
            directory = Path(node.source_file).resolve().parent
            grouped.setdefault(directory, []).append(node)
        return grouped

    def _dir_raw(self, directory: Path) -> list[dict[str, Any]]:
        """Raw hcl2 dicts for every .tf in a directory, cached per directory."""
        if directory not in self._raw_cache:
            raws: list[dict[str, Any]] = []
            for path in sorted(directory.glob("*.tf")):
                try:
                    with open(path, encoding="utf-8") as handle:
                        raws.append(hcl2.load(handle))
                except Exception as exc:  # pylint: disable=broad-except
                    # Unparseable .tf is already reported by the parser stage;
                    # here we just skip it for scope-building and note why.
                    logger.debug("Skipping %s for scope build: %s", path, exc)
                    continue
            self._raw_cache[directory] = raws
        return self._raw_cache[directory]


def _still_unresolved(value: Any, original: Any) -> bool:
    """True if evaluation made no progress (still contains interpolation)."""
    return isinstance(value, str) and "${" in value and value == original
