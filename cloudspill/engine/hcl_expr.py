"""A small HCL expression evaluator.

CloudSpill's parser hands attribute values to the rules verbatim. When an
attribute is an expression rather than a literal, hcl2 renders it wrapped in
interpolation syntax, e.g.:

    var.x                       -> "${var.x}"
    var.x ? "a" : "b"           -> "${var.x ? \"a\" : \"b\"}"
    "${local.prefix}-bucket"    -> "${local.prefix}-bucket"

This module evaluates the subset of HCL expression syntax that real-world IaC
uses to drive security-relevant attributes: variable / local references,
ternaries, equality and boolean operators, negation, and parentheses. Anything
outside that subset (function calls, splats, arithmetic, unknown references)
raises :class:`Unresolvable`, and the caller leaves the original text in place.

The evaluator is deliberately small. It is not a Terraform interpreter; it is
just enough to stop the scanner from going blind on parameterised configs.
"""

from __future__ import annotations

import re
from typing import Any, Callable

__all__ = ["Unresolvable", "evaluate"]


class Unresolvable(Exception):
    """Raised when an expression cannot be resolved to a concrete value."""


# --------------------------------------------------------------------------- #
# Tokeniser
# --------------------------------------------------------------------------- #
_TOKEN_RE = re.compile(
    r"""
      (?P<ws>\s+)
    | (?P<string>"(?:\\.|[^"\\])*")
    | (?P<number>-?\d+(?:\.\d+)?)
    | (?P<op>==|!=|&&|\|\||[?:!()])
    | (?P<ident>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_*]*)*)
    """,
    re.VERBOSE,
)

_KEYWORDS = {"true": True, "false": False, "null": None}


def _tokenize(expr: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    pos = 0
    for match in _TOKEN_RE.finditer(expr):
        if match.start() != pos:
            raise Unresolvable(f"unexpected character in {expr!r}")
        pos = match.end()
        kind = match.lastgroup
        if kind == "ws":
            continue
        assert kind is not None
        tokens.append((kind, match.group()))
    if pos != len(expr):
        raise Unresolvable(f"unexpected trailing input in {expr!r}")
    return tokens


# --------------------------------------------------------------------------- #
# Recursive-descent parser + evaluator (precedence climbing)
# --------------------------------------------------------------------------- #
class _Parser:  # pylint: disable=too-few-public-methods
    def __init__(
        self, tokens: list[tuple[str, str]], resolve_ref: Callable[[str], Any]
    ):
        self._tokens = tokens
        self._pos = 0
        self._resolve_ref = resolve_ref

    def _peek(self) -> tuple[str, str] | None:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else None

    def _advance(self) -> tuple[str, str]:
        tok = self._tokens[self._pos]
        self._pos += 1
        return tok

    def _expect(self, value: str) -> None:
        tok = self._peek()
        if tok is None or tok[1] != value:
            raise Unresolvable(f"expected {value!r}")
        self._advance()

    def parse(self) -> Any:
        value = self._ternary()
        if self._peek() is not None:
            raise Unresolvable("trailing tokens")
        return value

    def _ternary(self) -> Any:
        cond = self._or()
        tok = self._peek()
        if tok and tok[1] == "?":
            self._advance()
            true_val = self._ternary()
            self._expect(":")
            false_val = self._ternary()
            return true_val if _truthy(cond) else false_val
        return cond

    def _or(self) -> Any:
        left = self._and()
        while (tok := self._peek()) and tok[1] == "||":
            self._advance()
            right = self._and()
            left = _truthy(left) or _truthy(right)
        return left

    def _and(self) -> Any:
        left = self._equality()
        while (tok := self._peek()) and tok[1] == "&&":
            self._advance()
            right = self._equality()
            left = _truthy(left) and _truthy(right)
        return left

    def _equality(self) -> Any:
        left = self._unary()
        while (tok := self._peek()) and tok[1] in ("==", "!="):
            op = self._advance()[1]
            right = self._unary()
            left = (left == right) if op == "==" else (left != right)
        return left

    def _unary(self) -> Any:
        tok = self._peek()
        if tok and tok[1] == "!":
            self._advance()
            return not _truthy(self._unary())
        return self._primary()

    def _primary(self) -> Any:
        tok = self._peek()
        if tok is None:
            raise Unresolvable("unexpected end of expression")
        kind, text = tok
        if text == "(":
            self._advance()
            value = self._ternary()
            self._expect(")")
            return value
        self._advance()
        if kind == "string":
            return _unquote(text)
        if kind == "number":
            return float(text) if "." in text else int(text)
        if kind == "ident":
            if text in _KEYWORDS:
                return _KEYWORDS[text]
            return self._resolve_ref(text)
        raise Unresolvable(f"unexpected token {text!r}")


def _truthy(value: Any) -> bool:
    return bool(value)


def _unquote(text: str) -> str:
    return text[1:-1].replace('\\"', '"').replace("\\\\", "\\")


def evaluate(expr: str, resolve_ref: Callable[[str], Any]) -> Any:
    """Evaluate an HCL expression string.

    ``resolve_ref`` is called with a dotted reference (e.g. ``"var.region"``)
    and must return its value or raise :class:`Unresolvable`.
    """
    tokens = _tokenize(expr)
    if not tokens:
        raise Unresolvable("empty expression")
    return _Parser(tokens, resolve_ref).parse()
