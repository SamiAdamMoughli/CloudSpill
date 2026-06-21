# CloudSpill — Revised Architecture

## Core Principles

1. **Each pipeline stage produces immutable output consumed by the next.** No stage mutates another stage's data.
2. **The graph carries typed edges.** Taint rules depend on *why* two nodes connect.
3. **Findings and taint results are separate models.** The reporter joins them at the end.
4. **A `ScanContext` owns the full lifecycle** — parsers, graph, engine, reporter are stateless workers that receive context.
5. **Everything is a protocol.** Parsers, rules, formatters, enrichers — all pluggable via structural subtyping.

---

## Directory Structure

```
bastion-project/
├── .gitignore
├── .pre-commit-config.yaml
├── ARCHITECTURE.md
├── CONTRIBUTING.md
├── LICENSE
├── README.md
├── pyproject.toml
├── cloudspill/
│   ├── __init__.py
│   ├── py.typed                # PEP 561 — declares typed package
│   ├── cli.py                  # Click entry point — thin, delegates to ScanContext
│   ├── context.py              # ScanContext: owns scan lifecycle and pipeline
│   ├── models/
│   │   ├── __init__.py
│   │   ├── nodes.py            # IaCNode (with optional children for nesting)
│   │   ├── findings.py         # Finding, Severity (rule engine output only)
│   │   ├── taint.py            # TaintResult, TaintPath (taint engine output only)
│   │   └── graph.py            # Edge, EdgeKind enum, ResourceGraph
│   ├── parsers/
│   │   ├── __init__.py
│   │   ├── base.py             # Parser Protocol
│   │   ├── terraform.py        # HCL → IaCNode tree
│   │   ├── docker.py           # Dockerfile → IaCNode tree
│   │   └── registry.py         # ParserRegistry: file extension → parser
│   ├── rules/
│   │   ├── __init__.py         # RuleRegistry: collects + exposes all rules
│   │   ├── base.py             # Rule Protocol + @register decorator
│   │   └── aws/                # modular, per-service rule packages
│   │       ├── utils/          # shared helpers (hcl.py, policy.py)
│   │       ├── s3/  iam/  ec2/  rds/  vpc/  kms/  lambda_svc/
│   │       ├── dynamodb/  ecs_fargate/  cloudfront/  api_gateway/
│   │       └── cloudtrail/  sns_sqs/  secrets_manager/  guardduty/  organizations/
│   ├── engine/
│   │   ├── __init__.py
│   │   ├── rule_engine.py      # Walks nodes × rules → list[Finding]
│   │   └── taint_engine.py     # BFS over graph from findings → list[TaintResult]
│   ├── enrichers/
│   │   ├── __init__.py
│   │   ├── base.py             # Enricher Protocol (optional post-processing)
│   │   └── ai.py               # LLM enricher (Gemma 4 / Qwen — opt-in)
│   └── output/
│       ├── __init__.py
│       ├── base.py             # Formatter Protocol
│       ├── table.py            # Rich table formatter
│       ├── json.py             # JSON formatter
│       └── markdown.py         # Markdown report formatter
└── tests/
    ├── __init__.py
    ├── fixtures/
    │   ├── s3_public.tf
    │   ├── iam_wildcard.tf
    │   ├── full_stack.tf       # Multi-resource with cross-references
    │   └── Dockerfile.vulnerable
    ├── test_parsers.py
    ├── test_graph.py
    ├── test_rules.py
    ├── test_taint.py
    ├── test_enrichers.py
    └── test_output.py
```

---

## Data Flow (each arrow = immutable handoff)

```
files on disk
    │
    ▼
ParserRegistry.parse_all(paths)
    │  returns: list[IaCNode]  (tree-structured, with children)
    ▼
ResourceGraph.build(nodes)
    │  returns: ResourceGraph  (nodes + typed edges)
    ▼
RuleEngine.evaluate(nodes, graph)
    │  returns: list[Finding]  (no taint data — just rule violations)
    ▼
TaintEngine.propagate(findings, graph)
    │  returns: list[TaintResult]  (source finding + full path + risk)
    ▼
Enricher.enrich(findings, taint_results, graph)   ← OPTIONAL
    │  returns: list[EnrichedFinding]
    ▼
Formatter.format(findings, taint_results)
    │  returns: str | None (prints or writes)
```

---

## Key Model Changes

### IaCNode — supports nesting

```python
@dataclass(frozen=True)
class IaCNode:
    node_id: str              # "aws_s3_bucket.data"
    node_type: str            # "resource" | "data" | "variable" | "local" | "output" | "module"
    resource_type: str        # "aws_s3_bucket" | "" for non-resources
    name: str
    attributes: dict[str, Any]
    children: tuple[IaCNode, ...]  # nested blocks (provisioners, inline policies, etc.)
    source_file: str
    line: int
```

Using `tuple` (not list) because the node is frozen.

### Edge — typed relationships

```python
class EdgeKind(Enum):
    ATTRIBUTE_REF = "attribute_ref"   # ${aws_s3_bucket.data.arn}
    DEPENDS_ON = "depends_on"         # explicit depends_on
    ATTACHMENT = "attachment"          # iam_role_policy_attachment
    MODULE_OUTPUT = "module_output"   # module.x.output_y
    SECURITY_GROUP = "security_group" # vpc_security_group_ids

@dataclass(frozen=True)
class Edge:
    source: str       # node_id of referencing resource
    target: str       # node_id of referenced resource
    kind: EdgeKind
    attribute: str    # which attribute created this edge
```

### Finding — clean, no taint

```python
@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    title: str
    description: str
    resource: str          # node_id
    file: str
    line: int
```

No `taint_path` field. Findings are pure rule output.

### TaintResult — taint engine output

```python
@dataclass(frozen=True)
class TaintResult:
    finding: Finding       # the originating finding
    paths: tuple[TaintPath, ...]  # all propagation paths from this finding

@dataclass(frozen=True)
class TaintPath:
    nodes: tuple[str, ...]        # node_ids from source → sink
    edges: tuple[EdgeKind, ...]   # how each hop connects
    risk: str                     # human-readable risk summary
```

---

## ScanContext — orchestrator

```python
class ScanContext:
    """Owns the full scan pipeline. Stateless workers, stateful context."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._parser_registry = ParserRegistry()
        self._rule_registry = RuleRegistry(enabled=config.rule_sets)
        self._enrichers: list[Enricher] = []

    def run(self, paths: list[Path]) -> ScanResult:
        nodes = self._parser_registry.parse_all(paths)
        graph = ResourceGraph.build(nodes)
        findings = RuleEngine(self._rule_registry).evaluate(nodes, graph)
        taint_results = TaintEngine(graph).propagate(findings)
        # enrichers are optional — loop is a no-op if empty
        for enricher in self._enrichers:
            enricher.enrich(findings, taint_results, graph)
        return ScanResult(findings=findings, taint_results=taint_results, graph=graph)
```

The CLI becomes a thin wrapper that builds a `ScanConfig`, creates a `ScanContext`, calls `run()`, and passes the result to a `Formatter`.

---

## Why this is better

| Problem in v1 | Fix in v2 |
|---|---|
| `Finding.taint_path` couples two pipeline stages | `Finding` and `TaintResult` are separate models |
| Flat node list loses block nesting | `IaCNode.children` preserves hierarchy |
| Untyped edges break taint reasoning | `Edge` + `EdgeKind` give semantic meaning |
| No scan lifecycle owner | `ScanContext` orchestrates the pipeline |
| AI engine hardwired into CLI | `Enricher` protocol — AI is one implementation, zero cost if unused |
| Monolithic `Reporter` class | `Formatter` protocol with one class per output format |
| Rule discovery undefined | `RuleRegistry` with explicit collection and filtering |