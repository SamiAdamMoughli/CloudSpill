![CloudSpill logo](https://github.com/SamiAdamMoughli/CloudSpill/blob/main/logo_cloudspill.png?raw=true)

# CloudSpill

**Static Application Security Testing Engine for Infrastructure-as-Code**

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-448%20passing-brightgreen.svg)](cloudspill/tests/)

CloudSpill parses Terraform configurations and Dockerfiles into a typed AST, builds a directed acyclic graph of resource dependencies, runs structural security rules, and traces how misconfigurations propagate through your infrastructure via taint analysis.

It is not a regex scanner. It reasons about structure.

---

## Features

- **Structural analysis** — typed AST over Terraform resources and Dockerfile instructions; no regex
- **Resource graph** — directed acyclic graph of references, attachments, and `depends_on` edges
- **Taint engine** — BFS propagation traces how a single misconfiguration reaches downstream resources
- **36+ rules** — AWS (S3, IAM, EC2, RDS, Docker) and Azure (NSG, Storage, DB, VM, RBAC, Function App)
- **AI enrichment** — optional LLM analysis via Ollama, OpenAI, Anthropic, or Google Gemini
- **Graph visualisation** — `--graph` outputs a Mermaid diagram with severity-coloured nodes and taint overlays
- **Multiple output formats** — Rich terminal table, JSON, Markdown
- **CI/CD integration** — `--fail-on CRITICAL` exits with code 1 on matching severity

---

## Quickstart

```bash
git clone https://github.com/SamiAdamMoughli/CloudSpill
cd CloudSpill

python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run the test suite
pytest

# Scan the bundled vulnerable fixtures
cloudspill cloudspill/tests/fixtures/examples/vulneable-aws-stack/ --show-taint
cloudspill cloudspill/tests/fixtures/examples/vulneable-azure-stack/ --rules az --show-taint
```

---

## Usage

```bash
# Scan a directory or single file
cloudspill ./infrastructure/
cloudspill main.tf

# Filter by severity
cloudspill ./infra --min-severity HIGH

# Target specific rule sets (comma-separated)
cloudspill ./infra --rules s3,iam,ec2
cloudspill ./infra --rules az               # Azure rules only

# Output formats
cloudspill ./infra --format table           # Rich table (default)
cloudspill ./infra --format json            # Machine-readable
cloudspill ./infra --format markdown        # Report file

# Show taint propagation paths
cloudspill ./infra --show-taint

# Visualise the resource graph (paste into mermaid.live or GitHub markdown)
cloudspill ./infra --graph
cloudspill ./infra --graph --graph-file diagram.md

# Exit code 1 if findings at or above this severity (CI/CD)
cloudspill ./infra --fail-on CRITICAL
```

---

## AI Enrichment

CloudSpill can enrich findings with LLM-generated explanations and remediation patches. Four providers are supported.

### Local (Ollama / vLLM / LM Studio)

```bash
# Start Ollama first, then:
cloudspill ./infra --ai --model qwen3:8b
cloudspill ./infra --ai --model gemma3:12b --ai-url http://localhost:1234/v1
```

### OpenAI

```bash
export CLOUDSPILL_API_KEY=sk-...
cloudspill ./infra --ai --provider openai --model gpt-4o
```

### Anthropic

```bash
export CLOUDSPILL_API_KEY=sk-ant-...
cloudspill ./infra --ai --provider anthropic --model claude-haiku-4-5-20251001
```

### Google Gemini

```bash
export CLOUDSPILL_API_KEY=...
cloudspill ./infra --ai --provider google --model gemini-3.5-flash

# Free-tier rate limiting (10 RPM): pace requests to avoid 429s
cloudspill ./infra --ai --provider google --ai-rpm 9
```

### Prompt modes

| Mode | Description |
|---|---|
| `explain` | Plain-English risk explanation covering what is wrong and the blast radius (default) |
| `fix` | Minimal copy-paste Terraform / Dockerfile remediation snippet |
| `triage` | True-positive / false-positive verdict with evidence from source context |

```bash
cloudspill ./infra --ai --provider google --prompt-mode fix
cloudspill ./infra --ai --provider anthropic --prompt-mode triage
```

If no inference server is reachable, CloudSpill falls back gracefully and continues without AI enrichment.

---

## Architecture

```mermaid
flowchart TD
    A([fa:fa-folder IaC Files\n.tf · Dockerfile]) --> B

    subgraph PARSE ["1 · Parse"]
        B[ParserRegistry\ndispatches by file type]
        B --> B1[TerraformParser]
        B --> B2[DockerfileParser]
        B1 & B2 --> C[/"list[IaCNode]\ntyped AST tree"/]
    end

    subgraph GRAPH ["2 · Graph"]
        C --> D[ResourceGraph.build\nscans attribute refs\n& depends_on]
        D --> E[/"ResourceGraph\nDAG with typed edges\nATTRIBUTE_REF · DEPENDS_ON\nATTACHMENT · SECURITY_GROUP"/]
    end

    subgraph RULES ["3 · Rules"]
        E --> F[RuleEngine\nvisits every node × rule\nauto-discovered via @register]
        F --> G[/"list[Finding]\nrule_id · severity · resource\ntags · remediation"/]
    end

    subgraph TAINT ["4 · Taint"]
        G --> H[TaintEngine\nBFS forward through DAG]
        E --> H
        H --> I[/"list[TaintResult]\npropagation paths\nwith risk summaries"/]
    end

    subgraph ENRICH ["5 · Enrich  (optional)"]
        G & I & E --> J[AIEnricher\nOllama · OpenAI · Anthropic · Gemini\ngraceful fallback on error]
        J --> K[/"list[EnrichedFinding]\nexplanation · patch · confidence"/]
    end

    subgraph OUT ["6 · Output"]
        G & I & K --> L{Formatter}
        L --> L1[Table\nRich terminal]
        L --> L2[JSON\nmachine-readable]
        L --> L3[Markdown\nCI report]
        L --> L4[Mermaid\ngraph diagram]
    end

    ScanResult["ScanResult\nfindings · taint_results\nenriched_findings · metadata\n— filter by severity —"]
    I --> ScanResult
    G --> ScanResult
    K --> ScanResult
    ScanResult --> OUT

    style PARSE fill:#1e293b,stroke:#334155,color:#94a3b8
    style GRAPH fill:#1e293b,stroke:#334155,color:#94a3b8
    style RULES fill:#1e293b,stroke:#334155,color:#94a3b8
    style TAINT fill:#1e293b,stroke:#334155,color:#94a3b8
    style ENRICH fill:#1e293b,stroke:#334155,color:#94a3b8
    style OUT fill:#1e293b,stroke:#334155,color:#94a3b8
    style ScanResult fill:#0f172a,stroke:#6366f1,color:#a5b4fc
```

---

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run the full test suite (448 tests)
pytest cloudspill/tests/

# Type checking
mypy --strict cloudspill/

# Linting and formatting
pylint cloudspill/ --ignore=tests
black --check cloudspill/
isort --check --profile black cloudspill/

# Security audit
bandit -r cloudspill/
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions, coding standards, and how to add new rules, parsers, or providers.

---

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md).

---

## Ethical Use

CloudSpill is a static analysis tool for infrastructure code you own or have explicit written authorisation to audit. It performs no active scanning, no network connections to target infrastructure, and no live infrastructure interaction. All analysis is performed on configuration files at rest.

---

## License

[MIT](LICENSE)
