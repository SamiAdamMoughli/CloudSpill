# CloudSpill

**Static Application Security Testing Engine for Infrastructure-as-Code**

CloudSpill parses Terraform configurations and Dockerfiles into a typed AST, builds a directed acyclic graph of resource dependencies, and performs taint analysis to trace how security misconfigurations propagate through your infrastructure.

It is not a regex scanner. It reasons about structure.

## Installation

```bash
pip install -e ".[dev]"
```

## Usage

```bash
# Scan a directory
cloudspill scan ./infrastructure/

# Output formats
cloudspill scan ./infra --format table       # Rich table (default)
cloudspill scan ./infra --format json        # Machine-readable
cloudspill scan ./infra --format markdown    # Report file

# Filter by severity
cloudspill scan ./infra --min-severity HIGH

# Show taint propagation paths
cloudspill scan ./infra --show-taint

# Target specific rule sets
cloudspill scan ./infra --rules s3,iam

# Exit code 1 if findings above threshold (CI/CD)
cloudspill scan ./infra --fail-on CRITICAL
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full pipeline design, data model, and design rationale.

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Type checking
mypy --strict cloudspill/

# Linting
pylint cloudspill/
black --check cloudspill/ tests/
isort --check cloudspill/ tests/

# Security audit
bandit -r cloudspill/
```

## Ethical Use

CloudSpill is a static analysis tool for infrastructure code you own or have explicit written authorisation to audit. It performs no active scanning, no network connections, and no live infrastructure interaction. All analysis is performed on configuration files at rest.

## License

[MIT](LICENSE)