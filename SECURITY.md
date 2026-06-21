# Security Policy

CloudSpill is a static analysis tool that people run against their own
infrastructure code, often in CI. A vulnerability here — a crash on crafted
input, a path-traversal during file collection, or a rule that silently stops
firing — can weaken the security posture of everyone who depends on it. We take
reports seriously and appreciate your help.

## Supported versions

CloudSpill is pre-1.0 and ships fixes only on the latest release line. Security
fixes are applied to `main` and the most recent tagged release.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a vulnerability

**Please do not open a public GitHub issue for a security vulnerability.**

Report privately through one of:

- GitHub's **[Report a vulnerability](https://github.com/SamiAdamMoughli/CloudSpill/security/advisories/new)**
  flow (preferred — Security → Advisories → Report a vulnerability), or
- email **arctic.pine.44@proton.me** with the subject line `CloudSpill security`.

Please include:

- a description of the issue and its impact,
- the version / commit you tested,
- a minimal reproduction (a small `.tf` / `Dockerfile` snippet and the command
  you ran), and
- any suggested remediation if you have one.

## What to expect

- **Acknowledgement** within **3 business days**.
- An initial assessment (severity, affected versions) within **7 business days**.
- We aim to ship a fix or a documented mitigation within **30 days** of
  triage; complex issues may take longer, and we'll keep you updated.
- We'll credit you in the release notes / advisory unless you ask us not to.

We follow **coordinated disclosure**: please give us a reasonable window to
release a fix before any public write-up.

## In scope

- Crashes, hangs, or unbounded resource use triggered by crafted IaC input.
- Path traversal, arbitrary file read/write, or code execution during parsing,
  config resolution (variables / `locals` / local module expansion), or file
  collection.
- Exposure of secrets handled by the tool (e.g. `--api-key`, environment
  variables) in logs, output, or error messages.
- A rule that fails to fire on a clear violation (a false negative) — these are
  security-relevant for a scanner; report them and we'll treat them as bugs.

## Out of scope

- Findings reported **by** CloudSpill about your own infrastructure — those are
  the tool working as intended; fix them in your IaC.
- Vulnerabilities in third-party dependencies with no CloudSpill-specific
  impact (report those upstream; we'll bump the dependency).
- Security of an LLM endpoint you configure via `--ai` / `--provider`; CloudSpill
  sends finding context to the backend you choose, so vet that backend yourself.
- Issues requiring a pre-compromised host, a malicious local Python environment,
  or running the tool on infrastructure code you do not trust without review.

## A note on AI enrichment

The optional `--ai` feature sends finding details and a window of surrounding
source to the LLM provider you select (local Ollama, OpenAI, Anthropic, or
Google). Treat that as sending the relevant snippet of your IaC to that
provider, and do not enable it against sensitive code with a backend you do not
trust.
