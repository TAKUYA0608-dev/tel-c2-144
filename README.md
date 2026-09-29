# TEL-C2-144 — Telecom Base-Station Anomaly Evidence Escalation Router

> **Category**: Cat 2 (domain workflow (a job to be done))
> **Industry**: Telecom

## Overview

Escalation routing for a completed base-station anomaly evidence packet. Given a JSON packet, the agent minimises subscriber and site data, resolves provenance once, quarantines free text as quoted evidence, reconciles the packet deterministically, interprets the escalation signals into a closed taxonomy, anchors every finding to a citation from a closed evidence index minted for this run, and proposes exactly one route from a seeded precedence policy — urgent owner escalation, evidence incomplete, duplicate or correlated candidate, change-context escalation, or standard engineering with the evidence that decided it. The signal interpretation is LLM-backed through the configured client; without one a seeded lexicon runs and the envelope discloses deterministic-fallback mode. Every route is proposed for a human owner's decision, an urgency claim is never demoted, a route whose findings cannot all be cited is withheld, and instruction-shaped request bodies are rejected outright. No evidence store is shipped — the packet travels with each request.

This is an agent template built with the **AGENTIC STAR** development platform and the
**AgentCore Framework**. It is intended to be taken as a starting point: fork it, adapt it to
your own data and policies, and run it inside your own AGENTIC STAR deployment.

## Requirements

**This template does not run standalone.** It requires:

| Requirement | Notes |
|---|---|
| **AGENTIC STAR platform** | The agent connects to the platform at start-up. Without it, start-up fails immediately (see *Behaviour without the platform* below). Deployment guides and API documentation: [AGENTIC STAR Developers](https://developers.fd.agenticstar.tm.softbank.jp/) |
| **AgentCore Framework** (`agenticstar-agentcore`) | Installed from PyPI as a dependency. |
| Python | 3.11 or later (`requires-python = ">=3.11"`) |

```bash
pip install -e .
```

### Behaviour without the platform

The framework is designed to run **only** on AGENTIC STAR. There is no fallback or degraded
mode. If the platform is unreachable or the SDK version does not match, the agent raises
`PlatformRequired` during graph compile / start-up preflight rather than starting in a partially
working state. This is intentional — a half-running agent is worse than one that refuses to start.

## Quick Start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest tests/ -v
```

Tests run without a platform connection. Running the agent itself does not.

## Project Structure

```
src/          agent implementation (nodes, services, schemas)
tests/        unit, integration and boundary tests
config/       agent configuration
docs/         design and operational documentation
```

See `docs/02_design.md` for the design and `docs/03_test_spec.md` for the test specification.

## Customising

1. Adjust `config/` for your own environment and policies.
2. Replace the knowledge sources and sample data with your own.
3. Review the node implementations under `src/nodes/` for domain-specific logic.
4. Re-run the test suite.

## License

MIT — see [LICENSE](LICENSE).

## Status of this repository

This template is published **as is**, by its individual author, under the MIT license. It carries
**no warranty and no support commitment**, and no organisation stands behind its behaviour or
fitness for any purpose. Issues and pull requests may or may not receive a response; that is at
the sole discretion of the repository owner.
