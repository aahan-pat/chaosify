# Chaosify

Chaosify is a safe, namespace-scoped execution environment for Kubernetes security verification. It proves whether your Kubernetes guardrails actually work — not just whether they are configured — and serves as the controlled execution sandbox for OpenClaw-driven pentesting.

All execution is confined to a dedicated, RBAC-enforced test namespace. Chaosify structurally cannot touch any other namespace in the cluster.

## Installation

Requires Node.js ≥ 22.16.0.

```bash
npm install -g chaosify
```

To try without installing:

```bash
npx chaosify --help
```

## Docs

- [Architecture](docs/architecture.md) — system design, safety model, and multi-cluster model
- [Reference](docs/reference.md) — complete command reference, flags, and exit codes
- [Scenarios](docs/scenarios.md) — full scenario library with control objectives and remediation
- [Case Study: Kubernetes Goat](docs/case-study-kubernetes-goat.md) — end-to-end run against a deliberately vulnerable cluster
