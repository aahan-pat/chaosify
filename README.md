# ChaosClaw

ChaosClaw is a safe, namespace-scoped execution environment for Kubernetes security verification. It proves whether your Kubernetes guardrails actually work — not just whether they are configured — and serves as the controlled execution sandbox for OpenClaw-driven pentesting.

All execution is confined to a dedicated, RBAC-enforced test namespace. ChaosClaw structurally cannot touch any other namespace in the cluster.

## Installation

Requires Node.js ≥ 22.16.0.

```bash
npm install -g chaosclaw
```

To try without installing:

```bash
npx chaosclaw --help
```

## Quick start

```bash
# Initialize the test namespace
chaosclaw setup init

# Survey the cluster's security posture (read-only)
chaosclaw recon webhooks --output recon-webhooks.json --format json
chaosclaw recon policies --output recon-policies.json --format json
chaosclaw recon psa      --output recon-psa.json      --format json
chaosclaw recon rbac     --output recon-rbac.json     --format json

# Check the cluster is ready
chaosclaw probe preflight

# Run the preventive baseline pack
chaosclaw probe run --pack preventive-baseline --output result.json

# Run a single scenario
chaosclaw probe run --scenario deny-hostpath --context prod-us-east

# Test an arbitrary manifest
chaosclaw probe run --manifest ./my-pod.yaml --expect rejected
```

Results are `PASS`, `FAIL`, `ERROR`, or `SKIPPED`. Every run produces a structured JSON evidence artifact.

## Command groups

| Group | Description |
|---|---|
| `setup` | Initialize and tear down the test namespace |
| `recon` | Survey cluster security posture — read-only |
| `probe` | Execute attack primitives and scenario packs |
| `scenarios` | Discover and inspect available scenarios |

### Setup

```bash
chaosclaw setup init     # Create namespace, ResourceQuota, ServiceAccount, Role/RoleBinding
chaosclaw setup cleanup  # Tear down the test namespace
```

### Recon

Survey the cluster before any test workloads are submitted. All tools are read-only.

```bash
chaosclaw recon webhooks          # Fail-open webhook detection
chaosclaw recon policies          # Kyverno / Gatekeeper probe, audit-mode detection
chaosclaw recon psa               # Pod Security Admission labels per namespace
chaosclaw recon rbac              # Cluster-admin bindings, high-privilege service accounts
chaosclaw recon nodes             # Kernel versions, container runtimes, AppArmor presence
chaosclaw recon network-policies  # Per-namespace network segmentation gaps
chaosclaw recon runtime-agents    # Detect Falco, KubeArmor, Tetragon, Tracee
chaosclaw recon topology          # Resource graph: ingress paths, secret mounts, SA bindings (requires graphnetes)
```

All tools support `--context <name>`, `--output <file>`, and `--format json`.

### Probe

Four composable execution primitives for free-form pentesting, plus scenario pack runs.

```bash
# Run a built-in scenario pack
chaosclaw probe run --pack preventive-baseline --output result.json
chaosclaw probe run --pack runtime-baseline --alert-source falco

# Check cluster readiness
chaosclaw probe preflight --context prod-us-east

# Submit a pod, exec a command, capture exit code + stdout + stderr
chaosclaw probe exec \
  --pod ./probe.yaml \
  --run "cat /var/run/secrets/kubernetes.io/serviceaccount/token" \
  --expect succeeded \
  --alert-source falco

# Probe a target endpoint from inside a pod
chaosclaw probe network \
  --from ./net-probe.yaml \
  --target http://169.254.169.254/latest/meta-data/ \
  --expect unreachable

# Test what a service account is actually authorized to do
chaosclaw probe identity \
  --as default \
  --can list \
  --resource secrets \
  --resource-namespace kube-system \
  --expect denied

# Exec a threat command and poll a runtime tool for a correlated alert
chaosclaw probe detect \
  --pod ./escape-probe.yaml \
  --run "nsenter --mount=/proc/1/ns/mnt -- cat /etc/shadow" \
  --expect alert_fired \
  --alert-source falco \
  --observation-window 15
```

### Scenario discovery

```bash
chaosclaw scenarios list
chaosclaw scenarios list --pack preventive-baseline
chaosclaw scenarios show deny-privileged-container
```

## OpenClaw skills

ChaosClaw ships two OpenClaw skills in `skills/`:

| Skill | Trigger | Description |
|---|---|---|
| `chaosclaw` | "Verify controls on this cluster" | Targeted control verification — init, preflight, scenario pack runs, result parsing, failure summarization |
| `openclaw-pentest` | "Pentest this cluster" | Autonomous security assessment — recon-first, then execution primitives to probe the attack surface; produces a prioritized Critical/High/Gap report |

Use `chaosclaw` when you know what controls to verify. Use `openclaw-pentest` when you want an autonomous assessment across all control layers.

To use with Claude Code, point to the skills directory in your Claude Code settings or symlink the skill files to `~/.claude/skills/`.

## Docs

- [Architecture](docs/architecture.md) — system design, safety model, and multi-cluster model
- [Reference](docs/reference.md) — complete command reference, flags, and exit codes
- [Scenarios](docs/scenarios.md) — full scenario library with control objectives and remediation
- [Case Study: Kubernetes Goat](docs/case-study-kubernetes-goat.md) — end-to-end run against a deliberately vulnerable cluster
