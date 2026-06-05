# Chaosify Reference

Complete command reference, flags, exit codes, and agentic AI skill setup.

---

## Commands

### Reconnaissance

Survey the cluster's security posture before submitting any test workloads. All recon tools are read-only. A single tool failure never aborts the survey.

```bash
# Initialize test namespace with RBAC scoping and ResourceQuota
chaosify setup init

# Individual survey tools
chaosify recon webhooks           # fail-open webhook detection
chaosify recon policies           # Kyverno / Gatekeeper probe, audit-mode detection
chaosify recon psa                # Pod Security Admission labels per namespace
chaosify recon rbac               # cluster-admin bindings, high-privilege service accounts
chaosify recon nodes              # kernel versions, container runtimes, AppArmor presence
chaosify recon network-policies   # per-namespace network segmentation gaps
chaosify recon runtime-agents     # detect Falco, KubeArmor, Tetragon, Tracee
chaosify recon topology           # resource topology graph: ingress paths, secret mounts, SA bindings (requires graphnetes)
```

All recon tools support `--output <file>` and `--format json`.

### Cluster readiness

```bash
chaosify probe preflight
chaosify probe preflight --context prod-us-east
chaosify probe preflight --output json
```

### Verification — manifest admission

```bash
# Built-in scenario packs
chaosify probe run --pack preventive-baseline
chaosify probe run --pack runtime-baseline --alert-source falco
chaosify probe run --scenario deny-privileged-container
chaosify probe run --pack preventive-baseline --context prod-us-east
chaosify probe run --pack preventive-baseline --output result.json

# Arbitrary manifest
chaosify probe run --manifest ./my-pod.yaml --expect rejected
chaosify probe run --manifest ./my-deployment.yaml --expect allowed
```

### Verification — execution primitives

Four composable primitives for AI-driven free-form pentesting. An agentic AI generates manifests and commands dynamically from recon findings.

```bash
# exec — create a pod, run a command inside it, capture exit code + stdout + stderr
chaosify probe exec \
  --pod ./probe.yaml \
  --run "cat /var/run/secrets/kubernetes.io/serviceaccount/token" \
  --expect succeeded \
  --alert-source falco

# network — probe a target from inside a pod
chaosify probe network \
  --from ./net-probe.yaml \
  --target http://169.254.169.254/latest/meta-data/ \
  --expect unreachable

# identity — test what a service account is actually allowed to do
chaosify probe identity \
  --as default \
  --can list \
  --resource secrets \
  --resource-namespace kube-system \
  --expect denied

# detect — exec a threat command and poll a runtime tool for a correlated alert
chaosify probe detect \
  --pod ./escape-probe.yaml \
  --run "nsenter --mount=/proc/1/ns/mnt -- cat /etc/shadow" \
  --expect alert_fired \
  --alert-source falco \
  --observation-window 15
```

See the skills in `skills/` for execution guidance and evidence schema.

### Scenario discovery

```bash
chaosify scenarios list
chaosify scenarios list --pack preventive-baseline
chaosify scenarios show deny-privileged-container
```

See [scenarios.md](scenarios.md) for the full scenario catalog.

### Other

```bash
chaosify version
chaosify help
```

---

## Flags

| Flag | Description |
|---|---|
| `--context <name>` | Kubernetes context to use |
| `--namespace <name>` | Test namespace override (default: `chaosify`) |
| `--output <path>` | Write JSON evidence artifact to file |
| `--format <table\|json>` | Output mode |
| `--pack <id>` | Scenario pack to run |
| `--scenario <id>` | Single scenario to run |
| `--manifest <path>` | Manifest to submit (`probe run`) |
| `--expect <outcome>` | Expected outcome for the test |
| `--pod <path>` | Pod manifest (`probe exec`, `probe detect`) |
| `--run "<cmd>"` | Command to exec inside the container |
| `--container <name>` | Container to exec into (default: first) |
| `--from <path>` | Source pod manifest (`probe network`) |
| `--target <url\|host:port>` | Probe target (`probe network`) |
| `--protocol <http\|https\|tcp>` | Network protocol (default: inferred) |
| `--as <sa-name>` | Service account to test (`probe identity`) |
| `--can <verb>` | RBAC verb to test (`probe identity`) |
| `--resource <resource>` | Kubernetes resource to test (`probe identity`) |
| `--resource-namespace <ns>` | Namespace for the permission check |
| `--graph <path>` | Path to existing `graphnetes-out/graph.json` — skips build step (`recon topology`) |
| `--alert-source <tool>` | Runtime alert source: `none`, `falco`, `tetragon`, `kubearmor` |
| `--observation-window <s>` | Seconds to poll for a runtime alert (default: 10) |
| `--pod-timeout <s>` | Max wait for pod to reach Running (default: 60) |
| `--exec-timeout <s>` | Max time for exec command (default: 30) |
| `--connect-timeout <s>` | TCP connect timeout for network probe (default: 5) |
| `--timeout <duration>` | Per-run timeout |
| `--fail-fast` | Stop after first failed scenario |
| `--cleanup <always\|on-success>` | Cleanup mode (default: `always`) |

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | All scenarios passed |
| `1` | One or more failed controls |
| `2` | Execution error |
| `3` | Preflight failure |
| `4` | Invalid CLI usage |

---

## Agentic AI skills

Chaosify ships two agentic AI skills in `skills/`:

| Skill | Trigger | Description |
|---|---|---|
| `chaosify` | "Verify controls on this cluster" | Targeted control verification — recon init, preflight, scenario pack runs, result parsing, failure summarization, fleet fan-out |
| `agentic-pentest` | "Pentest this cluster" | Autonomous security assessment — the agent runs recon first, then uses execution primitives to probe the attack surface; produces a prioritized Critical/High/Gap report |

Use `chaosify` when you know what controls to run. Use `agentic-pentest` when you want an AI agent to assess the cluster's security posture autonomously without being constrained to pre-defined scenarios.

### Register with your agentic AI

Point your agent's skill loader at the `skills/` directory. The exact config format depends on your agent framework — add `skills/chaosify/` and `skills/agentic-pentest/` to its skill search path.

> **Claude Code users:** use `skills/claude/SKILL.md` instead. It is a single merged file that covers both skills and is pre-formatted for Claude Code's skill loader.

### Skill structure

```
skills/
  chaosify/
    SKILL.md                  ← workflows and safety rules
    references/
      goal-elaboration.md     ← result vocabulary, summarization, fleet aggregation
      cli-reference.md        ← commands, JSON schema, exit codes, remediation
  agentic-pentest/
    SKILL.md                  ← pentest workflow and authorization gate
    references/
      goal-elaboration.md     ← scope, cross-pack correlation, severity, report structure
      cli-reference.md        ← commands, exit codes, execution primitives, remediation
```

Chaosify owns the pass/fail verdict. The skills own the workflow, interpretation, and remediation layer.
