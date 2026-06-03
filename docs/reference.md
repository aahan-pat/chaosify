# ChaosClaw Reference

Complete command reference, flags, exit codes, and OpenClaw skill setup.

---

## Commands

### Reconnaissance

Survey the cluster's security posture before submitting any test workloads. All recon tools are read-only. A single tool failure never aborts the survey.

```bash
# Initialize test namespace with RBAC scoping and ResourceQuota
chaosclaw setup init

# Individual survey tools
chaosclaw recon webhooks           # fail-open webhook detection
chaosclaw recon policies           # Kyverno / Gatekeeper probe, audit-mode detection
chaosclaw recon psa                # Pod Security Admission labels per namespace
chaosclaw recon rbac               # cluster-admin bindings, high-privilege service accounts
chaosclaw recon nodes              # kernel versions, container runtimes, AppArmor presence
chaosclaw recon network-policies   # per-namespace network segmentation gaps
chaosclaw recon runtime-agents     # detect Falco, KubeArmor, Tetragon, Tracee
chaosclaw recon topology           # resource topology graph: ingress paths, secret mounts, SA bindings (requires graphnetes)
```

All recon tools support `--output <file>` and `--format json`.

### Cluster readiness

```bash
chaosclaw probe preflight
chaosclaw probe preflight --context prod-us-east
chaosclaw probe preflight --output json
```

### Verification — manifest admission

```bash
# Built-in scenario packs
chaosclaw probe run --pack preventive-baseline
chaosclaw probe run --pack runtime-baseline --alert-source falco
chaosclaw probe run --scenario deny-privileged-container
chaosclaw probe run --pack preventive-baseline --context prod-us-east
chaosclaw probe run --pack preventive-baseline --output result.json

# Arbitrary manifest (primary interface for OpenClaw)
chaosclaw probe run --manifest ./my-pod.yaml --expect rejected
chaosclaw probe run --manifest ./my-deployment.yaml --expect allowed
```

### Verification — execution primitives

Four composable primitives for OpenClaw-driven free-form pentesting. OpenClaw generates all manifests and commands dynamically from recon findings.

```bash
# exec — create a pod, run a command inside it, capture exit code + stdout + stderr
chaosclaw probe exec \
  --pod ./probe.yaml \
  --run "cat /var/run/secrets/kubernetes.io/serviceaccount/token" \
  --expect succeeded \
  --alert-source falco

# network — probe a target from inside a pod
chaosclaw probe network \
  --from ./net-probe.yaml \
  --target http://169.254.169.254/latest/meta-data/ \
  --expect unreachable

# identity — test what a service account is actually allowed to do
chaosclaw probe identity \
  --as default \
  --can list \
  --resource secrets \
  --resource-namespace kube-system \
  --expect denied

# detect — exec a threat command and poll a runtime tool for a correlated alert
chaosclaw probe detect \
  --pod ./escape-probe.yaml \
  --run "nsenter --mount=/proc/1/ns/mnt -- cat /etc/shadow" \
  --expect alert_fired \
  --alert-source falco \
  --observation-window 15
```

See the skills in `skills/` for execution guidance and evidence schema.

### Scenario discovery

```bash
chaosclaw scenarios list
chaosclaw scenarios list --pack preventive-baseline
chaosclaw scenarios show deny-privileged-container
```

See [scenarios.md](scenarios.md) for the full scenario catalog.

### Other

```bash
chaosclaw version
chaosclaw help
```

---

## Flags

| Flag | Description |
|---|---|
| `--context <name>` | Kubernetes context to use |
| `--kubeconfig <path>` | kubeconfig path override |
| `--namespace <name>` | Test namespace override (default: `chaosclaw`) |
| `--output <path>` | Write JSON evidence artifact to file |
| `--format <table\|json>` | Output mode |
| `--verbose` | Include extra diagnostic detail |
| `--quiet` | Minimal terminal output |
| `--no-color` | Disable colorized output |
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

## OpenClaw skills

ChaosClaw ships two OpenClaw skills in `skills/`:

| Skill | Trigger | Description |
|---|---|---|
| `chaosclaw` | "Verify controls on this cluster" | Targeted control verification — recon init, preflight, scenario pack runs, result parsing, failure summarization, fleet fan-out |
| `openclaw-pentest` | "Pentest this cluster" | Autonomous security assessment — OpenClaw runs recon first, then uses execution primitives to probe the attack surface; produces a prioritized Critical/High/Gap report |

Use `chaosclaw` when you know what controls to run. Use `openclaw-pentest` when you want OpenClaw to assess the cluster's security posture autonomously without being constrained to pre-defined scenarios.

### Register with OpenClaw

Add the skills directory to `~/.openclaw/openclaw.json`:

```json
{
  "skills": {
    "load": {
      "extraDirs": ["/path/to/chaosclaw/skills"],
      "watch": true
    },
    "entries": {
      "chaosclaw": { "enabled": true },
      "openclaw-pentest": { "enabled": true }
    }
  }
}
```

### Skill structure

```
skills/
  chaosclaw/
    SKILL.md                  ← workflows and safety rules
    references/
      goal-elaboration.md     ← result vocabulary, summarization, fleet aggregation
      cli-reference.md        ← commands, JSON schema, exit codes, remediation
  openclaw-pentest/
    SKILL.md                  ← pentest workflow and authorization gate
    references/
      goal-elaboration.md     ← scope, cross-pack correlation, severity, report structure
      cli-reference.md        ← commands, exit codes, execution primitives, remediation
```

ChaosClaw owns the pass/fail verdict. The skills own the workflow, interpretation, and remediation layer.
