---
name: chaosclaw
description: Kubernetes security testing with ChaosClaw — verify preventive controls, run a full cluster pentest, or investigate specific gaps. Covers control verification (admission policies, PSA, RBAC) and autonomous pentesting (exec, network, identity, detection layer).
metadata:
  install: "symlink or copy this file to ~/.claude/skills/chaosclaw/SKILL.md"
---

TRIGGER when: the user asks to verify Kubernetes controls, run preflight, check admission policies, run a scenario pack, investigate a failed ChaosClaw result, pentest a cluster, run a security assessment, find gaps in cluster security posture, or uses phrases like "pentest this cluster", "check how secure this cluster is", "find what controls are missing", "assess this cluster", "verify guardrails", "control verification", "preventive baseline", or any `deny-*` scenario name.

SKIP: general Kubernetes debugging unrelated to admission controls or security posture. Skip questions about ChaosClaw internals or source code. Skip if the user is asking you to build or modify ChaosClaw itself.

---

# ChaosClaw Skill

ChaosClaw is a local CLI binary (`chaosclaw`) on the machine running this agent. Before any workflow, verify it is present:

```bash
chaosclaw version
```

If not found, tell the user to install ChaosClaw and stop. Do not attempt to install it yourself.

---

## Which workflow to use

| User intent | Workflow |
|---|---|
| Verify specific controls, run a scenario pack, investigate a single failure | **Control Verification** |
| Full security assessment, pentest, "find what's broken", multi-layer gap analysis | **Cluster Pentest** |

---

## Workflow A — Control Verification

Use when the user wants to confirm specific admission controls are enforced.

**Step 1 — Resolve cluster context.**
Ask which Kubernetes context to use if not specified. Run `kubectl config get-contexts`. Confirm before proceeding.

**Step 2 — Initialize the test namespace (first run only).**
```bash
chaosclaw setup init --context <context-name>
```
Skip if the user confirms it already exists.

**Step 2.5 — Run topology recon (if graphnetes is installed).**
```bash
chaosclaw recon topology --context <context-name> --namespace chaosclaw --output topology.json
```
If graphnetes is not installed the command returns `status: skip` — continue to Step 3. If it succeeds, read `topology.json`. Use `data.stats.secretMounts`, `data.stats.ingressPaths`, and `data.stats.serviceAccountBindings` to surface high-value targets and inform which scenarios or `--manifest` test cases to prioritize.

**Step 3 — Run preflight.**
```bash
chaosclaw probe preflight --context <context-name>
```

| Outcome | Action |
|---|---|
| Pass | Proceed |
| Permission error | Show the missing permission; suggest an RBAC check; do not proceed |
| Missing policy engine warning | Note that some scenarios may be skipped; proceed |
| Any other failure | Surface the error; do not proceed |

**Step 4 — Run the pack or scenario.**
```bash
# Full preventive baseline
chaosclaw probe run --pack preventive-baseline --context <context-name> --output chaosclaw-result.json

# Runtime baseline (requires alert source)
chaosclaw probe run --pack runtime-baseline --alert-source <falco|tetragon|kubearmor|none> --context <context-name> --output chaosclaw-runtime.json

# Single scenario
chaosclaw probe run --scenario <scenario-id> --context <context-name>

# Arbitrary manifest
chaosclaw probe run --manifest <path> --expect <rejected|allowed> --context <context-name>
```

**Step 5 — Parse and summarize results.**
Read the JSON artifact. Apply the result vocabulary and summarization rules below.

**Rerunning after a fix:**
Run the single scenario, compare the new result against the previous artifact, report whether the control now passes.

**Fleet mode:**
For each cluster in a `clusters.yaml`, run Steps 2–4, writing per-cluster output files. After all runs, produce the fleet summary (see §Fleet Summary below).

---

## Workflow B — Cluster Pentest

Use when the user wants a full security assessment across all control layers.

**Step 0 — Confirm authorization.**
Ask the user to confirm both:
1. They own or are authorized to test the target cluster.
2. They understand this submits test workloads to a live cluster (scoped to the `chaosclaw` namespace).

Do not proceed until both are confirmed.

**Step 1 — Resolve and confirm cluster context.**
```bash
kubectl config get-contexts
```
State the target cluster explicitly. Ask the user to confirm.

**Step 2 — Initialize the test namespace.**
```bash
chaosclaw setup init --context <context-name>
```
If init fails, surface the error and stop.

**Step 3 — Run topology recon (if graphnetes is installed).**
```bash
chaosclaw recon topology --context <context-name> --namespace <ns> --output topology-<ns>.json
```
Run one call per namespace of interest. If graphnetes is not installed the command returns `status: skip` — continue to Step 4. If it succeeds, read all `topology-*.json` before proceeding.

**Step 4 — Run the full recon survey.**
```bash
chaosclaw recon webhooks         --context <context-name> --output recon-webhooks.json --format json
chaosclaw recon policies         --context <context-name> --output recon-policies.json --format json
chaosclaw recon psa              --context <context-name> --output recon-psa.json      --format json
chaosclaw recon rbac             --context <context-name> --output recon-rbac.json     --format json
chaosclaw recon nodes            --context <context-name> --output recon-nodes.json    --format json
chaosclaw recon network-policies --context <context-name> --output recon-netpol.json  --format json
chaosclaw recon runtime-agents   --context <context-name> --output recon-agents.json  --format json
```
Read all output files alongside any `topology-*.json` files from Step 3 before proceeding.

**Step 5 — Analyze the recon report.**
For each tool's findings, determine:
- Which RBAC principals need identity checks
- Which network paths need reachability probes
- Which execution techniques need runtime testing
- Which alert source to use (see §Alert Source Selection)

Store the alert source now. Use it consistently for all Step 6 calls.

**Step 6 — Run execution primitives for every identified gap.**

```bash
# RBAC over-privilege — one call per flagged SA
chaosclaw probe identity \
  --as <sa-name> \
  --can <verb> \
  --resource <resource> \
  --resource-namespace <ns> \
  --expect denied \
  --context <context-name> \
  --output identity-<sa>.json

# Network segmentation gap — one call per flagged namespace/target
chaosclaw probe network \
  --from <probe-pod.yaml> \
  --target <url-or-host:port> \
  --expect unreachable \
  --alert-source <source> \
  --context <context-name> \
  --output network-<target>.json

# Exec-based attack path (escape, token theft, etc.)
chaosclaw probe exec \
  --pod <pod.yaml> \
  --run "<command>" \
  --expect <succeeded|failed|denied> \
  --alert-source <source> \
  --context <context-name> \
  --output exec-<name>.json

# Runtime detection gap
chaosclaw probe detect \
  --pod <pod.yaml> \
  --run "<threat-command>" \
  --expect <alert_fired|action_blocked|no_alert> \
  --alert-source <source> \
  --observation-window <seconds> \
  --context <context-name> \
  --output detect-<name>.json
```

Run `probe detect` after every `probe exec` that succeeds — this separates "can the attacker do it" from "does the defender see it".

**Recon signal → primitive mapping:**

| Recon signal | Primitive | What to test |
|---|---|---|
| Fail-open webhook (`failurePolicy: Ignore`) | `probe network` | Probe API server — confirm bypass window |
| Policy in Audit mode | `probe exec` | Confirm action succeeds (Audit doesn't block) |
| No PSA on a namespace | `probe exec` | Run privileged command — confirm no enforcement |
| Non-built-in cluster-admin SA | `probe identity` | Prove SA can list secrets, create pods in production namespaces |
| High-privilege SA | `probe identity` | Prove specific dangerous permissions |
| No egress NetworkPolicy | `probe network` | Probe metadata service, etcd, kubelet, cross-namespace pods |
| Runtime agent absent | `verify exec --alert-source none` | Confirm exec succeeds — detection layer absent |
| Runtime agent present | `verify exec --alert-source <tool>` | Confirm exec AND check if tool fires |
| Runtime agent present | `probe detect` | Test whether tool fires on specific threat commands |
| Old kernel / no AppArmor | `probe exec` | Test escape techniques (nsenter, chroot) |
| Topology: `secretMounts` present | `probe exec` | Exec into Pod, read the secret path — confirm credential accessible |
| Topology: `ingressPaths` present | `probe network` | Probe backend Service — confirm exposure and NetworkPolicy coverage |
| Topology: `serviceAccountBindings` + RBAC HIGH SA | `probe identity` | Confirm per-Pod attack path for that SA |

**Step 7 — Correlate and report.**
Apply the correlation rules in §Correlation and produce the report using §Report Structure.

**Step 8 — Offer next steps.**
After the report:
1. Offer to rerun any failed primitive after the user applies a fix.
2. Offer to save all artifacts for audit records.
3. If multiple Critical/High findings exist, offer to prioritize by attack surface severity.

---

## CLI Reference

### Setup commands

```bash
chaosclaw setup init    --context <ctx>
chaosclaw setup cleanup --context <ctx>
```

### Recon commands

```bash
chaosclaw recon webhooks          --context <ctx>
chaosclaw recon policies          --context <ctx>
chaosclaw recon psa               --context <ctx>
chaosclaw recon rbac              --context <ctx> [--include-system]
chaosclaw recon nodes             --context <ctx>
chaosclaw recon network-policies  --context <ctx>
chaosclaw recon runtime-agents    --context <ctx>
chaosclaw recon topology          --context <ctx> --namespace <ns> [--graph <path>]
```

`topology` requires [graphnetes](https://github.com/aahan-pat/graphnetes) on PATH. Returns a SKIP finding if not installed — survey continues.

Recon finding severities: `CRITICAL` / `HIGH` / `WARN` / `INFO` / `SKIP`

### Identity command

```bash
chaosclaw probe identity \
  --as <sa-name> \
  --can <verb> \
  --resource <resource> \          # use slash notation for subresources: pods/exec
  --resource-namespace <ns> \
  --expect <allowed|denied> \
  --namespace <sa-namespace> \
  [--group rbac.authorization.k8s.io] \
  --context <context-name> \
  --output identity-result.json
```

Requires `create subjectaccessreviews` permission. Exit code 2 if denied — do not treat as a control finding.

### Exec command

| `--expect` value | Meaning |
|---|---|
| `succeeded` | Exit code 0 |
| `failed` | Non-zero exit code |
| `denied` | Exec API blocked (403) |

### Network command

Protocol inferred from target: `http://` → HTTP, `https://` → HTTPS, `host:port` → TCP.

### Scenario discovery

```bash
chaosclaw scenarios list
chaosclaw scenarios list --pack preventive-baseline
chaosclaw scenarios show <scenario-id>
```

### Preventive baseline scenarios

| Scenario ID | Control objective |
|---|---|
| `deny-privileged-container` | Prevent privileged workloads |
| `deny-unapproved-registry` | Restrict disallowed image registries |
| `deny-hostpath` | Prevent hostPath volume usage |
| `deny-forbidden-capabilities` | Restrict dangerous Linux capabilities |
| `deny-latest-tag` | Prevent mutable image tags |
| `deny-privilege-escalation` | Prevent privilege escalation |
| `deny-host-network` | Prevent host network namespace access |

### Exit codes

| Code | Meaning | Action |
|---|---|---|
| `0` | All checks passed | Confirm controls verified |
| `1` | One or more failed | Summarize failures; suggest fixes |
| `2` | Execution error | Surface the error; do not treat as control failure |
| `3` | Preflight failure | Resolve before rerunning |
| `4` | Invalid CLI usage | Check the command |

### JSON artifact schema

All `probe` commands produce the same evidence envelope:

| Field | Description |
|---|---|
| `runId` | UUID for this run |
| `clusterContext` | Cluster tested |
| `summary` | `{ pass, fail, error, skipped }` counts |
| `results` | Per-result array |

Each result entry:

| Field | Description |
|---|---|
| `scenarioId` | e.g. `deny-privileged-container`, `exec:probe.yaml`, `identity:default/list/secrets` |
| `status` | `Pass`, `Fail`, `Error`, or `Skipped` |
| `expectedOutcome` | Declared via `--expect` |
| `observedOutcome` | What actually happened |
| `likelyIssue` | Best-guess explanation for failures |
| `cleanupStatus` | `success`, `failed`, `skipped`, `partial` |
| `rawResponse` | Tool-specific detail (exit code, stdout, HTTP status, alert payload) |

---

## Result Interpretation

### Result vocabulary

Never paraphrase or reinterpret these verdicts:

| Result | Meaning |
|---|---|
| **PASS** | Cluster behaved as expected — control is working |
| **FAIL** | Cluster did NOT behave as expected — control is broken or absent |
| **ERROR** | Scenario could not complete — not a verdict on the control |
| **SKIPPED** | Prerequisite was missing (e.g. policy engine not installed) |

FAIL ≠ ERROR.

### Summarization — control verification

**Clean run (all PASS):** Confirm which controls are verified using the scenario IDs from the artifact, not invented descriptions.

**Failures:** For each FAIL: (1) state the scenario ID and its control objective, (2) quote the `likelyIssue` field verbatim, (3) suggest targeted remediation (see §Remediation), (4) offer to rerun just that scenario after the user fixes it.

**Errors:** Distinguish from failures. Surface the error message without presenting it as a control verdict.

**Skipped:** Explain what prerequisite was missing.

### Fleet summary

- Total clusters tested: pass / fail / error counts
- Per-scenario: how many clusters failed each control
- Common failure patterns across clusters
- Clusters that need a rerun

### Alert source selection

Check `data.agents` from the `runtime-agents` recon output:

| Detected agents | Use |
|---|---|
| Tetragon | `--alert-source tetragon` |
| KubeArmor | `--alert-source kubearmor` |
| Falco only | `--alert-source falco` |
| None | `--alert-source none` |
| Multiple | Prefer Tetragon → KubeArmor → Falco |

### Recon interpretation

**webhooks:** `failurePolicy: Ignore` → run `probe network` to probe the API server. No validating webhooks → critical gap, record and continue.

**policies:** No policy engine → critical gap. Policies in Audit mode → run `probe exec` for high-risk commands (Audit doesn't block). No findings → focus on runtime and RBAC.

**psa:** Namespaces without PSA labels → run `probe exec` from a pod in that namespace.

**rbac:** Non-built-in cluster-admin SA → `verify identity --as <sa> --can list --resource secrets --resource-namespace kube-system --expect denied`. Any High-privilege SA → `verify identity --can create --resource pods --resource-namespace <prod-ns> --expect denied`. A `Fail` (allowed when denied expected) = confirmed privilege escalation path → **High**.

**network-policies:** Namespaces with no NetworkPolicies → `verify network --target http://169.254.169.254/latest/meta-data/ --expect unreachable`. Always run at least one network probe per cluster even if policies look clean.

**runtime-agents:** No agent → `--alert-source none`, record detection layer absent. Falco only → can detect, cannot block. Tetragon/KubeArmor → can detect and block.

**nodes:** Older kernel versions and absent AppArmor are informational defense-depth gaps. Not a decision gate.

**topology:** If `status: skip` → note coverage gap, continue. If `status: ok`: `secretMounts` → `probe exec` to read the secret from inside the pod; `ingressPaths` → `probe network` to probe the backend Service; `serviceAccountBindings` + RBAC HIGH match → `probe identity` to confirm per-Pod path. Node IDs use `Kind/namespace/name` form.

### Correlation (pentest)

| Pattern | Classification |
|---|---|
| exec PASS + no alert | **Critical** — attack succeeds and goes undetected |
| exec PASS + alert fired | **High** — attack succeeds but is detected |
| exec PASS (escape) + no runtime agent | **Critical** — escape confirmed, detection layer absent |
| RBAC identity FAIL (allowed when denied) | **High** — privilege escalation confirmed |
| Network FAIL (reachable when unreachable) | **High** — lateral movement / exfiltration path confirmed |
| detect FAIL (no_alert when alert_fired) | **High** — detection gap |
| No runtime agent + exec succeeds | **Critical** — entire detection layer absent |
| All controls PASS | **Passing** |

**Overall posture:** Any Critical → Critical. High only → High. WARN/gaps only → Medium. All pass → Passing.

### High-value exec commands

| Technique | Command | What it proves |
|---|---|---|
| Token theft | `cat /var/run/secrets/kubernetes.io/serviceaccount/token` | SA token readable inside pod |
| Host namespace escape | `nsenter --mount=/proc/1/ns/mnt ls /` | Container mount namespace breakout |
| Host filesystem chroot | `chroot /proc/1/root ls /etc` | Host root filesystem accessible |
| Kernel module load | `insmod /dev/null` | Kernel module loading unrestricted |
| Sensitive file read | `cat /etc/shadow` | Host shadow file accessible |

### High-value network targets

| Target | What it proves |
|---|---|
| `http://169.254.169.254/latest/meta-data/` | Cloud metadata service reachable (credential theft risk) |
| `https://kubernetes.default.svc` | Kubernetes API reachable from pod |
| `http://<node-ip>:10250/pods` | Kubelet API reachable |
| `http://<node-ip>:2379` | etcd direct access |
| `http://<pod-ip-other-ns>:8080` | Cross-namespace pod reachable |

---

## Remediation Reference

**`deny-privileged-container`** — Verify the policy covering `securityContext.privileged: true` is in Enforce mode (not Audit).

**`deny-unapproved-registry`** — Verify the allowlist covers all image pull paths including init containers.

**`deny-hostpath`** — Verify the policy covers bare `Pod` resources, not just `Deployment`.

**`deny-forbidden-capabilities`** — Check the blocklist includes both `NET_RAW` and `SYS_ADMIN`.

**`deny-latest-tag`** — Verify enforcement applies to all containers and is not scoped to a specific namespace.

**`deny-privilege-escalation`** — Confirm `allowPrivilegeEscalation: false` is enforced at admission, not just set as a default.

**`deny-host-network`** — Verify the policy covers `hostNetwork: true` on bare Pods, not just Deployments.

---

## Report Structure (pentest)

```
Cluster: <context-name>
Assessment date: <timestamp>
Recon summary: <n> Critical, <n> High, <n> Warn
Execution primitives run: <list>
Alert source used: <falco|tetragon|kubearmor|none>
Overall posture: [Critical / High / Medium / Passing]

### Critical Findings
<control surface, failed layers, quoted detail/likelyIssue, risk statement>

### High Findings
<same format>

### Coverage Gaps
<tools that returned SKIP, missing permissions, absent agents — quote coverageImpact>

### Verified Controls
<evidence-backed verdicts only — never assert a control works without a Pass result>
```

---

## Safety Reminders

- Always confirm the cluster context. Never assume the current context is the intended target.
- Never skip preflight (control verification) or init + authorization confirmation (pentest).
- All execution is confined to the `chaosclaw` namespace — RBAC-bound, cannot affect other namespaces.
- A pentest does not modify policies, webhooks, application workloads, or cluster config.
- If cleanup reports a partial failure, surface the `kubectl delete` command before the next primitive.
- `probe identity` requires `create subjectaccessreviews`. If denied (exit code 2), skip identity checks — do not treat as a control finding.
