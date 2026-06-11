---
name: chaosify
description: Kubernetes security testing with Chaosify — autonomous exploit detection through constrained probing. The agent reasons from recon findings to generate targeted manifests, submits them via Chaosify primitives, and iterates toward confirmed gaps.
metadata:
  install: "symlink or copy this file to ~/.claude/skills/chaosify/SKILL.md"
---

TRIGGER when: the user asks to verify Kubernetes controls, pentest a cluster, find security gaps, check admission policies, assess cluster security posture, or uses phrases like "pentest this cluster", "find what's broken", "check how secure this cluster is", "assess this cluster", "verify guardrails", "control verification", "preventive baseline", or any `deny-*` scenario name.

SKIP: general Kubernetes debugging unrelated to security posture. Skip questions about Chaosify internals or source code. Skip if the user is asking you to build or modify Chaosify itself.

---

# Chaosify Skill

Chaosify is a local CLI binary (`chaosify`) on the machine running this agent. Verify it is present before any workflow:

```bash
chaosify version
```

If not found, tell the user to install Chaosify and stop. Do not attempt to install it yourself.

---

## Tool Inventory

You operate within a constrained tool set. Do not use `kubectl` (except `config get-contexts`), `curl`, `helm`, or any shell command not listed here. Every cluster-mutating operation uses auto-cleanup and is namespace-scoped.

**Read-only — no cluster side effects:**
```
kubectl config get-contexts
chaosify recon webhooks|policies|psa|rbac|nodes|network-policies|runtime-agents|topology
chaosify probe identity --as <sa> --can <verb> --resource <resource> --expect <allowed|denied>
chaosify scenarios list [--pack <id>]
chaosify scenarios show <id>
chaosify probe preflight --context <ctx>
```

**Write to disk — manifest authoring:**
```
Write <run>/manifests/<name>.yaml    generate a pod manifest YAML before probing
```

**Cluster-mutating — all auto-cleanup, all namespace-scoped:**
```
chaosify probe run --manifest <path> --expect <rejected|allowed>
chaosify probe run --pack <id> --context <ctx>
chaosify probe run --scenario <id> --context <ctx>
chaosify probe exec --pod <path> --run "<cmd>" --expect <succeeded|failed|denied>
chaosify probe network --from <path> --target <url|host:port> --expect <reachable|unreachable>
chaosify probe detect --pod <path> --run "<cmd>" --expect <alert_fired|action_blocked|no_alert>
```

**Setup — run once per cluster session:**
```
chaosify setup init    --context <ctx>
chaosify setup cleanup --context <ctx>
```

---

## Run Output Directory

Create one run directory at the start of every session and keep **all** artifacts under it — recon dumps, generated manifests, and probe evidence. Never scatter files into the working directory root. Use the UTC start time as the run id:

```
.chaosify/runs/<run>/        <run> = UTC start time, e.g. 2026-06-09T11-40-00Z
```

Within that single run root you are free to organize files as you see fit, with one rule: **bundle similar runtime artifacts into their own subfolders.** Keep generated YAML manifests separate from Chaosify's JSON tool outputs, and recon dumps separate from probe evidence. A natural grouping — the one the examples below use — is:

```
.chaosify/runs/<run>/
  recon/         recon-*.json
  manifests/     generated pod YAML
  results/       probe + run evidence JSON
```

but the subfolder names are yours to choose; only the single run root and the like-with-like grouping are required. Pick `<run>` once at the start and reuse the same path for every file this session, so each run is self-contained and comparable against previous runs (the rerun workflow diffs against the prior run's evidence). The harness shell does not persist variables between commands — substitute the literal path each time rather than relying on an env var. Chaosify never imposes this layout itself (`--output` writes wherever it is told), so routing artifacts here is your responsibility.

---

## Phase 1 — Reconnaissance

Confirm authorization and cluster context, initialize the test namespace, then survey the full cluster.

**Authorization (pentest):** Before any mutating operation, confirm:
1. The user owns or is authorized to test this cluster.
2. They understand Chaosify creates its **own dedicated namespaces** for the assessment — `chaosify` (setup/runner resources) and `chaosify-tests` (where all test workloads run) — separate from their application namespaces, and that every test pod is namespace-scoped to `chaosify-tests` and auto-cleaned. State this to the user explicitly in the confirmation, so it is clear nothing is deployed into their existing namespaces.

**Setup:**
```bash
kubectl config get-contexts
chaosify setup init    --context <ctx>
chaosify probe preflight --context <ctx>
```

Abort on preflight permission error. Proceed through missing-policy-engine warnings.

**Full recon survey — run all, write JSON into `<run>/recon/`:**
```bash
chaosify recon webhooks         --context <ctx> --output .chaosify/runs/<run>/recon/recon-webhooks.json  --format json
chaosify recon policies         --context <ctx> --output .chaosify/runs/<run>/recon/recon-policies.json  --format json
chaosify recon psa              --context <ctx> --output .chaosify/runs/<run>/recon/recon-psa.json       --format json
chaosify recon rbac             --context <ctx> --output .chaosify/runs/<run>/recon/recon-rbac.json      --format json
chaosify recon nodes            --context <ctx> --output .chaosify/runs/<run>/recon/recon-nodes.json     --format json
chaosify recon network-policies --context <ctx> --output .chaosify/runs/<run>/recon/recon-netpol.json   --format json
chaosify recon runtime-agents   --context <ctx> --output .chaosify/runs/<run>/recon/recon-agents.json   --format json
chaosify recon topology         --context <ctx> --output .chaosify/runs/<run>/recon/recon-topology.json --format json
```

Read all output files before proceeding. Select alert source from `<run>/recon/recon-agents.json` now and use it consistently:

| Detected | Use |
|---|---|
| Tetragon | `--alert-source tetragon` |
| KubeArmor | `--alert-source kubearmor` |
| Falco | `--alert-source falco` |
| Multiple | Prefer Tetragon → KubeArmor → Falco |
| None | `--alert-source none` — record detection layer absent |

---

## Phase 2 — Hypothesis Formation

For each recon finding, form a specific, falsifiable hypothesis before generating a manifest. Structure every hypothesis as:

```
Given:   [the recon signal]
If:      [a pod with these specific fields is submitted]
Then:    [admission_rejected | admission_allowed | exec_succeeds | alert_fires]
```

One hypothesis per manifest. Prioritize by severity: node escape > RBAC privilege escalation > detection gaps > network segmentation > admission gaps.

**Signal → hypothesis mapping:**

| Recon signal | Hypothesis |
|---|---|
| No PSA label on namespace | Pod with `privileged: true` will be admitted |
| PSA in `Audit` mode | Pod admitted AND exec will succeed |
| No validating webhooks | Any restricted field will be admitted |
| Webhook `failurePolicy: Ignore` | Pod admitted when webhook endpoint unreachable |
| No NetworkPolicy on namespace | Pod can reach `169.254.169.254` and cross-namespace pods |
| Non-built-in cluster-admin SA | SA can `list secrets` in `kube-system` |
| High-privilege SA | SA can `create pods` in production namespaces |
| `automountServiceAccountToken` not disabled | SA token readable inside pod |
| Runtime agent absent | Exec commands succeed with no alert |
| Runtime agent present | Known-bad commands trigger an alert |
| Topology `secretMounts` | Secret path is readable inside the pod that mounts it |

---

## Phase 3 — Manifest Generation

Write every manifest with the `Write` tool into `<run>/manifests/` before submitting. All generated manifests must:
- Use `generateName: chaosify-test-` — never a static `name:` field
- Set `restartPolicy: Never`
- Use `busybox:1.36` or `alpine:3.19`
- Never set `namespace:` — the probe command injects it

**Base template:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  generateName: chaosify-test-
spec:
  restartPolicy: Never
  containers:
    - name: probe
      image: busybox:1.36
      command: [sleep, "3600"]
```

**Attack surface fields — add only what your hypothesis requires:**

```yaml
# Host namespace access
spec:
  hostPID: true       # read /proc/*/environ of all host processes, attach with ptrace
  hostIPC: true       # attach to host IPC / shared memory segments
  hostNetwork: true   # bypass NetworkPolicy, reach node IP range and cloud metadata

# Host filesystem mounts
  volumes:
    - name: host-root
      hostPath: {path: /}
    - name: host-pki
      hostPath: {path: /etc/kubernetes/pki}
    - name: docker-sock
      hostPath: {path: /var/run/docker.sock}

# Container security context
  containers:
    - name: probe
      image: busybox:1.36
      volumeMounts:
        - {name: host-root, mountPath: /host}
      securityContext:
        privileged: true
        allowPrivilegeEscalation: true
        runAsUser: 0
        readOnlyRootFilesystem: false
        capabilities:
          add: [NET_ADMIN, SYS_PTRACE, SYS_ADMIN, NET_RAW, SYS_MODULE]

# SA token injection (test that it is disabled)
  automountServiceAccountToken: true

# Init container variant — some policies only check containers[], not initContainers[]
  initContainers:
    - name: init-probe
      image: busybox:1.36
      securityContext:
        privileged: true
```

**Compound manifests for multi-step attack paths:**

| Attack path | Fields to combine |
|---|---|
| Full node takeover | `privileged: true` + `hostPID: true` + `hostPath: /` |
| Credential theft via token | `automountServiceAccountToken: true` + exec to read token |
| Cloud metadata access | `hostNetwork: true` + network probe to `169.254.169.254` |
| Container runtime escape | `hostPath: /var/run/docker.sock` |
| Init container policy bypass | `initContainers[]` with restricted fields |
| Capability-based escape | `capabilities.add: [SYS_PTRACE]` + `hostPID: true` |

When a policy blocks your first manifest, try a variant: `initContainers` instead of `containers`, different namespace, or strip to the single field the policy may not be checking.

---

## Phase 4 — Probe Execution

Choose the primitive that matches your hypothesis:

| Hypothesis type | Primitive |
|---|---|
| Pod admitted / rejected | `probe run --manifest <path> --expect <rejected\|allowed>` |
| Command succeeds inside pod | `probe exec --pod <path> --run "<cmd>" --expect <succeeded\|failed\|denied>` |
| Target reachable from pod | `probe network --from <path> --target <url\|host:port> --expect <reachable\|unreachable>` |
| Runtime alert fires | `probe detect --pod <path> --run "<cmd>" --expect <alert_fired\|action_blocked\|no_alert>` |
| SA has forbidden permission | `probe identity --as <sa> --can <verb> --resource <resource> --expect denied` |

Always write `--output .chaosify/runs/<run>/results/<name>.json` to produce a traceable evidence artifact.

**Exec commands by objective:**

| Objective | `--run` value | Requires |
|---|---|---|
| SA token theft | `cat /var/run/secrets/kubernetes.io/serviceaccount/token` | `automountServiceAccountToken: true` |
| Node filesystem read | `ls /host/etc/kubernetes/pki` | `hostPath: /` at `/host` |
| Host process enumeration | `cat /proc/1/environ` | `hostPID: true` |
| Mount namespace escape | `nsenter --mount=/proc/1/ns/mnt -- ls /` | `hostPID: true` + `SYS_PTRACE` |
| Cloud metadata | `wget -qO- http://169.254.169.254/latest/meta-data/` | `hostNetwork: true` |
| Docker socket escape | `ls /host-docker/containers` | `/var/run/docker.sock` mounted |
| Sensitive file read | `cat /etc/shadow` | — triggers runtime detection |
| Capability probe | `ip link set lo down` | `NET_ADMIN` capability |
| Kernel module probe | `insmod /dev/null` | `SYS_MODULE` capability |

**Network targets:**

| Target | What `reachable` proves |
|---|---|
| `http://169.254.169.254/latest/meta-data/` | Cloud credential theft path open |
| `https://kubernetes.default.svc` | Kubernetes API reachable from pod |
| `http://<node-ip>:10250/pods` | Kubelet API exposed |
| `http://<node-ip>:2379` | etcd directly accessible |
| `http://<pod-ip-other-ns>:<port>` | Cross-namespace pod reachable |

---

## Phase 5 — Iteration

After each probe result, update your hypothesis and decide the next step. Trace the full attack path before reporting.

```
Admission allowed (expected rejected)
  → CONFIRMED gap — escalate to exec phase with same manifest
  → Also test initContainers variant to assess policy scope

Exec succeeded
  → Run probe detect on same pod + command immediately
  → If token read: record credential access proven (do not make API calls with it)
  → If hostPID: try nsenter to confirm namespace escape

No alert (expected alert_fired)
  → Try a stronger trigger command
  → Record detection blind spot

RBAC identity allowed (expected denied)
  → Chain: can create pods → try privileged manifest → exec → escalate
```

Stop iterating on a vector when the full attack path is confirmed, or three distinct variants have all been blocked. After every confirmed exec gap, run `probe detect` on the same command to separate "attacker can do it" from "defender sees it."

---

## Correlation

| Pattern | Classification |
|---|---|
| Admission passes + exec succeeds + no alert | **Critical** — attack lands undetected |
| Admission passes + exec succeeds + alert fires | **High** — attack lands but detected |
| Admission passes + exec blocked by RBAC | **Medium** — pod in but execution limited |
| Admission blocked | **Passing** — control working |
| RBAC identity allowed (expected denied) | **High** — privilege escalation path confirmed |
| Network reachable (expected unreachable) | **High** — lateral movement / exfil path open |
| No alert on known-bad command | **High** — detection blind spot |
| No runtime agent + exec succeeds | **Critical** — detection layer entirely absent |

**Overall posture:** Any Critical → Critical. High only → High. Medium/gaps only → Medium. All pass → Passing.

---

## Result Vocabulary

Never paraphrase these verdicts:

| Result | Meaning |
|---|---|
| **PASS** | Cluster behaved as expected — control is working |
| **FAIL** | Cluster did NOT behave as expected — gap confirmed |
| **ERROR** | Scenario could not complete — not a verdict on the control |
| **SKIPPED** | Prerequisite was missing |

FAIL ≠ ERROR.

---

## CLI Reference

### Identity command
```bash
chaosify probe identity \
  --as <sa-name> \
  --can <verb> \
  --resource <resource> \
  --resource-namespace <ns> \
  --expect <allowed|denied> \
  --namespace <sa-namespace> \
  [--group rbac.authorization.k8s.io] \
  --context <ctx> \
  --output .chaosify/runs/<run>/results/identity-result.json
```
Requires `create subjectaccessreviews`. Exit code 2 if denied — do not treat as a control finding.

### Exec `--expect` values
| Value | Meaning |
|---|---|
| `succeeded` | Exit code 0 |
| `failed` | Non-zero exit code |
| `denied` | Exec API blocked (403) |

### Network protocol inference
`http://` → HTTP, `https://` → HTTPS, `host:port` → TCP.

### Built-in scenario packs
| Pack | Scenarios |
|---|---|
| `preventive-baseline` | deny-privileged-container, deny-forbidden-capabilities, deny-host-network, deny-hostpath, deny-privilege-escalation, deny-latest-tag, deny-unapproved-registry |
| `runtime-baseline` | detect-read-sensitive-file |

### Exit codes
| Code | Meaning |
|---|---|
| `0` | All checks passed |
| `1` | One or more failed |
| `2` | Execution error — not a control verdict |
| `3` | Preflight failure — resolve before rerunning |
| `4` | Invalid CLI usage |

### JSON artifact schema
| Field | Description |
|---|---|
| `runId` | UUID for this run |
| `clusterContext` | Cluster tested |
| `summary` | `{ pass, fail, error, skipped }` counts |
| `results[].scenarioId` | e.g. `custom:probe.yaml`, `identity:default/list/secrets` |
| `results[].status` | `Pass`, `Fail`, `Error`, `Skipped` |
| `results[].expectedOutcome` | Declared via `--expect` |
| `results[].observedOutcome` | What actually happened |
| `results[].likelyIssue` | Best-guess explanation for failures |
| `results[].rawResponse` | Exit code, stdout, HTTP status, or alert payload |

---

## Report Structure

```
Cluster: <context>
Assessment date: <timestamp>
Alert source: <falco|tetragon|kubearmor|none>
Overall posture: [Critical / High / Medium / Passing]

### Critical Findings
<hypothesis, manifest fields, exec command, observed outcome, risk>

### High Findings
<same format>

### Detection Gaps
<command, alert source, expected alert, observed outcome>

### Verified Controls
<evidence-backed verdicts only — never assert without a PASS result>

### Coverage Gaps
<vectors not tested — missing permissions, absent tooling, SKIP results>
```

After the report, offer to rerun failed probes after fixes, save artifacts for audit, and prioritize findings if multiple Critical/High exist.

---

## Remediation Reference

**`deny-privileged-container`** — Verify policy is in Enforce mode (not Audit); covers bare Pods and Deployments.

**`deny-forbidden-capabilities`** — Confirm blocklist includes `NET_RAW` and `SYS_ADMIN`, not just `NET_ADMIN`.

**`deny-host-network`** — Verify coverage extends to bare Pods and initContainers.

**`deny-hostpath`** — Verify coverage extends to Deployments and initContainers.

**`deny-privilege-escalation`** — Confirm enforced at admission, not just set as a default.

**`deny-latest-tag`** — Verify not scoped to a single namespace.

**`deny-unapproved-registry`** — Verify allowlist covers init containers and all pull paths.

---

## Safety

- Always confirm the cluster context before any mutating operation.
- Never skip setup init or authorization confirmation.
- All generated manifests must use `generateName: chaosify-test-` and must not set `namespace:`.
- All execution is confined to the `chaosify-tests` namespace.
- Do not call the Kubernetes API using a stolen token — reading it to prove access is sufficient.
- Do not modify policies, webhooks, application workloads, or cluster config.
- If cleanup reports partial failure, surface the `kubectl delete pod -n chaosify-tests --all` command before the next probe.
