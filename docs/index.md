---
layout: home

hero:
  name: Chaosify
  text: Prove your Kubernetes guardrails actually work
  tagline: A safe, namespace-scoped execution environment for Kubernetes security verification and AI-driven pentesting. It doesn't scan your config — it runs the attack and records what the cluster actually did.
  actions:
    - theme: brand
      text: Quick start
      link: #quick-start
    - theme: alt
      text: Command Reference
      link: /reference
    - theme: alt
      text: Architecture
      link: /architecture
    - theme: alt
      text: View on GitHub
      link: https://github.com/aahan-pat/chaosify

features:
  - title: Verifies, doesn't just scan
    details: Proves whether a control actually blocks a workload at admission and runtime — not just whether it's configured. Every verdict is backed by a live cluster response.
  - title: Structurally safe
    details: All execution is confined to a dedicated, RBAC-enforced test namespace. The runner's service account cannot create, read, or affect anything outside it — enforced by Kubernetes, not by convention.
  - title: Deterministic verdicts
    details: PASS / FAIL / ERROR / SKIPPED computed by the CLI, not an LLM. Chaosify owns correctness; the agent only decides what to test and what it means.
  - title: Built for agents
    details: Pre-correlated recon threat graphs and a compact --format summary TSV mode hand an AI agent leads to confirm — entry point → capability → impact — not raw dumps to reassemble.
  - title: Free-form pentesting
    details: Four composable primitives — exec, network, identity, detect — let an agent generate manifests on the fly from recon findings and probe the real attack surface.
  - title: Verifiable evidence
    details: Every finding is a structured JSON artifact with the exact command, exit code, stdout, and cleanup status. Reproducible proof, not a scanner score.
---

## What Chaosify does {#what-it-does}

Most Kubernetes security tools read your YAML and tell you what *should* happen.
Chaosify submits a real workload to a real cluster and records what *actually*
happened — then computes a deterministic verdict from the live API response.

```bash
# Does the cluster actually reject a privileged container?
chaosify probe run --scenario deny-privileged-container --context prod
```

```text
deny-privileged-container … FAIL
  expected: rejected (admission should deny privileged: true)
  observed: allowed   (pod admitted, running)
  evidence: ./chaosify-evidence.json
```

A `FAIL` here is not a guess from a config linter — it is the cluster admitting a
privileged pod that your policy was supposed to stop. That gap is real, and now
you have the receipt.

## From recon to confirmed exploit {#recon-to-exploit}

Chaosify surveys eight read-only dimensions of cluster posture — webhooks,
policies, PSA, RBAC, nodes, network policies, runtime agents, and topology — and
**correlates** them into attack leads rather than dumping isolated facts.

```bash
chaosify recon rbac --context prod --format summary
```

```text
# tool=rbac status=ok podsScanned=10 tokensHarvested=3
SEV       ENTRYPOINT                  SA             EXPLOITS                  PERMS
CRITICAL  attacker-pod/pentest-lab    privileged-sa  priv-esc,lateral,secret  pods,pods/exec:get,list,create; secrets:get,list,watch
HIGH      falco-vkfxt/falco           falco          secret                   nodes,namespaces,pods,services:get,list,watch
# blindSpot: kyverno tokens unreadable in 4 controller pods
```

The `summary` mode emits a compact TSV — one deduped row per finding, severity
sorted, with scan metadata and blind spots as `#` comments — purpose-built for a
low-token agent context window. An RBAC report that was **475 lines** of
pretty-printed JSON becomes the **~6 lines** an agent actually acts on. See the
[recon summary format](/recon-summary-format).

## Confirm gaps with execution primitives {#primitives}

Once recon surfaces a lead, four composable primitives let an agent (or you)
prove it on the live cluster. All run inside the RBAC-scoped test namespace.

| Primitive | Question it answers | Example |
|---|---|---|
| `probe exec` | Can a pod run this command and read this file? | `cat /etc/shadow` → exit 0, contents returned |
| `probe network` | Can a pod reach this target? | `http://169.254.169.254/…` → metadata endpoint reachable |
| `probe identity` | Is this service account *actually* allowed to do this? | `chaosify-runner create pods` in `default` → denied |
| `probe detect` | Does a runtime tool fire an alert for this technique? | `nsenter` host escape → no alert observed |

```bash
chaosify probe detect \
  --pod ./escape-probe.yaml \
  --run "nsenter --mount=/proc/1/ns/mnt -- cat /etc/shadow" \
  --expect alert_fired \
  --alert-source falco \
  --observation-window 15
```

The **Critical** classification falls out of the combination Chaosify can prove
end to end: the attack *succeeded* **and** *went undetected*.

## Structurally safe by design {#safety}

Chaosify's safety guarantee is not about restricting which manifests you submit —
it's about guaranteeing they can't escape. The runner's service account is
RBAC-bound to one test namespace (default: `chaosify`). An agent can generate and
submit arbitrary attack manifests for free-form pentesting, and the blast radius
holds regardless.

```text
identity:chaosify-runner/create/pods (in default) … PASS
  expected: denied
  observed: denied   ← isolation held even on a cluster with no admission controls
```

Every run is namespace-scoped, timeout-bound, least-privilege, and
auto-cleaned-up. See the [safety model](/architecture#_6-safety-model).

## Proven against a known-bad cluster {#case-study}

Run against [Kubernetes Goat](/case-study-kubernetes-goat) — a deliberately
vulnerable cluster with no policy engine, no runtime detection, and no network
policies — Chaosify surfaced the full attack surface in under five seconds and
confirmed every gap with live evidence:

- **Critical** — host namespace escape via `nsenter` succeeded *and* fired no alert
- **High** — `/etc/shadow` read succeeded from inside an unprivileged container
- **High** — privileged + `hostPID` workloads admitted with no policy engine
- **Verified** — Chaosify's own RBAC isolation held throughout

No false negatives on a cluster with no controls at all. Read the full
[case study](/case-study-kubernetes-goat).

## Drives an AI agent, end to end {#agents}

Chaosify ships two agentic skills. **Chaosify owns the pass/fail verdict; the
skills own the workflow, interpretation, and remediation layer.**

- **`chaosify`** — targeted control verification when you know what to run: recon
  init, preflight, scenario-pack runs, failure summarization, fleet fan-out.
- **`agentic-pentest`** — autonomous assessment: the agent runs recon first, then
  uses the execution primitives to probe the surface, producing a prioritized
  Critical / High / Gap report.

The same single-cluster core scales horizontally — an agent fans the CLI out
across a fleet and aggregates the JSON evidence, while the verification engine
stays simple and deterministic. See the [architecture](/architecture).

## Quick start {#quick-start}

Requires Node.js ≥ 22.16.0.

```bash
npm install -g chaosify-kubernetes
```

```bash
# 1. Create the RBAC-scoped test namespace + ResourceQuota
chaosify setup init --context <ctx>

# 2. Verify the cluster is ready
chaosify probe preflight --context <ctx>

# 3. Survey posture (read-only), then run a control pack
chaosify recon rbac --context <ctx> --format summary
chaosify probe run --pack preventive-baseline --context <ctx>
```

Exit codes make orchestration trivial: `0` all passed · `1` failed control ·
`2` execution error · `3` preflight failure · `4` invalid usage.

See the [Command Reference](/reference) for every command and flag, the
[Scenarios](/scenarios) catalog for what each control verifies, and the
[Recon Summary Format](/recon-summary-format) for the low-token agent output mode.
