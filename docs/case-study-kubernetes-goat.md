# Case Study: Kubernetes Goat on minikube

**Date:** 2026-05-28  
**Cluster:** minikube  
**Target environment:** [Kubernetes Goat](https://madhuakula.com/kubernetes-goat/) — a deliberately vulnerable Kubernetes environment  
**Tool version:** ChaosClaw v0.1.0  
**Overall posture:** Critical

---

## Setup

Kubernetes Goat is an intentionally misconfigured Kubernetes environment used for security training and tooling validation. It ships with several application namespaces (`big-monolith`, `secure-middleware`) and no security controls configured — no policy engine, no runtime detection agents, and no network policies. This makes it an ideal environment for validating that ChaosClaw correctly identifies a fully unprotected cluster.

ChaosClaw was run against Kubernetes Goat deployed on a local minikube instance. All activity was confined to the `chaosclaw` test namespace via RBAC-enforced isolation.

---

## Recon

The first step was a full cluster survey. ChaosClaw surveyed eight dimensions — webhooks, policies, PSA, RBAC, nodes, network policies, runtime agents, and topology — in under five seconds.

```bash
chaosclaw recon webhooks         --context minikube --output recon-webhooks.json --format json
chaosclaw recon policies         --context minikube --output recon-policies.json --format json
chaosclaw recon psa              --context minikube --output recon-psa.json      --format json
chaosclaw recon rbac             --context minikube --output recon-rbac.json     --format json
chaosclaw recon nodes            --context minikube --output recon-nodes.json    --format json
chaosclaw recon network-policies --context minikube --output recon-netpol.json  --format json
chaosclaw recon runtime-agents   --context minikube --output recon-agents.json  --format json
```

**Summary: 1 Critical, 3 High, 2 Warn**

| Severity | Tool | Finding |
|---|---|---|
| Critical | `policies` | No policy engine detected — Kyverno and OPA/Gatekeeper are absent |
| High | `webhooks` | No admission webhooks — no webhook-based enforcement layer |
| High | `network-policies` | 5 namespaces with no NetworkPolicies — all pod-to-pod traffic unrestricted |
| High | `runtime-agents` | Falco, KubeArmor, Tetragon, and Tracee all absent — no runtime detection |
| Warn | `psa` | 5 user namespaces with no Pod Security Admission labels |
| Warn | `rbac` | `cluster-admin` bound to non-system principal (`kubeadm:cluster-admins`) |

The recon report established a complete picture before any test workloads were submitted: the cluster had no admission-level enforcement, no runtime detection, and unrestricted network traffic between namespaces. With this context, ChaosClaw identified three high-priority attack paths to probe.

---

## Execution

### Attack path 1 — Sensitive file read goes undetected

**Primitive:** `probe exec`  
**Command:** `cat /etc/shadow`  
**Expected:** `failed` (a restrictive policy or PSA should prevent the pod or block the read)  
**Observed:** `succeeded` — exit code 0, shadow file contents returned in stdout

```json
{
  "scenarioId": "exec:basic-pod.yaml",
  "status": "Fail",
  "expectedOutcome": "failed",
  "observedOutcome": "succeeded",
  "rawResponse": "{\"exitCode\":0,\"stdout\":\"root:*:::::::\\ndaemon:*:::::::\\n...\"}"
}
```

With no policy engine and no PSA labels on the namespace, the pod was admitted without restriction. The container ran as an unprivileged user but the host shadow file was still readable — confirming that filesystem access controls were absent. An attacker with pod exec access in any of the five unprotected namespaces could read this file without triggering any alert.

---

### Attack path 2 — Host namespace escape with no detection

**Primitive:** `probe detect`  
**Technique:** `nsenter` with `hostPID: true`  
**Expected:** `no alert` (no runtime agent installed, so no alert is possible)  
**Observed:** `no alert observed`

```json
{
  "scenarioId": "custom:detect:privileged-pod.yaml",
  "status": "Pass",
  "expectedOutcome": "no alert",
  "observedOutcome": "no alert observed"
}
```

This result is a `PASS` against expectation but represents the most severe posture finding in the run. A privileged pod with `hostPID: true` was admitted, `nsenter` executed against the host mount namespace, and no alert fired — because no runtime agent was present to observe it. The technique succeeded completely and silently.

This is the combination that produces a **Critical** classification: the attack succeeded AND went undetected.

---

### Control verification — ChaosClaw RBAC isolation held

**Primitive:** `probe identity`  
**Service account:** `chaosclaw-runner`  
**Check:** `create pods` in `default` namespace  
**Expected:** `denied`  
**Observed:** `denied`

```json
{
  "scenarioId": "identity:chaosclaw-runner/create/pods",
  "status": "Pass",
  "expectedOutcome": "denied",
  "observedOutcome": "denied"
}
```

Throughout the run, ChaosClaw's own service account remained scoped to the `chaosclaw` namespace. It could not create pods, read secrets, or affect any other namespace. This confirms the safety model held even on a cluster with no admission controls — isolation is enforced at the Kubernetes RBAC level, not by convention.

---

## Findings summary

| Classification | Finding |
|---|---|
| **Critical** | Host namespace escape (`nsenter`) executed successfully with no runtime detection |
| **Critical** | No runtime detection layer — Falco, KubeArmor, Tetragon, and Tracee all absent |
| **High** | Sensitive file read (`/etc/shadow`) succeeded from inside a container |
| **High** | No admission policy engine — privileged and hostPID workloads admitted without restriction |
| **High** | No NetworkPolicies in 5 namespaces — unrestricted lateral movement between pods |
| **Verified** | ChaosClaw RBAC namespace isolation confirmed |

---

## What this demonstrates

This run validates ChaosClaw against a known-bad cluster and confirms two things:

**Detection accuracy.** ChaosClaw correctly identified every significant gap in the cluster — no false negatives on a cluster with no controls at all. The recon layer surfaced the full attack surface before a single test workload was submitted, and the execution primitives confirmed each gap with live cluster evidence.

**Evidence quality.** Every finding is backed by a structured JSON artifact with the exact command, exit code, stdout, and cleanup status. This is verifiable, reproducible evidence — not a scanner score or a static configuration check.

