# `chaosify recon rbac` — Command Specification

## Purpose

`chaosify recon rbac` performs automated RBAC reconnaissance against a Kubernetes cluster, simulating the methodology of an expert pentester. The goal is not to enumerate all RBAC policies exhaustively, but to identify **exploitable privilege chains** — paths from a reachable entry point to a meaningful security impact.

---

## Core Question This Command Answers

> "Given what I can reach, is there a path to something I shouldn't have access to — and how?"

All data collection and reasoning is subordinate to this question. Anything that doesn't contribute to answering it is noise.

---

## What the Command Does

### 1. Enumerate Running Pods
Using the CLI's own permissions (`pods/list`, `pods/get`), the command lists all running pods and extracts:

- Pod name and namespace
- Mounted ServiceAccount name
- Whether `automountServiceAccountToken` is enabled

This is the entry point for all subsequent recon. The CLI operates pod-first, not role-first, since pods are the physical entry points into ServiceAccount identities.

### 2. Harvest ServiceAccount Tokens via Exec
For each reachable pod, the command execs in and reads the mounted token:

```
/var/run/secrets/kubernetes.io/serviceaccount/token
```

This is possible because the CLI holds `pods/exec` permissions. Each harvested token represents a ServiceAccount identity that can be independently interrogated.

### 3. Fingerprint Each Token's Permissions
For each harvested token, the command queries the Kubernetes API using `SelfSubjectRulesReview` to determine the **effective permissions** of that identity:

```bash
curl -s \
  --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  https://kubernetes.default.svc/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}'
```

This returns flattened effective permissions, accounting for multiple role bindings, aggregated roles, and cluster-wide grants — without needing direct access to Role or ClusterRole objects.

### 4. Identify Exploitable Privilege Chains
The agent reasons over the collected permission data to flag identities that enable one or more of the following exploit classes:

#### Privilege Escalation
- `bind` or `escalate` verbs → can grant itself new roles
- `create` on `clusterrolebindings` → can bind itself to `cluster-admin`
- `create` on `pods` → can spawn a privileged pod and escape to the node

#### Lateral Movement
- SA token with cross-namespace access → pivot from one compromised workload to another
- Exec access into a pod carrying a high-privilege SA → stepping stone to broader access

#### Secret / Data Access
- `get` on `secrets` → can read all secrets in namespace, including other SA tokens
- `get` on `configmaps` → may expose credentials, connection strings, or internal configuration

### 5. Emit a Targeted Threat Graph
The command outputs a structured summary of discovered exploit paths — not a raw RBAC dump. Each finding maps:

```
Entry Point (Pod) → Identity (ServiceAccount) → Permissions → Impact
```

---

## What the Command Does NOT Do

- **Does not dump all roles and clusterroles.** The CLI lacks direct RBAC API access, and even with it, a full dump is not useful to the agent.
- **Does not enumerate ServiceAccounts directly.** SA discovery is derived from pod specs — only SAs actually mounted in running pods are relevant.
- **Does not reason about theoretical identities.** Only SAs attached to reachable, running pods are in scope.

---

## CLI Permissions Required

| Resource   | get | list | create | delete |
|------------|-----|------|--------|--------|
| pods       | ✅  | ✅   | ✅     | ✅     |
| pods/exec  | ✅  | ✅   | ✅     | ✅     |
| pods/log   | ✅  | ✅   | ✅     | ✅     |

Direct RBAC API access (`roles`, `clusterroles`, `rolebindings`, `serviceaccounts`) is **not required**. All RBAC intelligence is gathered indirectly via exec and token introspection.

---

## Recon Loop (Execution Order)

```
1. list pods (all namespaces)
       ↓
2. extract SA name + automount status from each pod spec
       ↓
3. exec into each pod → harvest token
       ↓
4. SelfSubjectRulesReview per token → effective permissions
       ↓
5. flag dangerous permissions (escalation / lateral movement / secret access)
       ↓
6. emit threat graph: Pod → SA → Permissions → Impact
```

---

## Agent Output Format

The agent emits a YAML threat summary structured for readability and further action:

```yaml
findings:
  - pod: target-pod
    namespace: default
    service_account: default
    token_harvested: true
    exploit_classes:
      - privilege_escalation
      - secret_access
    dangerous_permissions:
      - resources: [secrets]
        verbs: [get, list]
      - resources: [clusterrolebindings]
        verbs: [create]
    attack_chain: >
      Exec into target-pod → harvest SA token → token can create clusterrolebindings
      → bind to cluster-admin → full cluster compromise
    severity: critical
```

---

## Design Principles

- **Pod-first, not role-first.** Roles that aren't bound to running pods are irrelevant to an attacker with exec access.
- **Effective permissions over policy objects.** `SelfSubjectRulesReview` gives the ground truth of what an identity can actually do, accounting for all bindings and aggregations.
- **Signal over volume.** The agent receives a filtered, pre-correlated threat graph — not raw API dumps. Triage happens in the CLI, not in the agent's context window.
- **Honest about blind spots.** The command surfaces what it cannot see (e.g. roles not bound to any running pod) so the agent's conclusions are appropriately scoped.