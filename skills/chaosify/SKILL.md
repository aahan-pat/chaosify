---
name: chaosify
description: Verify Kubernetes preventive controls using the Chaosify CLI — preflight checks, scenario pack runs, manifest-based edge case testing, and evidence-backed failure summarization for single-cluster or fleet-wide workflows.
metadata:
  requires:
    bins: ["chaosify", "kubectl"]
---

TRIGGER when: the user asks to verify Kubernetes controls, guardrails, admission policies, or Kyverno/OPA policies; asks to run Chaosify or a scenario pack; asks to check whether a cluster's preventive controls are working; asks to investigate a failed control; or uses terms like "control verification", "preventive baseline", or any `deny-*` scenario name.

SKIP: full cluster pentesting or security assessments — use the `agentic-pentest` skill instead. Skip general Kubernetes debugging unrelated to admission controls; questions about Chaosify internals or source code.

---

# Chaosify Skill — Kubernetes Control Verification

Chaosify is a local CLI binary (`chaosify`) on the machine running this agent. Verify it is present before any workflow:

```bash
chaosify version
```

If not found, tell the user to install Chaosify and stop.

For all CLI flags, JSON schema, exit codes, and remediation steps refer to `references/cli-reference.md`. For result interpretation and summarization rules refer to `references/goal-elaboration.md`.

---

## Tool Inventory

Use only the tools listed here. Do not use raw `kubectl` (except `config get-contexts`), `curl`, or any shell command not listed.

**Read-only:**
```
kubectl config get-contexts
chaosify probe preflight --context <ctx>
chaosify scenarios list [--pack <id>]
chaosify scenarios show <id>
```

**Write to disk — manifest authoring:**
```
Write <run>/manifests/<name>.yaml    generate pod manifest YAML before probing
```

**Cluster-mutating — all auto-cleanup, all namespace-scoped:**
```
chaosify probe run --pack <id>          --context <ctx>
chaosify probe run --scenario <id>      --context <ctx>
chaosify probe run --manifest <path> --expect <rejected|allowed> --context <ctx>
chaosify probe exec --pod <path> --run "<cmd>" --expect <succeeded|failed|denied>
```

**Setup:**
```
chaosify setup init    --context <ctx>
chaosify setup cleanup --context <ctx>
```

---

## Run Output Directory

Create one run directory at the start of every session and keep **all** artifacts under it — generated manifests and evidence JSON. Never scatter files into the working directory root. Use the UTC start time as the run id:

```
.chaosify/runs/<run>/        <run> = UTC start time, e.g. 2026-06-09T11-40-00Z
```

Within that single run root you are free to organize files as you see fit, with one rule: **bundle similar runtime artifacts into their own subfolders.** Keep generated YAML manifests separate from Chaosify's JSON evidence outputs. A natural grouping — the one the examples below use — is:

```
.chaosify/runs/<run>/
  manifests/     generated pod YAML
  results/       run + probe evidence JSON
```

but the subfolder names are yours to choose; only the single run root and the like-with-like grouping are required. Pick `<run>` once at the start and reuse the same path for every file this session, so each run is self-contained and comparable against the previous one (the `rerun_failed_scenarios` workflow diffs against the prior run's evidence). The harness shell does not persist variables between commands — substitute the literal path each time rather than relying on an env var. Chaosify never imposes this layout itself (`--output` writes wherever it is told), so routing artifacts here is your responsibility.

---

## Workflow: `verify_cluster_baseline`

**Step 1 — Resolve cluster context.**
Run `kubectl config get-contexts`. Confirm the target context with the user before proceeding.

**Step 2 — Initialize the test namespace (first run only).**
```bash
chaosify setup init --context <context-name>
```
Skip if the user confirms it already exists.

**Step 3 — Run preflight.**
See `references/cli-reference.md` §Preflight. Abort on permission error; proceed through missing-policy-engine warnings.

**Step 4 — Run the scenario pack.**
```bash
chaosify probe run --pack preventive-baseline --context <context-name> --output .chaosify/runs/<run>/results/preventive-baseline.json
```
See `references/cli-reference.md` §Run for runtime-baseline and single-scenario variants.

**Step 5 — Parse and summarize results.**
Read the JSON artifact. Apply rules in `references/goal-elaboration.md` §Summarization.

**Step 6 — Test edge cases with generated manifests.**
When a scenario passes but the policy may not cover all resource types, generate a manifest that targets the gap and test it directly:

```bash
# Example: test whether the hostPath policy covers initContainers
chaosify probe run --manifest .chaosify/runs/<run>/manifests/probe-initcontainer.yaml --expect rejected --context <context-name>
```

Use the manifest building blocks below to construct targeted probes. Write each manifest with the `Write` tool into `<run>/manifests/` before submitting.

**Base manifest template:**
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

**Fields to add for edge case coverage:**
```yaml
# Test initContainers coverage (policies sometimes miss these)
  initContainers:
    - name: init-probe
      image: busybox:1.36
      securityContext:
        privileged: true        # or whichever field the scenario tests

# Test that a policy applies even without explicit securityContext
  containers:
    - name: probe
      image: busybox:1.36
      # no securityContext at all — policy should still enforce default deny

# Test hostPath in a volume only (no mount) — catches incomplete policies
  volumes:
    - name: host-vol
      hostPath: {path: /etc}
```

---

## Workflow: `rerun_failed_scenarios`

Run the single failing scenario after the user applies a fix. Compare the new result against the previous artifact. Report whether the control now passes.

See `references/cli-reference.md` §Rerun for the command.

---

## Workflow: `verify_prod_fleet`

For each cluster in a `clusters.yaml`, run Steps 2–4 of `verify_cluster_baseline` writing per-cluster output. After all runs, aggregate using the fleet rules in `references/goal-elaboration.md` §Fleet.

Run clusters sequentially unless the user explicitly requests parallel execution.

---

## Safety

- Always confirm the cluster context. Never assume the current context is the intended target.
- Never skip preflight — it is a safety gate.
- All generated manifests must use `generateName: chaosify-test-` and must not set `namespace:`.
- All execution is confined to the `chaosify-tests` namespace.
- If cleanup reports partial failure, surface the `kubectl delete pod -n chaosify-tests --all` command.
