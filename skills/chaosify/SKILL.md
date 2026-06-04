---
name: chaosify
description: Verify Kubernetes preventive controls using the Chaosify CLI — preflight checks, scenario pack runs, evidence parsing, and failure summarization for single-cluster or fleet-wide workflows.
metadata: {"openclaw": {"emoji": "⚔️", "requires": {"bins": ["chaosify", "kubectl"]}, "install": [{"id": "brew", "kind": "brew", "formula": "chaosify", "bins": ["chaosify"], "label": "Install Chaosify (brew)"}]}}
---

TRIGGER when: the user asks to verify Kubernetes controls, guardrails, admission policies, or Kyverno policies; asks to run Chaosify or a Chaosify scenario pack; asks to check whether a cluster's preventive controls are working; asks to investigate a failed control; or uses terms like "control verification", "preventive baseline", or "deny-*" scenario names.

SKIP: full cluster pentesting or security assessments — use the `openclaw-pentest` skill instead. Skip general Kubernetes debugging unrelated to admission controls or preventive policies; questions about Chaosify internals or source code.

---

# Chaosify Skill — Kubernetes Control Verification

**What is Chaosify?** Chaosify is a local CLI binary (`chaosify`) installed on the machine running this agent. It is not a ClawHub skill or cloud service. Before starting any workflow, verify it is available:

```bash
chaosify version
```

If the command is not found, tell the user to install Chaosify before proceeding. Do not attempt to install it yourself.

Before starting any workflow, read `references/goal-elaboration.md` to understand what verification means and how to interpret results.

For all CLI commands, flags, JSON schema, exit codes, and remediation steps, refer to `references/cli-reference.md`.

---

## Workflow: `verify_cluster_baseline`

Use when the user wants to verify a single cluster.

**Step 1 — Resolve cluster context.**
Ask the user which Kubernetes context to use if not already known. Run `kubectl config get-contexts`. Confirm before proceeding — never silently choose a context.

**Step 2 — Initialize the test namespace (first run only).**
If this is the first time running against this cluster, initialize the `chaosify` namespace:
```bash
chaosify setup init --context <context-name>
```
See `references/cli-reference.md` §Setup. Skip if the user confirms it already exists.

**Step 2.5 — Run topology recon (if graphnetes is installed).**
```bash
chaosify recon topology --context <context-name> --namespace chaosify --output topology.json
```
If graphnetes is not installed the command returns `status: skip` — continue to Step 3. If it succeeds, read `topology.json`. Use `data.stats.secretMounts`, `data.stats.ingressPaths`, and `data.stats.serviceAccountBindings` to identify high-value targets and inform which scenarios or `--manifest` test cases to prioritize.

**Step 3 — Run preflight.**
See `references/cli-reference.md` §Preflight for the command and how to handle each outcome.

**Step 4 — Run the baseline pack.**
See `references/cli-reference.md` §Run. Write output to `chaosify-result.json`.

**Step 5 — Parse and summarize results.**
Read the JSON artifact. Follow the summarization rules in `references/goal-elaboration.md` §Summarization.

---

## Workflow: `rerun_failed_scenarios`

Use after the user has applied a fix and wants to re-verify.

Run the single scenario (see `references/cli-reference.md` §Rerun). Compare the new result against the previous artifact. Report whether the control now passes.

---

## Workflow: `verify_prod_fleet`

Use when the user has a cluster inventory (`clusters.yaml`) and wants to verify multiple clusters.

For each cluster, run Steps 2–4 of `verify_cluster_baseline`, writing per-cluster output. After all runs, aggregate using the fleet rules in `references/goal-elaboration.md` §Fleet. See `references/cli-reference.md` §Fleet for command syntax.

Run clusters sequentially unless the user explicitly requests parallel execution.

---

## Safety Reminders

- Always confirm the cluster context before running. Never assume the current context is the intended target.
- Never skip preflight — it is a safety gate. Decline if the user asks to skip it.
- Chaosify always runs in a dedicated test namespace (`chaosify-tests` by default). It does not touch application namespaces.
- If cleanup reports a partial failure, surface the `kubectl delete` command so the user can clean up manually.
