# Chaosify Code Audit

**Date:** 2026-06-05  
**Scope:** All source files, documentation, and skill files

---

## Summary

| Category | Count |
|---|---|
| Code bugs / correctness | 4 |
| Dead / unreachable code | 2 |
| Duplicate implementations | 3 |
| Code quality / consistency | 5 |
| Documentation issues | 6 |
| Stale references | 4 |

---

## Code Bugs / Correctness

### B-1 — Version mismatch across 3 files

`package.json` declares `0.1.1` but two source files still hardcode `0.1.0`:

- `src/cli/registry.ts:41` — `.version('0.1.0')`
- `src/core/teardown/evidence-builder.ts:3` — `const VERSION = '0.1.0'`

The `version` subcommand prints the registry value, and every evidence artifact embeds `VERSION`. Both will report a stale version number to users and in artifacts.

**Fix:** Read the version from `package.json` at build time or centralize it into a single constant in `src/version.ts` that `package.json` cannot diverge from.

---

### B-2 — `process.env['USER']` fails silently on Windows

`src/core/teardown/evidence-builder.ts:42`:

```ts
initiatedBy: process.env['USER'] ?? 'unknown',
```

`USER` is POSIX-only. On Windows the environment variable is `USERNAME`. The field will always be `'unknown'` in any Windows environment.

**Fix:** `process.env['USER'] ?? process.env['USERNAME'] ?? 'unknown'`

---

### B-3 — Default namespace mismatch between `setup` and `probe`

`setup init` and `setup cleanup` default to the `chaosify` namespace (via `DEFAULT_RECON_NAMESPACE` in `src/cli/commands/recon/utils/shared.ts:4`). All probe commands (`probe run`, `probe exec`, `probe network`, `probe detect`, `probe identity`) default to `chaosify-tests` (via `DEFAULT_PROBE_NAMESPACE` in `src/cli/commands/verify/utils/shared.ts:2`).

This means a user who runs `chaosify setup init` followed by `chaosify probe run --pack preventive-baseline` without specifying `--namespace` will have the probe create a *different* namespace (`chaosify-tests`) from the one `init` prepared (`chaosify`). The skill files and case study both refer to "the `chaosify` namespace", reinforcing the mismatch.

**Fix:** Either unify the two constants to the same value, or explicitly document that `setup init` and probe commands use different namespaces by default and each requires `--namespace` to be consistent.

---

### B-4 — `ScenarioRegistry.build()` JSDoc claims `pack.yaml` is required

`src/core/scenarios/registry.ts:120`:

```ts
/**
 * Builds and returns a registry loaded from all pack directories under scenariosDir.
 * Discovers pack directories automatically — each subdirectory must contain a pack.yaml.
 */
```

The implementation never reads or checks for a `pack.yaml` file. It derives all pack metadata from the directory name and registers every `*.yaml` file found inside. The comment incorrectly describes a non-existent constraint.

**Fix:** Remove the "must contain a pack.yaml" clause from the JSDoc.

---

## Dead / Unreachable Code

### D-1 — `src/core/kube/pod.ts` is never imported

This file exports `submitPod`, `waitForReady`, `execInPod`, and `deletePod`. A search across all source files and tests finds zero imports of `core/kube/pod`. Its role was entirely superseded by `src/core/scenarios/exec/pod-runner.ts`, which provides improved versions of the same primitives (`waitForPodRunning` checks container readiness and handles terminal phases; `execCapturing` captures stdout/stderr and handles timeout and RBAC denial).

The file is compiled, shipped in `dist/`, and adds surface area with no consumer.

**Fix:** Delete `src/core/kube/pod.ts`.

---

### D-2 — `Registry.register()` is a one-line wrapper with no purpose

`src/cli/registry.ts:29-31`:

```ts
register(program: Command, command: (program: Command) => void): void {
    command(program)
}
```

The method wraps a single function call. It adds no state, validation, error handling, or logging. Every call site — `registry.register(setup, init)` — is equivalent to writing `init(setup)` directly. The class adds no value over calling the command factories directly.

**Fix:** Remove the `Registry` class and the `registry` instance from `build()`. Call each command factory directly: `init(setup)`, `cleanup(setup)`, etc.

---

## Duplicate Implementations

### DUP-1 — Two `ensureNamespace` functions with different signatures

- `src/core/kube/namespace.ts:9` — `ensureNamespace(api: CoreV1Api, name: string): Promise<boolean>` — uses `isConflict()`, returns `false` on 409
- `src/core/scenarios/exec/pod-runner.ts:162` — `ensureNamespace(kc: KubeConfig, namespace: string): Promise<void>` — catches non-409 via raw status code comparison

Both create a namespace and silently succeed if it already exists, but with different detection logic and incompatible signatures. The pod-runner version is used by all probe commands and `run-context.ts`; the kube/namespace version is used by `core/setup/init.ts` (indirectly, via the `createNamespace` → `isConflict` path in `initNamespace`).

**Fix:** Consolidate to a single implementation. The pod-runner version is the de facto standard; the kube/namespace version can be removed or replaced by a thin wrapper over the pod-runner one.

---

### DUP-2 — Two `buildKubeConfig` functions with different return types

- `src/core/kube/client.ts:7` — returns `k8s.KubeConfig` only
- `src/cli/commands/recon/utils/shared.ts:10` — returns `{ kc: k8s.KubeConfig; clusterContext: string }`

All CLI commands use the shared.ts version because they need both the config and the context string. The `core/kube/client.ts` version is not imported anywhere outside of tests and is essentially shadowed. Having two exported functions with the same name performing nearly the same job invites confusion about which to use.

**Fix:** Remove `buildKubeConfig` from `src/core/kube/client.ts` or rename it to avoid ambiguity.

---

### DUP-3 — `header()` and `section()` in `output.ts` are identical

`src/cli/output.ts:11-14` (`header`) and `src/cli/output.ts:29-33` (`section`) have exactly the same implementation:

```ts
console.log()
console.log(chalk.bold(title))
```

The JSDoc describes them as distinct ("section title" vs "sub-section heading") but the output is visually identical. Call sites currently mix them somewhat arbitrarily. If they are truly meant to produce different output (e.g., different indentation or color), the implementations should diverge; if they are meant to be the same, one should be removed.

**Fix:** Either differentiate their visual output or consolidate them into a single `section()` function used throughout.

---

## Code Quality / Consistency

### Q-1 — Timeout constants duplicated across files with no shared source

Default timeouts are re-declared independently in:

| File | Constant | Value |
|---|---|---|
| `src/core/scenarios/exec/executor.ts:29` | `DEFAULT_TIMEOUT_MS` | `30_000` |
| `src/core/scenarios/exec/runtime-executor.ts:48-49` | `DEFAULT_TIMEOUT_MS` / `DEFAULT_OBSERVATION_WINDOW_MS` | `60_000` / `10_000` |
| `src/cli/commands/verify/run/run-scenarios.ts:7-8` | `DEFAULT_TIMEOUT_MS` / `DEFAULT_RUNTIME_TIMEOUT_MS` | `30_000` / `60_000` |
| `src/cli/commands/verify/exec.ts:17-19` | Three `_S` constants | Seconds variants |
| `src/cli/commands/verify/detect.ts:17-18` | Two `_S` constants | Seconds variants |
| `src/cli/commands/verify/network.ts:20-22` | Three `_S` constants | Seconds variants |

Changing a default timeout requires updating multiple files and searching for divergences. This is a maintenance hazard, not a bug, but it will cause drift.

---

### Q-2 — Command string splitting loses quoted arguments

In `src/cli/commands/verify/exec.ts:82` and `src/cli/commands/verify/detect.ts` (in `loadDetectScenario`):

```ts
const command = opts.run.split(' ')
```

Splitting on whitespace breaks commands containing quoted arguments with spaces (e.g., `--run "echo hello world"` becomes `["echo", "hello", "world"]` which is correct in that case, but `--run "cat '/etc/shadow'"` becomes `["cat", "'/etc/shadow'"]` which may or may not behave as intended depending on the shell inside the container). This is not guaranteed to cause failures in practice (exec commands are typically simple) but the limitation is undocumented and could surprise users.

---

### Q-3 — `topology` command omits cluster context from output

`src/cli/commands/recon/topology.ts:59`:

```ts
if (opts.context) field('Cluster Context', opts.context)
```

When `--context` is not explicitly passed, no cluster context is printed. Every other recon command calls `buildKubeConfig(opts.context)`, which returns the resolved active context and always prints it via `field('Cluster Context', clusterContext)`. The topology command is inconsistent and leaves the operator unable to confirm which cluster was surveyed from the output alone.

---

### Q-4 — `PreflightEngine` mutates shared `kc` in `run()`

`src/core/setup/preflight.ts:37-40`: `PreflightEngine` stores `this.kc` as instance state in the constructor, then mutates it in `run()` via `this.kc.setCurrentContext(options.context)`. If the same `PreflightEngine` instance were ever called with different contexts (or concurrently), the shared config would produce incorrect results. The current usage (one engine per command invocation) avoids this, but the design is fragile.

---

### Q-5 — `opts.run.split(' ')` in `detect.ts` discards early error context

In `src/cli/commands/verify/detect.ts:200`, the command split happens inside `loadDetectScenario` after the manifest is already loaded. Any error in the split is invisible to the caller. Contrast with `exec.ts:82` where the split is visible in the main action handler. Minor inconsistency in where this logic lives.

---

## Documentation Issues

### DOC-1 — `docs/reference.md` documents three unimplemented flags

The Flags table at `docs/reference.md:113-123` includes:

| Flag | Status |
|---|---|
| `--kubeconfig <path>` | Not implemented in any command |
| `--quiet` | Not implemented in any command |
| `--no-color` | Not implemented in any command |

These flags do not appear in any `commander` `.option()` call across the codebase. Users trying to use them will get no error — Commander silently ignores unknown options unless `allowUnknownOption(false)` is set — and the flags will have no effect.

**Fix:** Remove the three phantom flags from the table, or implement them.

---

### DOC-2 — `docs/architecture.md` has a broken internal link

`docs/architecture.md:237`:

```
For the evidence JSON schema, see [execution-layer-design.md](execution-layer-design.md).
```

`docs/execution-layer-design.md` does not exist. It was never committed. The link 404s.

**Fix:** Replace the link with a reference to `docs/reference.md` (§JSON Artifact Schema), or create the file.

---

### DOC-3 — Root-level YAML probe files are undocumented

`probe-hostns.yaml`, `probe-nettest.yaml`, and `probe-privileged.yaml` sit at the repository root with no mention in any documentation, README, or skill file. It is unclear whether these are example manifests for users, integration test fixtures, or artifacts from development. They appear in `git ls-files` output so they are tracked.

**Fix:** Either document them (add a `## Example probe manifests` section to README or reference.md), move them to a documented location like `examples/`, or remove them if they are not intentionally shipped.

---

## Stale References

### SR-1 — `agentic-pentest/references/cli-reference.md` documents wrong `rbac` data shape

`skills/agentic-pentest/references/cli-reference.md:108-111` says the `rbac` recon tool returns:

| Field | Description |
|---|---|
| `clusterAdminBindings` | Principals bound to `cluster-admin` |
| `highPrivilegePrincipals` | SAs with cluster-wide secret or wildcard access |

The actual implementation in `src/core/recon/rbac.ts:112-120` returns:

```ts
data: {
    clusterRoleCount: roles.length,
    clusterRoleBindingCount: bindings.length,
    partial: skipFindings.length > 0,
}
```

Neither `clusterAdminBindings` nor `highPrivilegePrincipals` exist in the output. An AI agent using this reference to parse recon results would always read `undefined` for these fields.

---

### SR-2 — `agentic-pentest/references/cli-reference.md` documents wrong `network-policies` data shape

`skills/agentic-pentest/references/cli-reference.md:113-117` documents:

| Field | Description |
|---|---|
| `namespace` | Namespace name |
| `policyCount` | Number of NetworkPolicy resources |
| `hasEgressPolicy` | Whether any egress policy exists |
| `hasDefaultDeny` | Whether a default-deny policy exists |

Also the array field is listed as `data.namespaceStatuses`. The actual code (`src/core/recon/network-policies.ts:76-85`) returns `data.namespaces` (not `data.namespaceStatuses`), with fields `hasIngress` and `hasEgress` (not `hasEgressPolicy`), and no `hasDefaultDeny` field at all.

---

### SR-3 — `skills/chaosify/SKILL.md` contains stale product name "ClawHub"

`skills/chaosify/SKILL.md:17`:

```
It is not a ClawHub skill or cloud service.
```

"ClawHub" appears to be a prior internal name. It does not appear anywhere else in the codebase or documentation and would be confusing to external users.

---

### SR-4 — `docs/reference.md` does not mention `skills/claude/SKILL.md`

`docs/reference.md:171-172` instructs users to add `skills/chaosify/` and `skills/agentic-pentest/` to their agent's skill search path. However, the repository also ships `skills/claude/SKILL.md`, which is a merged Claude Code–specific version of both skills in a single file. The reference docs never mention it, so Claude Code users following the docs will use the wrong skill files.

**Fix:** Add a note in `docs/reference.md` indicating that Claude Code users should use `skills/claude/SKILL.md` instead.
