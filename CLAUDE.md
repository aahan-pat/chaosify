# CLAUDE.md

Guidance for working in this repo. Read this before making changes.

## What Chaosify is

Chaosify is a **Kubernetes security control-verification tool** written in Go. It
enumerates and exercises an identity's real access against a cluster, then reports
whether the cluster's controls held.

The product is a **loop**, not a single scan:

```
Recon → Select scenario → Execute (safe boundary) → Verify → Report ─┐
  ▲                                                                    │
  └──────────────────── re-run continuously ──────────────────────────┘
```

- **One pass = a pentest.** The **repeat = continuous control verification.**
- Scenarios live in a **persistent, reusable library** (select from it first, generate
  and save new ones only when needed), which makes each re-run cheap, deterministic,
  and comparable against the previous run's report.
- Every action is **scoped, reversible, and cleaned up**. Verify asks: was it
  blocked? detected? remediated? alerted? Report emits a per-control verdict plus
  evidence and the trend vs. the last run.

This is authorized security tooling. It operates only inside an explicit engagement
window (see Authorization below) and defaults to a non-mutating dry-run.

## Core principles

Two rules govern every input field and most control flow:

1. **Order by connection state.** Offline inputs (authorization, connection details)
   are collected *before* any cluster call; cluster-querying inputs (identity, scope,
   stop-list) come *after* the connection exists.
2. **Provided-else-prompt.** Each field checks a flag/config value first and prompts
   interactively only if it is absent. This is deliberate: interactive `init` and
   non-interactive CI run the **same code path**. Preserve this when adding fields —
   don't fork logic between "interactive" and "CI" branches.

**Safety is a hard gate, not a default.** No connection is attempted until the
authorization window validates. `RunModeActive` requires an explicit confirmation
*plus* a configured scope and stop-list; `RunModeDryRun` is always the safe default.
Never weaken these gates for convenience.

## Layout

```
main.go                 Entry point → cmd.Execute()
cmd/
  root.go               Cobra root; wires subcommands via each package's New()
  init/                 Onboarding: authorization gate → connection → identity → scope
  recon/                Enumeration subcommands (get, permissions, ...)
internal/
  types/config.go       Shared, dependency-free engagement structs (Config, RunMode, ...)
  config/               Config resolution/persistence
  kube/onboarding.go    Cluster connection + onboarding flow against the API server
  recon/                Enumeration logic (identity, namespaces, permissions, rbac)
  ui/                   huh prompts + lipgloss theme
```

Subcommands live in their own `cmd/<name>` package and expose a `New() *cobra.Command`
constructor; wiring happens in `cmd/root.go`, not in package-level `init()` funcs.
`internal/types` holds plain structs with no third-party deps so any layer can import
it without cycles — keep it that way.

## Onboarding model (the `init` flow)

1. **Authorization gate (offline).** Engagement ID, sign-off reference, valid-from/until
   window. Validated at entry. **No connection until this passes.**
2. **Connection & identity.** Prefer a kubeconfig + context (file-select, then choose a
   context from a Select — never blind-typed; default `~/.kube/config` / `$KUBECONFIG`).
   Manual fallback (endpoint, CA cert, credential) only if kubeconfig is declined;
   TLS-skip must be an explicit, logged confirmation. Everything normalizes into one
   internal `Connection`.
3. **Verify + echo identity first.** Resolve who you are via `SelfSubjectReview`, display
   "Connected as ..." — this is also the first recon call.
4. **Scope.** Query readable namespaces → MultiSelect, all pre-checked (matches the
   "sweep all" default). Fall back to a default only if listing is denied. Cluster is
   *derived from the context*, never typed.
5. **Stop-list / denylist.** Reuse the queried namespace list as a MultiSelect (default
   none). Free-text only for finer resource/action rules.
6. **Run mode.** dry-run (default) vs. active; active triggers confirmation and requires
   scope + stop-list set.
7. **Expected privilege** (optional). Intended access level; any mismatch against
   enumerated reality is a finding. Default: enumerate-and-report, no reconciliation.

## Recon tiers

Enumeration degrades gracefully by what the identity is allowed to see:

- **Tier 0 — self-scoped (always runs, unconditional).** `SelfSubjectRulesReview` /
  `can-i --list` for the current identity. The API server lets any identity introspect
  itself, so this never fails. See `internal/recon/permissions.go`.
- **Tier 1 — cluster-scoped, gated per call.** RBAC objects, ServiceAccounts, pods,
  namespaces. **Probe each call first; never assume the broad picture succeeds.** This
  is where reality is discovered. See `internal/recon/rbac.go`, `namespaces.go`.
- **Tier 2 — derived analysis (no cluster calls).** Dangerous-verb flagging,
  subject→permission graph, escalation paths. Runs purely over Tier 0 + Tier 1 output;
  completeness scales with how much Tier 1 succeeded.

A recurring gotcha this implies: **listing namespaced resources never errors on a
missing namespace** — it returns an empty list for both a missing and an empty
namespace. Distinguish them with an explicit `Namespaces().Get` + `apierrors.IsNotFound`
only when the list is empty (see `internal/recon/rbac.go`).

## Conventions

- **Language/paradigm:** Go, object-oriented, composition-first. Match the surrounding
  code's style, comment density, and naming.
- **Errors:** wrap with context — `fmt.Errorf("...%q: %w", x, err)`. Check `err` before
  dereferencing any returned pointer (k8s List results included).
- **Kubernetes client:** `k8s.io/client-go` (v0.36.x). Use typed clientsets
  (`clientset.RbacV1()`, `CoreV1()`, `AuthorizationV1()`). For "can I" logic prefer
  `SelfSubjectRulesReview` over guessing.
- **CLI:** `spf13/cobra`. **Prompts:** `charm.land/huh/v2` (Select/MultiSelect, not
  free-text where a queried list exists). **Styling:** `charm.land/lipgloss/v2` via
  `internal/ui/theme.go`.

## Build & run

```
go build ./...           # build everything
go build ./internal/recon/   # build one package
go vet ./...
chaosify init            # run the onboarding flow
chaosify recon ...       # run enumeration
```

The module is `github.com/aahan-pat/chaosify`, Go 1.26.
