# Architecture

> Scope: **recon commands only** (the read-only reconnaissance phase). Other
> phases will be documented as they land.

## The one idea

Every recon command does the same three things:

```
   Kubernetes API server  ──►  parse into plain Go values  ──►  display to the LLM
        (retrieve)                    (shape the data)              (readable output)
```

1. **Retrieve** — ask the cluster's API server for data, as the identity that
   `chaosify init` established.
2. **Parse** — turn the raw Kubernetes objects into simple strings/slices that
   capture only what matters.
3. **Display** — print those in a clean, labelled format an LLM (or a human) can
   read and reason over.

That's the whole loop. A recon command is just: *get data, make sense of it, show it.*

## Two layers

The code splits along the retrieve-parse vs. display boundary:

| Layer | Package | Job |
|-------|---------|-----|
| **Command** | `cmd/recon/` | CLI wiring: define the command, connect to the cluster, call the logic, print the result. |
| **Logic** | `internal/recon/` | Talk to the API server and parse the response into plain Go values. **No printing, no CLI.** |
| **Display** | `internal/ui/` | `PrintBanner`, `PrintField`, `PrintInfo` — the readable output format. |

The rule: `internal/recon/` never prints and never imports cobra; `cmd/recon/`
never talks to Kubernetes directly. Keeping them separate means the logic is
reusable and the output format lives in one place.

## Walking one command

`chaosify recon get roles <namespace>` end to end:

```
cmd/recon/get.go          runRoles(ctx, client, namespace)
                             │
internal/recon/rbac.go       └─► ListRoles(...)  ── retrieve ──►  clientset.RbacV1().Roles(ns).List()
                                                  ── parse   ──►  RoleList → map[roleName][]"verb resource"
                             ┌───────────────────────────────────────────┘
cmd/recon/get.go           returns to runRoles
internal/ui                  └─► PrintBanner / PrintField / PrintInfo  ── display ──►  terminal / LLM
```

The command layer owns the timeout (`reconTimeout`), the connection, and the
output; the logic layer owns the API call and the parsing.

## How every recon command connects

All subcommands share one helper in `cmd/recon/recon.go`:

```go
client, cfg, err := connect()   // load the saved engagement + open a live client
```

`connect()` loads the engagement saved by `chaosify init` (`config.LoadRequired`)
and builds a Kubernetes clientset from whichever connection it recorded
(kubeconfig context, or manual endpoint). Every probe runs as that same identity,
inside a `reconTimeout` (30s) context.

## The two shapes of recon command

- **A single object** — `recon get <object>`. One file, one API list call, one
  parse. `get roles` and `get namespaces` are the wired examples; the rest are
  stubbed with `notImplemented` but already enforce their argument shape
  (namespaced objects require a `<namespace>`, cluster-scoped take none).
- **A derived view** — `recon get permissions`. Walks the engagement's in-scope
  namespaces and, for each, asks the API server what the caller can do
  (`SelfSubjectRulesReview`, i.e. `kubectl auth can-i --list`), then prints per
  namespace.

## What "parse" means in practice

The logic functions deliberately return **plain values**, not Kubernetes structs:

- `ListRoles` → `map[string][]string` (role name → `"verb resource"` lines)
- `ListNamespaces` → `[]string` (sorted names)
- `ListPermissions` → `[]string` (sorted `"verb resource.group"` lines)
- `WhoAmI` → `string` (`"user (groups: ...)"`)

The raw API objects (`*v1.RoleList`, `PolicyRule`, ...) are unwrapped here so
nothing downstream has to know the Kubernetes type system — the LLM sees clean
lines, not `&RoleList{Items:[]Role{...}}`.

## Adding a new recon probe

1. Write the logic in `internal/recon/<thing>.go`: take a `ctx` + `*kubernetes.Clientset`,
   call the API, return plain Go values. Wrap errors with context.
2. Wire the command in `cmd/recon/`: add it via `namespacedGet`/`clusterGet` (for
   `get`) or a new `newXCmd()`, call your logic through `connect()`, and print with
   `internal/ui`.

Retrieve, parse, display — same three steps every time.
