# Feature Spec: `--format summary` for recon commands

Status: Implemented
Affects: `chaosify recon <webhooks|policies|psa|rbac|nodes|network-policies|runtime-agents|topology>`
Related code: `src/cli/recon-summary.ts` (builder), `src/cli/commands/recon/*.ts`,
`src/cli/commands/recon/utils/shared.ts` (`writeTextToFile`), `src/core/recon/rbac.ts` (§6 dedup), `src/types/recon.ts`

Decisions made during implementation (supersede the open questions in §10):
- **Output shape: TSV** (header row once, tab-delimited, unpadded). NDJSON deferred.
- **Builder lives in its own pure module** `src/cli/recon-summary.ts` (`buildReconSummary(result) → string`),
  not in the chalk-based `output.ts`, so it is unit-testable without console mocking.
- **Inventory-row tools:** `policies`, `webhooks`, and `runtime-agents` emit one row per
  inventory item (so working controls show too), with severity/exploit columns filled in
  from the matching finding. `rbac`, `network-policies`, `psa` emit one row per threat finding.

## 1. Problem

Recon output is the largest token sink when an AI agent (or any consumer) reads
results back. The `--output <file>` / `--format json` paths serialize the **full**
`result` object — both the top-level `findings[]` and the entire `data` threat
graph — pretty-printed. Two structural issues dominate the byte count:

1. **Intra-record duplication.** `data.findings[].dangerousPermissions` repeats
   identical permission blocks. In a real run, `recon rbac` emitted a pod whose
   `dangerousPermissions` array held the **same two blocks (pods, secrets/configmaps)
   four times each — 8 entries, ~150 lines, for ~2 lines of distinct content.**
2. **Cross-record / cross-field duplication.** The same narrative sentence is
   stored twice per finding — once in top-level `findings[].detail` and again in
   `data.findings[].attackChain` (rbac) or `.impact` (psa, network-policies). In
   `recon network-policies` the identical `impact` paragraph appeared **8 times**
   (4 findings × 2 locations).

Measured impact: `recon-rbac.json` was **475 lines**; the decision-relevant
content fits in **~6**. `recon-netpol.json` was 96 lines carrying one unique
`impact` string.

The redundancy is a property of the producer, so the fix belongs in the producer
— not in per-consumer `jq` filters that must be re-derived (and re-debugged) on
every run.

## 2. Goals / Non-goals

**Goals**
- A third output mode, `--format summary`, emitting one compact record per
  vector with only the fields a consumer acts on.
- An unconditional dedup fix at the source (see §6) that benefits `table` and
  `json` too.
- Lossless drill-down: `json` remains the full artifact; `summary` never
  silently drops an *actionable* field (`suggestedProbe`, `dangerousPermissions`,
  `blindSpots`).

**Non-goals**
- Changing the JSON schema of `--format json` (back-compat; see §7).
- Summarizing evidence artifacts from `probe`/`verify` (recon only, for now).
- Replacing `table` (human-facing, coloured) — `summary` is machine-facing,
  parse-stable, and uncoloured.

## 3. CLI surface

Extend the existing option on every recon subcommand:

```
--format <mode>    Output mode: table, json, summary   (default: table)
```

`--output <path>` gains a companion behavior: when `--format summary` is set,
`--output` writes the summary artifact (newline-delimited, see §4) instead of the
full JSON. Full JSON to a file remains available via `--format json --output`.

No new flags beyond the added enum value. Optional follow-up (§8): `--top <N>`.

## 4. Output format

`summary` emits **TSV** (tab-delimited, unpadded). Structure per tool:
- a `# tool=… status=… <scan metadata>` header line;
- one column-header row (no `#`), then one tab-delimited data row per finding/
  inventory item, sorted by severity (CRITICAL → HIGH → WARN → INFO);
- trailing `# note:` / `# finding:` / `# blindSpot:` comment lines.

Lines beginning with `#` are metadata; every other line splits cleanly on `\t`
into the same number of cells as the header. A table amortizes field names into
one header row instead of repeating JSON keys per object; tabs never appear in
values, so no quoting/escaping is needed. Nested arrays are flattened to
sub-delimited strings (`a,b,c`) — the full typed structure stays one
`--format json` away.

Transformations applied, in order:

1. **Dedup arrays (lossless).** Collapse `dangerousPermissions` to unique
   `(apiGroups, resources, verbs)` tuples.
2. **Drop the doubled narrative (lossless).** Keep `exploitClasses`; drop the
   prose `attackChain` / `impact` / `detail` from per-row output (it is fully
   recoverable from `--format json`).
3. **Hoist identical strings to a legend.** If every finding shares a verbatim
   `impact`/`detail`, print it once under a `note:` line rather than per row.
4. **Compact nested perms.** Render `resources` × `verbs` as
   `secrets,configmaps:get,list,watch`.
5. **Drop non-actionable scan metadata** from rows; keep one header line
   (`podsScanned`, `policiesScanned`, etc.).
6. **Keep verbatim:** `severity`, entry point (`pod/namespace`),
   `exploitClasses`, `suggestedProbe`, `confirmed` (psa), and the full
   `blindSpots` block.

### Per-tool keep-list

| Tool | Per-row columns | Footer |
|------|-----------------|--------|
| rbac | severity, pod/ns, serviceAccount, exploitClasses, dedup'd perms | blindSpots |
| network-policies | severity, pod/ns, exploitClasses, egress/ingress, suggestedProbe | note (shared impact), blindSpots |
| psa | severity, pod/ns, enforceLevel, observedTraits, confirmed | blindSpots |
| policies | severity, policy, engine, mode (`Enforce`/`Audit`), exploitClasses | blindSpots |
| webhooks | severity, webhook, type, scope, failurePolicy | blindSpots |
| runtime-agents | severity, agent, detected, readyNodes/desiredNodes, exploitClasses | blindSpots |
| nodes | name, os, kernel, runtime, appArmorEnabled, seccompDefault | — |
| topology | (status line only when `skip`) | — |

## 5. Worked example — `recon rbac`

**Before** (`--format json`, 475 lines; one pod's `dangerousPermissions` = 8
repeated blocks, `findings[].detail` == `data.findings[].attackChain`).

**After** (`--format summary`):

```
rbac  podsScanned=10  tokensHarvested=3
SEV       ENTRYPOINT                  SA             EXPLOITS                        PERMS
CRITICAL  victim-pod-c/pentest-lab-b  privileged-sa  priv-esc,lateral,secret        pods,pods/exec,pods/log:get,list,watch,create,delete; secrets,configmaps:get,list,watch
CRITICAL  attacker-pod/pentest-lab    privileged-sa  priv-esc,lateral,secret        pods,pods/exec,pods/log:get,list,watch,create,delete; secrets,configmaps:get,list,watch
HIGH      falco-vkfxt/falco           falco          secret                         nodes,namespaces,pods,services,configmaps:get,list,watch
blindSpots:
  - kyverno tokens unreadable in 4 controller pods (default + 1 projected path)
  - roles not bound to a running pod / without a long-lived token secret are out of scope
```

Every field used to plan an attack — entry pod, SA, exploit classes, dangerous
verbs, blind spots — is preserved; the 8× permission repetition, the doubled
`attackChain` prose, and the JSON scaffolding are gone.

## 6. Source dedup fix (ships independently of the format)

`data.findings[].dangerousPermissions` should be deduplicated where it is built
in `src/core/recon/rbac.ts`, before it reaches any renderer. This is a defect
fix, not a presentation choice: it shrinks `table`, `json`, and `summary`
alike with **zero** information loss. Land this first; it removes the largest
single contributor regardless of whether `summary` is adopted.

## 7. Backward compatibility

- `--format json` byte-for-byte unchanged (post-§6 dedup excepted — that is a
  correctness fix and should be noted in CHANGELOG).
- `--format table` unchanged.
- Default remains `table`. `summary` is strictly additive.
- `validate-opts` (the `--format` validator) accepts the new enum value;
  unknown modes still error as today.

## 8. Implementation notes

- Add a `renderSummary(result)` helper in `src/cli/output.ts` alongside the
  existing `renderFindings`, dispatched per tool by a small keep-list map (§4).
  No coloured output (`summary` is for machine/file consumption).
- Each recon command's `.action()` gains one branch mirroring the existing
  `if (opts.format === 'json')` block:
  ```ts
  if (opts.format === 'summary') { renderSummary(result); process.exit(0) }
  ```
- When `--output` + `summary`, write the same text the renderer prints (capture
  the string rather than `console.log` directly, or refactor `renderSummary` to
  return a string the command both prints and persists).
- Severity ordering: reuse the existing severity ranking; stable-sort findings.

## 9. Testing

- Unit: `renderSummary` golden-file tests per tool using the fixtures already in
  `test/` (assert dedup, legend hoisting, column stability, severity order).
- Regression: assert `--format json` output is unchanged except for §6 dedup.
- Byte-budget guard: assert summary of the rbac fixture is < N lines / < M bytes
  so future schema growth can't silently reinflate it.

## 10. Open questions

- ~~NDJSON vs columnar?~~ **Resolved: TSV.** NDJSON repeats keys per row — the
  exact overhead this feature removes — and our primary consumer is an LLM
  context window, not a typed parser. A `--format ndjson` can be added later if a
  structured/pipeline consumer appears; the builder already produces a clean row
  model that would map to it.
- `--top <N>` to cap low-severity tail — **deferred** until there's a noisy
  real-world case; the per-tool finding counts are currently small.
- Should `topology` (currently `skip` on most clusters) emit anything beyond its
  status line in summary mode? **Resolved: no** — the non-ok path emits only
  `# tool=topology status=skip` plus any finding titles.
