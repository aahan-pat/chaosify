# Contributing to Chaosify

Thanks for your interest. Contributions of all kinds are welcome — new scenarios, bug fixes, documentation improvements, and core enhancements.

## Table of contents

- [Development setup](#development-setup)
- [Running checks locally](#running-checks-locally)
- [Adding a scenario](#adding-a-scenario)
- [Project structure](#project-structure)
- [Pull request checklist](#pull-request-checklist)
- [Reporting bugs](#reporting-bugs)

---

## Development setup

Requirements: **Node.js ≥ 22.16.0** and npm.

```bash
git clone https://github.com/aahan-pat/chaosify.git
cd chaosify
npm ci
```

To run the CLI locally without building:

```bash
npm run dev -- --help
```

---

## Running checks locally

Run these before opening a PR — CI will block on any failure.

```bash
npm run typecheck   # TypeScript type check (no emit)
npm run lint        # oxlint
npm run test        # vitest (unit tests)
npm run build       # tsdown bundle
```

---

## Adding a scenario

Scenarios are the most common contribution. Each scenario is a single YAML file in `src/scenarios/<pack-id>/`.

### 1. Choose or create a pack

Existing packs:

| Pack | Path | Category |
|------|------|----------|
| `preventive-baseline` | `src/scenarios/preventive-baseline/` | Admission control |
| `runtime-baseline` | `src/scenarios/runtime-baseline/` | Runtime detection |

If your scenario doesn't fit an existing pack, open an issue first to propose a new one.

### 2. Write the YAML

Use `deny-privileged-container.yaml` as a reference for preventive scenarios and `read-sensitive-file.yaml` for detective scenarios.

**Preventive scenario (admission control):**

```yaml
id: deny-your-scenario          # kebab-case, unique across all packs
version: 1
name: Human-readable name
description: One sentence — what this scenario attempts and what the cluster should do.
category: preventive
controlObjective: Short control objective (e.g. "Prevent host network access")
prerequisites:
  - name: can_create_pods
    description: Permission to create pods in the test namespace
  - name: admission_policy
    description: Admission policy that covers <the specific field being tested>
manifest:                       # The pod spec submitted to the cluster
  apiVersion: v1
  kind: Pod
  metadata:
    name: chaosify-<your-scenario-name>-test
  spec:
    containers:
      - name: test
        image: busybox:1.36
        # ... the dangerous configuration being tested
expectedOutcome:
  type: admission_rejected      # cluster should deny at admission
cleanup:
  deleteCreatedResources: true
safety:
  level: low
  namespaceScoped: true
```

**Detective scenario (runtime detection):**

```yaml
id: detect-your-scenario
version: 1
name: Human-readable name
description: One sentence — what action is taken and what the runtime tool should detect.
category: detective
controlObjective: Short control objective
prerequisites:
  - name: Runtime tool installed
    description: Falco, Tetragon, or KubeArmor must be configured to alert on <the specific behavior>.
manifest:
  apiVersion: v1
  kind: Pod
  metadata:
    generateName: chaosify-runtime-
  spec:
    restartPolicy: Never
    containers:
      - name: probe
        image: busybox:1.36
        command: [sh, -c, sleep 3600]
execStep:
  container: probe
  command: [<command>, <that>, <triggers>, <the>, <detection>]
  timeoutMs: 5000
expectedOutcome:
  type: alert_fired
cleanup:
  deleteCreatedResources: true
safety:
  level: low
  namespaceScoped: true
```

### 3. Update the scenario docs

Add your scenario to `docs/scenarios.md` following the same format as the existing entries — control objective, what it submits, what FAIL means, common causes, and remediation.

### 4. Test it

Scenarios are declarative, but you should verify yours runs against a real cluster (minikube, kind, or a cloud cluster) before submitting:

```bash
chaosify probe run --scenario <your-scenario-id> --context <your-context>
```

---

## Project structure

```
src/
  cli/          # Command definitions and registry
  core/         # Executor, validator, evidence builder, cleanup
  scenarios/    # Scenario YAML files
  types/        # TypeScript interfaces (evidence, scenario, recon)
  constants.ts  # All tunable values (timeouts, namespace names, etc.)
test/
  unit/         # Unit tests (vitest)
  safeguards/   # Fixture YAMLs for safety tests
docs/           # Architecture, reference, scenario library
```

All execution is scoped to the `chaosify-tests` namespace. Scenarios structurally cannot touch any other namespace.

---

## Pull request checklist

- [ ] `npm run typecheck`, `lint`, `test`, and `build` all pass locally
- [ ] New scenario: YAML added to `src/scenarios/<pack>/` and entry added to `docs/scenarios.md`
- [ ] New feature or bug fix: relevant unit tests added or updated
- [ ] PR description explains what the change does and why

---

## Reporting bugs

Open a [GitHub issue](https://github.com/aahan-pat/chaosify/issues) with:

- Chaosify version (`chaosify --version`)
- Kubernetes version and distribution
- The command you ran
- Full output (with `--output` JSON if relevant)

For security vulnerabilities, see [SECURITY.md](SECURITY.md).
