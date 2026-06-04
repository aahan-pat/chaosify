# Scenario Library

Chaosify scenarios are deterministic test cases that submit a known workload or command to a live cluster and verify the outcome against an expected result. Every scenario produces a structured JSON evidence artifact.

## Packs

| Pack ID | Category | Scenarios |
|---|---|---|
| `preventive-baseline` | Admission control | 7 |
| `runtime-baseline` | Runtime detection | 1 |

```bash
# List all scenarios in a pack
chaosify scenarios list --pack preventive-baseline

# Inspect a single scenario
chaosify scenarios show deny-privileged-container

# Run a full pack
chaosify probe run --pack preventive-baseline --context <ctx> --output result.json

# Run a single scenario
chaosify probe run --scenario deny-privileged-container --context <ctx>
```

## Result vocabulary

| Result | Meaning |
|---|---|
| `PASS` | Cluster behaved as expected — the control is working |
| `FAIL` | Cluster did not behave as expected — the control is broken or absent |
| `ERROR` | Scenario could not complete — not a verdict on the control |
| `SKIPPED` | Prerequisite missing (e.g. no policy engine installed) |

`FAIL` and `ERROR` are distinct. A `FAIL` means the cluster admitted or executed something it should have blocked. An `ERROR` means the scenario itself could not run.

---

## Pack: `preventive-baseline`

Tests whether admission controls reject known dangerous workload configurations. Each scenario submits a pod manifest and expects the cluster to reject it at admission. A `FAIL` means the workload was admitted — the policy is absent, misconfigured, or in Audit mode.

**Prerequisites:** A policy engine (Kyverno, OPA/Gatekeeper) or Pod Security Admission must be configured on the cluster. Without one, all scenarios in this pack will return `SKIPPED`.

---

### `deny-privileged-container`

**Control objective:** Prevent privileged workloads

**What it submits:** A pod with `securityContext.privileged: true`.

**FAIL means:** The cluster admitted a privileged container. A privileged container has unrestricted access to the host kernel and devices — equivalent to running as root on the node.

**Common causes:**
- Policy is in Audit mode rather than Enforce
- Policy scope excludes the test namespace
- No policy engine is installed

**Remediation:** Verify the policy covering `securityContext.privileged: true` is in Enforce mode, not Audit.

---

### `deny-unapproved-registry`

**Control objective:** Restrict disallowed image registries

**What it submits:** A pod pulling from `docker.io/unapproved-vendor/app:1.0.0`.

**FAIL means:** The cluster admitted a workload from an unapproved registry. Without registry restrictions, any image — including malicious ones — can be pulled and run.

**Common causes:**
- Allowlist does not cover all registries in use
- Policy does not apply to init containers
- Policy is namespace-scoped and misses the test namespace

**Remediation:** Verify the registry allowlist covers all image pull paths including init containers.

---

### `deny-hostpath`

**Control objective:** Prevent hostPath volume usage

**What it submits:** A pod mounting `/etc` from the host via a `hostPath` volume.

**FAIL means:** The cluster admitted a pod with direct host filesystem access. A hostPath mount gives a container read (and potentially write) access to host directories, enabling credential theft and persistence.

**Common causes:**
- Policy covers `Deployment` resources but not bare `Pod` resources
- Policy is in Audit mode
- No policy engine is installed

**Remediation:** Verify the policy covers bare `Pod` resources, not just `Deployment`.

---

### `deny-forbidden-capabilities`

**Control objective:** Restrict dangerous Linux capabilities

**What it submits:** A pod requesting `NET_ADMIN` via `securityContext.capabilities.add`.

**FAIL means:** The cluster admitted a pod with an elevated Linux capability. Dangerous capabilities such as `NET_ADMIN` and `SYS_ADMIN` allow network manipulation and kernel-level operations from within a container.

**Common causes:**
- Capability blocklist is incomplete
- Policy does not cover the specific capability being tested
- Policy is in Audit mode

**Remediation:** Verify the capability blocklist includes both `NET_RAW` and `SYS_ADMIN` in addition to `NET_ADMIN`.

---

### `deny-latest-tag`

**Control objective:** Prevent mutable image tags

**What it submits:** A pod using `busybox:latest`.

**FAIL means:** The cluster admitted a workload with a mutable image tag. The `:latest` tag resolves to a different image over time, making deployments non-reproducible and supply chain verification impossible.

**Common causes:**
- Policy is namespace-scoped and does not cover the test namespace
- Policy does not apply to all containers (e.g. skips init containers)
- Policy is in Audit mode

**Remediation:** Verify enforcement applies to all containers and is not scoped to a specific namespace.

---

### `deny-privilege-escalation`

**Control objective:** Prevent container privilege escalation

**What it submits:** A pod with `allowPrivilegeEscalation: true` and `runAsUser: 0`.

**FAIL means:** The cluster admitted a container that can gain additional privileges beyond its parent process. This is a common escalation path — a process running as an unprivileged user can use `setuid` binaries or kernel exploits to become root.

**Common causes:**
- Policy sets `allowPrivilegeEscalation: false` as a default but does not enforce it at admission
- PSA `restricted` profile is not applied to the namespace
- Policy is in Audit mode

**Remediation:** Confirm `allowPrivilegeEscalation: false` is enforced at admission, not just set as a default.

---

### `deny-host-network`

**Control objective:** Prevent host network namespace access

**What it submits:** A pod with `hostNetwork: true`.

**FAIL means:** The cluster admitted a pod sharing the host's network namespace. A pod with `hostNetwork: true` can bind to host ports, intercept node-level traffic, and access services not exposed through Kubernetes networking.

**Common causes:**
- Policy covers `Deployment` resources but not bare `Pod` resources
- Policy is in Audit mode
- No policy engine is installed

**Remediation:** Verify the policy covers `hostNetwork: true` on bare Pods, not just Deployments.

---

## Pack: `runtime-baseline`

Tests whether runtime security tools detect known threat techniques. Each scenario executes a command inside a running pod and polls the configured alert source for a correlated alert. A `FAIL` means the command executed but no alert was observed — the detection layer is absent or misconfigured.

**Prerequisites:** A runtime security tool (Falco, Tetragon, or KubeArmor) must be running on the cluster. Use `--alert-source <tool>` to specify which tool to poll. Use `--alert-source none` for pipeline testing without a live tool.

```bash
chaosify probe run --pack runtime-baseline --alert-source falco --context <ctx>
```

---

### `detect-read-sensitive-file`

**Control objective:** Runtime detection of sensitive file reads

**What it does:** Spawns a pod and runs `cat /etc/shadow` inside it. Polls the configured runtime tool for a correlated alert.

**PASS means:** The runtime tool fired an alert for the sensitive file access within the observation window.

**FAIL means:** The command executed and no alert was observed. The runtime tool is either absent, not configured to monitor sensitive file reads, or the rule is disabled.

**Compatible alert sources:** Falco (`Read sensitive file untrusted` rule), Tetragon, KubeArmor

**Remediation:** Verify the runtime tool's sensitive file read rule is enabled and in enforce/alert mode, not audit-only.
