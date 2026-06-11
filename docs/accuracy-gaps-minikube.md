# Accuracy & Gap Analysis — Chaosify Minikube Pentest

Independent verification of the Chaosify-driven pentest for cluster context `minikube`,
performed **without** the Chaosify CLI.

- **Tooling used:** `kubectl` v1.36.1 (server v1.35.1), server-side dry-run admission
  (`kubectl --dry-run=server`, which executes the real Kyverno webhooks), and
  `kubectl auth can-i --as=<SA>` for RBAC.
- **Run cross-checked:** `.chaosify/runs/2026-06-11T00-23-00Z/`
- **Verification date:** 2026-06-11

**Bottom line:** Chaosify's per-probe verdicts were accurate *where the tool actually
probed*, but both Chaosify's recon summary and the agent report reached **two wrong
conclusions** and **missed three findings** — including a node-escape chain rooted in a
Critical cluster-admin ServiceAccount. The root cause is structural: Chaosify only submits
workloads to the `chaosify-tests` namespace, so it never sees that `kube-system` is exempt
from every admission policy, and its RBAC recon did not surface a ServiceAccount-subject
`cluster-admin` binding.

---

## 1. Verified accurate

| Finding | Independent verification |
|---|---|
| 6 Kyverno ClusterPolicies, all `Enforce` | `kubectl get clusterpolicy` → all 6 `validationFailureAction: Enforce`. ✓ |
| No image registry / tag policy exists | Rule dump shows only host-ns, hostpath, privesc, privileged, root-user, capabilities — no image rule. ✓ |
| `deny-latest-tag` admitted | `kubectl run --image=busybox:latest --dry-run=server` → `created (server dry run)`. ✓ |
| `deny-unapproved-registry` admitted | dry-run of `quay.io/unapproved-vendor/app:1.0.0` (non-root) → `created`. ✓ |
| Privileged / hostPath / host-ns / caps / privesc rejected **in chaosify-tests** | dry-run each → `admission webhook "validate.kyverno.svc-fail" denied`. ✓ |
| initContainer privileged bypass blocked | Policy pattern covers `initContainers[*]`; dry-run rejected. ✓ |
| No NetworkPolicies in any namespace | `kubectl get netpol -A` → `No resources found`. ✓ |
| Egress open (exfil path) | matches probe `net-egress.json` (1.1.1.1:53 reachable); no NetworkPolicy exists to stop it. ✓ |
| No runtime detection agents | `kubectl get ds -A` → only `kube-system/kube-proxy`; no falco/tetragon/kubearmor/tracee pods. ✓ |
| Node facts | Debian 12, kernel `7.0.11-arch1-1`, `docker://29.2.1`, kubelet `v1.35.1`. ✓ |
| RBAC counts | 86 ClusterRoles / 65 ClusterRoleBindings — matches recon. ✓ |
| `chaosify-tests:default` SA denied secrets/pods | `kubectl auth can-i` → `no` for list secrets (kube-system) and create pods (default). ✓ |
| Two `failurePolicy: Ignore` webhooks are cleanup/monitor only | `kyverno-ttl-...` (`kyverno-cleanup-controller.kyverno.svc`) and `monitor-webhooks.kyverno.svc` are Ignore; the enforcing webhook `validate.kyverno.svc-fail` is `Fail` (fail-closed). ✓ |
| SA token mountable/readable | consistent with `exec-token.json`. ✓ |
| Kyverno returns HTTP 400 on denial → Chaosify records `ERROR` | Reproduced: dry-run denials are real rejections; the 5 pack "ERROR" rows are controls *working*. ✓ |

---

## 2. Wrong / misleading conclusions

### 2.1 ❌ "Every node-escape and privilege-escalation vector was blocked" — FALSE outside chaosify-tests
All 6 ClusterPolicies **exclude four namespaces** on every rule:

```
excludes = [kube-node-lease, kube-public, kube-system, kyverno]
```

Proof (server dry-run, real admission):
```
privileged + hostPID + hostPath:/  in kube-system     -> pod/dr-escape created (server dry run)   # ADMITTED
same pod                            in chaosify-tests  -> denied by validate.kyverno.svc-fail       # REJECTED
```
A full host-takeover pod (privileged + `hostPath: /` + `hostPID`) is **admitted in
`kube-system`**. The agent report generalized the `chaosify-tests` PASS results to the
whole cluster. Chaosify could not have caught this — it only ever submits to
`chaosify-tests`.

### 2.2 ❌ `disallow-root-user` gives false assurance — does NOT prevent running as root
The rule uses Kyverno conditional anchors:
```yaml
pattern:
  spec:
    containers:
      - =(securityContext):
          =(runAsUser): ">0"
```
`=(...)` means "validate only **if present**." A pod that simply **omits** `runAsUser`
runs as the image's default user (root/uid 0 for busybox) and is admitted:
```
busybox:1.36, no securityContext    -> pod/dr-root created (server dry run)   # ADMITTED, runs as root
busybox:1.36, runAsUser: 0 explicit -> denied                                 # REJECTED
```
So the policy blocks the *declaration* `runAsUser: 0` but not actual root execution; it
never sets/requires `runAsNonRoot: true`. Neither Chaosify (no root-by-default scenario in
its `deny-*` set) nor the agent report flagged this. Chaosify's own `deny-latest-tag` /
`deny-unapproved-registry` test pods had no securityContext and therefore ran as root —
admitted.

### 2.3 ⚠️ "RBAC is tight / no privilege-escalation path" — incomplete
The report tested only `chaosify-tests:default` and concluded RBAC was locked down. A
genuinely privileged ServiceAccount in another namespace was never tested (see 3.1).

---

## 3. Missed findings

### 3.1 🔴 CRITICAL — `kube-system:default` ServiceAccount is bound to `cluster-admin`
ClusterRoleBinding `minikube-rbac` (a well-known minikube default) binds:
```
roleRef:  ClusterRole/cluster-admin
subject:  ServiceAccount  kube-system/default
```
Verified:
```
kube-system:default  can-i '*' '*'                       -> yes
kube-system:default  can-i list secrets   -n kube-system -> yes
kube-system:default  can-i create pods    -n kube-system -> yes
kube-system:default  can-i create daemonsets -n kube-system -> yes
```
Chaosify's `recon rbac` reported only the `kubeadm:cluster-admins` **Group** binding
(`HIGH`) and did **not** surface this **ServiceAccount** binding — the more dangerous of
the two, because a SA token is reachable by any pod scheduled with that SA. The agent
report inherited the miss by probing the wrong SA.

### 3.2 🔴 HIGH/Critical — Node-takeover chain (combines 3.1 + 2.1)
Because `kube-system` is exempt from all admission policies **and** its `default` SA has
cluster-admin:
```
launch/compromise any pod in kube-system using the default SA
  → obtain cluster-admin token
  → create privileged pod (hostPath:/, hostPID, privileged) in kube-system  (admitted, see 2.1)
  → chroot / nsenter to host root  → full node takeover
```
A real, end-to-end privilege-escalation-to-node-escape path. Neither report identified it.

### 3.3 🟠 MEDIUM — `disallow-root-user` root-by-default bypass
See 2.2. Recorded here as a discrete missed finding: containers run as root cluster-wide
(outside the 4 exempt namespaces) merely by omitting `runAsUser`.

### 3.4 🟡 LOW — `host-ports` sub-rule not surfaced
`disallow-host-namespaces` contains a second rule, `host-ports`, that Chaosify's recon did
not mention (it reported policies but not per-rule coverage). Not exercised by any probe.

### 3.5 🟡 LOW — System namespaces also lack PSA labels
Chaosify's PSA recon reported only the *user* namespaces as unlabeled. Ground truth:
**every** namespace — including `kube-system`, `kube-public`, `kube-node-lease` — has no
`pod-security.kubernetes.io/*` labels. Chaosify scoped the finding to non-system
namespaces; the system namespaces are equally unlabeled and (per 2.1) also unprotected by
Kyverno.

---

## 4. Not independently verifiable with kubectl

| Chaosify claim | Status |
|---|---|
| `appArmorEnabled: false` | Not verifiable via kubectl alone — derived from node inspection. Needs node/kubelet access; **left unconfirmed** (kernel `7.0.11-arch1-1` is the host's Arch kernel via the minikube docker driver, so AppArmor-disabled is plausible but unproven here). |
| `seccompDefault: runtime/default` | Same — would require reading the kubelet config on the node. **Unconfirmed.** |

---

## 5. Root causes (why the gaps exist)

1. **Namespace-scoped probing.** Chaosify submits all workloads to `chaosify-tests`, so it
   is structurally blind to per-namespace policy `exclude` blocks. The most security-
   relevant namespace (`kube-system`) is never tested, yet it is exempt from every policy.
2. **RBAC recon under-reports.** It flagged a Group→cluster-admin binding but not a
   ServiceAccount→cluster-admin binding. ServiceAccount bindings are the higher-risk class
   and should be enumerated explicitly.
3. **Operator-chosen identity probe.** `probe identity` tests whichever SA the operator
   names; the natural default (`chaosify-tests:default`) misses privileged SAs elsewhere.
   Recon should hand the operator the list of cluster-admin subjects to probe.
4. **No root-by-default scenario.** The `preventive-baseline` pack tests explicit
   `runAsUser: 0` but not the common "omit `runAsUser`, run as image root" case, so a real
   gap in `disallow-root-user` went unseen.
5. **Kyverno 400 vs 403.** Already known: genuine denials are recorded as `ERROR`. Verified
   the controls do block; the verdict mapping is cosmetic but can mislead an operator who
   trusts the status field over the `rawResponse`.

---

## 6. Corrected posture

The cluster is **weaker than reported**. Admission control is strong *only in non-exempt
namespaces*. The combination of (a) a cluster-admin `kube-system:default` SA, (b) full
admission-policy exemption for `kube-system`, (c) no runtime detection, and (d) open egress
constitutes a confirmed **node-takeover + undetected-exfiltration** chain. Corrected overall
posture: **Critical** (was reported High).

**Top corrected remediations (priority order):**
1. Remove/replace the `minikube-rbac` cluster-admin binding on `kube-system:default`; set
   `automountServiceAccountToken: false` on the default SA.
2. Reconsider the blanket `kube-system`/`kyverno` policy exemptions, or compensate with
   tight RBAC on who can create pods there.
3. Change `disallow-root-user` to enforce `runAsNonRoot: true` (not just `runAsUser > 0`).
4. Add a Kyverno image-registry allowlist + digest/tag policy (covers 2 confirmed gaps).
5. Default-deny NetworkPolicies with explicit egress allowlists.
6. Install a runtime detection agent (Falco/Tetragon).
