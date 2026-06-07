---
name: codex
description: Kubernetes security reference — maps attack techniques to MITRE ATT&CK, CIS Benchmark controls, and Chaosify scenarios. Use when the user asks how an exploit works, what a security concept means, how to defend against a technique, or how to map a finding to a framework.
metadata:
  requires: []
---

TRIGGER when: the user asks what a Kubernetes security concept means, how a specific attack or exploit works, which MITRE ATT&CK technique maps to a scenario, what a CIS Benchmark control covers, how to defend against a specific technique, what the risk of a misconfiguration is, or uses phrases like "explain how X works", "what does Y mean", "is Z secure", "what's the risk of", "map this to MITRE", "what framework covers this".

SKIP: requests to actively test or pentest a cluster — use the `chaosify` or `agentic-pentest` skills for those. Skip general Kubernetes operational questions unrelated to security.

---

# Chaosify Codex — Kubernetes Security Reference

This skill is a knowledge reference. It does not run any commands or touch any cluster. Use it to understand the *why* behind what Chaosify tests, and to map findings to industry frameworks.

---

## Attack Surface Layers

Kubernetes security is organized into five layers. Every Chaosify primitive maps to one or more of these.

| Layer | What it controls | Chaosify primitive |
|---|---|---|
| **Admission** | What workloads can be scheduled | `probe run --manifest` |
| **Runtime** | What a running container can do | `probe exec`, `probe detect` |
| **Network** | What a pod can reach | `probe network` |
| **Identity** | What a service account can do | `probe identity` |
| **Node** | What escapes the container boundary | `probe exec` with escape commands |

A gap at any layer can be compensated by a control at another. The goal of a Chaosify assessment is to find layers with no compensating control.

---

## MITRE ATT&CK for Containers — Technique Mapping

| MITRE Technique | ID | What it describes | Chaosify scenario / command |
|---|---|---|---|
| Deploy Container | T1610 | Attacker deploys a malicious container | `probe run --manifest` with `privileged: true` |
| Container Escape to Host | T1611 | Breakout via `hostPID`, `hostPath`, or kernel exploit | `probe exec --run "nsenter --mount=/proc/1/ns/mnt -- ls /"` |
| Steal Application Access Token | T1528 | Read mounted SA token inside pod | `probe exec --run "cat /var/run/secrets/.../token"` |
| Unsecured Credentials in Files | T1552.001 | Read secrets from mounted hostPath | `probe exec --run "ls /host/etc/kubernetes/pki"` |
| Valid Accounts: Cloud Accounts | T1078.004 | Access cloud IMDS to steal credentials | `probe network --target http://169.254.169.254/latest/meta-data/` |
| Network Service Scanning | T1046 | Scan for reachable services from inside pod | `probe network --target <host:port>` |
| Container Administration Command | T1609 | Exec into running container | `probe exec --expect denied` (RBAC test) |
| Ingress Tool Transfer | T1105 | Write executable to `/tmp` and run it | `probe detect --run "wget -O /tmp/x ... && chmod +x /tmp/x && /tmp/x"` |
| Abuse Elevation Control Mechanism | T1548 | `allowPrivilegeEscalation: true` | `deny-privilege-escalation` scenario |
| Escape to Host via Privileged Container | T1611 | `privileged: true` | `deny-privileged-container` scenario |

---

## CIS Kubernetes Benchmark — Key Controls

| CIS Control | What it requires | Related Chaosify recon |
|---|---|---|
| 5.2.1 | Do not admit privileged containers | `recon policies` / `deny-privileged-container` |
| 5.2.2 | Do not admit containers wanting to share the host process ID | `deny-host-network` (hostPID variant) |
| 5.2.3 | Do not admit containers wanting to share the host IPC | admission gap — no built-in scenario yet |
| 5.2.4 | Do not admit containers wanting to share the host network namespace | `deny-host-network` |
| 5.2.5 | Do not admit containers with `allowPrivilegeEscalation` | `deny-privilege-escalation` |
| 5.2.6 | Do not admit root containers | `deny-privilege-escalation` (runAsUser: 0) |
| 5.2.7 | Do not admit containers with dangerous capabilities | `deny-forbidden-capabilities` |
| 5.2.8 | Do not admit containers with hostPath volumes | `deny-hostpath` |
| 5.3.2 | Ensure all namespaces have NetworkPolicies | `recon network-policies` |
| 5.4.1 | Prefer using secrets as files over env vars | `recon rbac` |
| 5.4.2 | Consider external secret storage | defense guidance only |
| 5.7.1 | Create administrative boundaries between resources | `probe identity` |
| 5.7.3 | Apply SecurityContext to pods and containers | `recon psa` |
| 5.7.4 | Do not use default namespace | `recon rbac` |

---

## Attack Field Reference

Every field below is a potential exploit vector when left unrestricted.

| Field | Risk | What an attacker does with it |
|---|---|---|
| `privileged: true` | Critical | Full host kernel capabilities, all devices, escape to host |
| `hostPID: true` | Critical | Read all host process memory, attach debugger to any process |
| `hostNetwork: true` | Critical | Bypass NetworkPolicy, reach cloud metadata, node services |
| `hostIPC: true` | High | Attach to host shared memory, read inter-process secrets |
| `hostPath: /` | Critical | Read/write host filesystem including PKI, SSH keys, kubelet certs |
| `hostPath: /var/run/docker.sock` | Critical | Full container escape via Docker socket |
| `capabilities.add: [NET_ADMIN]` | High | Modify network interfaces, ARP spoofing, packet capture |
| `capabilities.add: [SYS_PTRACE]` | High | Attach to host processes with `hostPID`, read memory |
| `capabilities.add: [SYS_ADMIN]` | Critical | Mount filesystems, load kernel modules, escape cgroups |
| `capabilities.add: [NET_RAW]` | High | Raw socket access, packet crafting |
| `allowPrivilegeEscalation: true` | High | `sudo`/`setuid` inside container |
| `runAsUser: 0` | High | Runs as root — no UID separation from host |
| `automountServiceAccountToken: true` | Medium–High | API server access from inside pod, depends on SA permissions |
| No `readOnlyRootFilesystem` | Medium | Attacker can write tools to container filesystem |
| No resource limits | Medium | Noisy neighbor attacks, resource exhaustion |

---

## RBAC Exploit Reference

| Permission | Why it is dangerous | How to test with Chaosify |
|---|---|---|
| `*` on `*` (wildcard) | Full cluster control | `probe identity --can "*" --resource "*" --expect denied` |
| `create pods` | Can schedule privileged pods → node escape | `probe identity --can create --resource pods --expect denied` |
| `create clusterrolebindings` | Can grant cluster-admin to any account | `probe identity --can create --resource clusterrolebindings --expect denied` |
| `get/list secrets` | Direct credential theft | `probe identity --can list --resource secrets --resource-namespace kube-system --expect denied` |
| `exec pods` | Shell into any pod in namespace | `probe identity --can create --resource pods/exec --expect denied` |
| `impersonate` | Act as any user including cluster-admin | `probe identity --can impersonate --resource users --expect denied` |
| `escalate` / `bind` | Self-grant higher privilege | `probe identity --can escalate --resource clusterroles --expect denied` |
| `patch deployments` | Inject malicious container into running workload | `probe identity --can patch --resource deployments --expect denied` |

---

## Runtime Detection Reference

| Technique | What a good runtime tool should detect | Chaosify test |
|---|---|---|
| Sensitive file read | `cat /etc/shadow`, `cat /etc/passwd` | `runtime-baseline` / `probe detect` |
| Shell spawned in container | `sh -c`, `bash`, `python -c` inside a non-shell container | `probe detect --run "sh -c id"` |
| Package manager execution | `apt-get`, `yum`, `apk` inside container | `probe detect --run "apk add curl"` |
| Credential file access | Reading `/var/run/secrets/...` token | `probe detect --run "cat /var/run/secrets/kubernetes.io/serviceaccount/token"` |
| Network tool execution | `nc`, `nmap`, `curl` inside container | `probe detect --run "nc -zv 8.8.8.8 53"` |
| Container escape attempt | `nsenter`, `chroot`, `mount` | `probe detect --run "nsenter --mount=/proc/1/ns/mnt -- ls /"` |
| Crypto miner fingerprint | Process named `xmrig`, `minerd`, high CPU | behavioral — not directly testable by Chaosify |
| Write + execute in `/tmp` | Writing binary to `/tmp` and executing | `probe detect --run "echo '#!/bin/sh' > /tmp/x && chmod +x /tmp/x && /tmp/x"` |

---

## What Chaosify Tests vs. Does Not Test

**Tests:**
- Admission control enforcement (PSA, OPA, Kyverno, webhooks)
- Runtime detection tool alert coverage
- RBAC permission boundaries via SubjectAccessReview
- Network policy enforcement via reachability probing
- Container escape primitives via exec
- Cloud metadata isolation

**Does not test:**
- etcd encryption at rest
- API server TLS configuration
- Audit log completeness
- Node-level kernel hardening (seccomp profiles, AppArmor — recon surveys, does not verify)
- Image vulnerability scanning policies
- Image signature verification (Cosign/Sigstore)
- Supply chain integrity (SBOM attestation)
- Multi-tenancy namespace isolation beyond NetworkPolicy

---

## Defense-in-Depth Checklist

Use this to assess gaps after a Chaosify run:

- [ ] PSA `restricted` or `baseline` profile enforced on all non-system namespaces
- [ ] Kyverno or OPA Gatekeeper policies in `Enforce` mode (not `Audit`)
- [ ] No wildcard verb permissions in any RoleBinding or ClusterRoleBinding
- [ ] `automountServiceAccountToken: false` on all pods that do not need API access
- [ ] NetworkPolicy deny-all egress baseline with explicit allow rules per namespace
- [ ] Cloud IMDS (`169.254.169.254`) unreachable from pods
- [ ] Runtime security agent (Falco / Tetragon / KubeArmor) deployed and alerting
- [ ] Falco/Tetragon rules cover: sensitive file reads, shell spawn, token access, network tools
- [ ] No hostPath mounts to sensitive paths (`/`, `/etc`, `/proc`, `/var/run/docker.sock`)
- [ ] No privileged containers outside system namespaces
- [ ] No cluster-admin ClusterRoleBindings for non-system service accounts
- [ ] `probe identity` sweep of all non-default service accounts for dangerous permissions
