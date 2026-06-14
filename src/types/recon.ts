// Types for the recon layer — intentionally separate from the evidence schema used for pass/fail verdicts.

export type ReconFindingSeverity = 'CRITICAL' | 'HIGH' | 'WARN' | 'INFO' | 'SKIP'

export interface ReconFinding {
    severity: ReconFindingSeverity
    title: string
    detail: string
    /** SKIP findings only. */
    missingPermission?: string
    /** SKIP findings only. */
    coverageImpact?: string
}

// Result from one recon tool — always returned, never thrown, even on permission errors.
export interface ReconToolResult {
    tool: string
    status: 'ok' | 'skip' | 'error'
    findings: ReconFinding[]
    /** Raw structured data for agentic AI consumption. */
    data: unknown
}

// Top-level artifact written by `chaosify recon all`.
export interface ReconReport {
    runId: string
    clusterContext: string
    namespace: string
    startedAt: string
    endedAt: string
    summary: { critical: number; high: number; warn: number; info: number; skip: number }
    tools: ReconToolResult[]
}

// ---------------------------------------------------------------------------
// RBAC threat graph — pod-first recon (see docs/rbac-command.md).
// The CLI walks running pods → harvests each pod's mounted ServiceAccount token
// via exec → fingerprints that token's effective permissions via
// SelfSubjectRulesReview → flags exploitable privilege chains. The emitted data
// is a pre-correlated threat graph (Pod → SA → Permissions → Impact), not a raw
// RBAC dump: triage happens in the CLI, not in the agent's context window.
// ---------------------------------------------------------------------------

// Exploit classes a harvested identity may enable.
export type RbacExploitClass = 'privilege_escalation' | 'lateral_movement' | 'secret_access'

// Severity of a single threat finding. Lowercase to match the agent YAML output.
export type RbacThreatSeverity = 'critical' | 'high' | 'medium' | 'low'

// One effective permission flagged as dangerous, with the classes it contributes to.
export interface RbacDangerousPermission {
    resources: string[]
    verbs: string[]
    apiGroups: string[]
    exploitClasses: RbacExploitClass[]
}

// One reachable pod → its mounted identity → what that identity can do.
export interface RbacThreatFinding {
    pod: string
    namespace: string
    serviceAccount: string
    /** Whether the SA token is mounted into the pod (automountServiceAccountToken). */
    automountToken: boolean
    /** Whether the token was successfully read out of the pod via exec. */
    tokenHarvested: boolean
    exploitClasses: RbacExploitClass[]
    dangerousPermissions: RbacDangerousPermission[]
    /** Human-readable Entry Point → Identity → Permissions → Impact narrative. */
    attackChain: string
    severity: RbacThreatSeverity
    /** True when dangerous permissions were found in namespaces other than the pod's own namespace. */
    crossNamespaceAccess: boolean
}

// Emitted in ReconToolResult.data — the pre-correlated threat graph plus blind spots.
export interface RbacThreatGraph {
    podsScanned: number
    tokensHarvested: number
    findings: RbacThreatFinding[]
    /** Honest about what the survey could not see (design principle: no false confidence). */
    blindSpots: string[]
}

// ---------------------------------------------------------------------------
// Network exposure graph — pod-first recon (see network-policies command).
// Each reachable running pod's egress/ingress coverage is evaluated against the
// NetworkPolicies that actually select it. A pod with an open path becomes a
// finding mapping entry point → reachable target → impact, plus a non-binding
// probe to confirm it. CNI enforcement is never assumed — a policy existing
// does not prove it is enforced (flannel ignores them) — so that gap is
// surfaced as a blind spot rather than scored as coverage.
// ---------------------------------------------------------------------------

export type NetpolExploitClass = 'metadata_exposure' | 'egress_exfiltration' | 'lateral_movement'

export type NetpolThreatSeverity = 'critical' | 'high' | 'medium' | 'low'

// One namespace's reachable pods sharing an open-path exposure profile.
export interface NetpolThreatFinding {
    namespace: string
    /** A reachable running pod in this namespace — the concrete entry point. */
    examplePod: string
    /** How many running pods in this namespace share this exposure profile. */
    podCount: number
    /** No NetworkPolicy selects these pods for egress — outbound traffic is unrestricted. */
    egressOpen: boolean
    /** No NetworkPolicy selects these pods for ingress — reachable from any pod cluster-wide. */
    ingressOpen: boolean
    exploitClasses: NetpolExploitClass[]
    /** Human-readable Entry Point → reachable target → impact narrative. */
    impact: string
    /** Non-binding probe the agent can run to confirm the path. */
    suggestedProbe: string
    severity: NetpolThreatSeverity
}

// Emitted in ReconToolResult.data — pre-correlated open network paths plus blind spots.
export interface NetpolThreatGraph {
    podsScanned: number
    policiesScanned: number
    findings: NetpolThreatFinding[]
    /** Honest about what the survey could not see (e.g. whether the CNI enforces policies). */
    blindSpots: string[]
}

// ---------------------------------------------------------------------------
// PSA enforcement gap graph — pod-first recon (see psa command).
// Each reachable running pod's namespace is evaluated for a PSA enforce label.
// Absent or privileged enforce levels enable node_escape; baseline enables
// container_escape. Restricted is the secure posture and emits no finding.
// ---------------------------------------------------------------------------

// The four possible enforce label values, plus 'none' for an absent label.
export type PsaEnforceLevel = 'none' | 'privileged' | 'baseline' | 'restricted'

// Attack classes a PSA gap enables — node_escape for unrestricted namespaces, container_escape for baseline.
export type PsaExploitClass = 'node_escape' | 'container_escape'

export type PsaThreatSeverity = 'critical' | 'high' | 'medium' | 'low'

// Dangerous attributes a running pod's spec actually exercises. The first four are
// node-escape traits (blocked at baseline+); privilege_escalation is admitted by baseline.
export type PsaObservedTrait =
    | 'privileged'
    | 'host_namespaces'
    | 'host_path'
    | 'dangerous_capabilities'
    | 'privilege_escalation'

// One namespace's reachable pods sharing the same PSA enforcement gap.
export interface PsaThreatFinding {
    namespace: string
    /** A reachable running pod in this namespace — the concrete entry point. Prefers a pod that confirms the chain. */
    examplePod: string
    /** How many running pods in this namespace share this exposure profile. */
    podCount: number
    enforceLevel: PsaEnforceLevel
    /** True when audit/warn labels exist but no enforce label — non-compliant pods are still admitted. */
    auditOnly: boolean
    /**
     * Dangerous traits a running pod actually exercises that the namespace's PSA level admits —
     * the difference between a confirmed reachable chain and a merely-permissive namespace.
     * Empty when the gap is only potential (no running pod exercises it).
     */
    observedTraits: PsaObservedTrait[]
    /** True when ≥1 running pod confirms a reachable chain; false when the namespace is only permissive. */
    confirmed: boolean
    exploitClasses: PsaExploitClass[]
    /** Human-readable entry point → PSA gap → impact narrative. */
    impact: string
    /** Non-binding probe the agent can run to confirm the gap. */
    suggestedProbe: string
    severity: PsaThreatSeverity
}

// Emitted in ReconToolResult.data — pre-correlated enforcement gaps plus blind spots.
export interface PsaThreatGraph {
    podsScanned: number
    namespacesScanned: number
    findings: PsaThreatFinding[]
    /** Honest about what the survey could not see (e.g. other admission controllers). */
    blindSpots: string[]
}

// ---------------------------------------------------------------------------
// Admission webhook threat graph (see webhooks command).
// Admission webhooks are cluster config, not pod-reachable, so this is not a
// pod-first survey — but it shares the threat-graph vocabulary (exploit classes,
// scored severity, suggested probe, blind spots) so an agent reads psa, policies,
// and webhooks as one consistent admission-control picture rather than three shapes.
// ---------------------------------------------------------------------------

export interface WebhookInfo {
    name: string
    type: 'validating' | 'mutating'
    ruleCount: number
    failurePolicy: string
    scope: string
}

// The single class a webhook gap enables: a path to bypass admission enforcement.
export type WebhookExploitClass = 'admission_bypass'

export type WebhookThreatSeverity = 'critical' | 'high' | 'medium' | 'low'

// One fail-open webhook and the admission it leaves bypassable.
export interface WebhookThreatFinding {
    webhook: string
    type: 'validating' | 'mutating'
    /** cluster-wide is worse than namespace-scoped — a wider bypass. */
    scope: string
    failurePolicy: string
    ruleCount: number
    exploitClasses: WebhookExploitClass[]
    impact: string
    suggestedProbe: string
    severity: WebhookThreatSeverity
}

export interface WebhookThreatGraph {
    webhooksScanned: number
    findings: WebhookThreatFinding[]
    /** Raw inventory retained for the agent — every webhook, not just the flagged ones. */
    webhooks: WebhookInfo[]
    blindSpots: string[]
}

// ---------------------------------------------------------------------------
// Policy engine threat graph (see policies command).
// Detects Kyverno / Gatekeeper and scores enforcement-mode gaps. Like webhooks,
// this surveys cluster config rather than reachable pods; the honest limit — that
// per-policy workload coverage is not simulated — is surfaced as a blind spot.
// ---------------------------------------------------------------------------

export type PolicyEngine = 'kyverno' | 'gatekeeper' | 'none'

export interface PolicyInfo {
    name: string
    engine: PolicyEngine
    /** 'Enforce' | 'Audit' for Kyverno; Gatekeeper does not surface this field. */
    validationFailureAction?: string
}

export type PolicyExploitClass = 'admission_bypass'

export type PolicyThreatSeverity = 'critical' | 'high' | 'medium' | 'low'

// One policy whose enforcement mode admits the workloads it claims to govern.
export interface PolicyThreatFinding {
    policy: string
    engine: PolicyEngine
    exploitClasses: PolicyExploitClass[]
    impact: string
    suggestedProbe: string
    severity: PolicyThreatSeverity
}

export interface PolicyThreatGraph {
    engine: PolicyEngine
    policiesScanned: number
    findings: PolicyThreatFinding[]
    /** Raw inventory retained for the agent. */
    policies: PolicyInfo[]
    blindSpots: string[]
}

// ---------------------------------------------------------------------------
// Runtime detection threat graph (see runtime-agents command).
// Detects Falco / KubeArmor / Tetragon / Tracee DaemonSets and scores detection
// gaps: no agent at all, partial node coverage (pods on uncovered nodes run
// unmonitored), and detect-only posture with no kernel-level enforcement.
// ---------------------------------------------------------------------------

export interface AgentStatus {
    name: string
    detected: boolean
    readyNodes?: number
    desiredNodes?: number
    namespace?: string
}

// detection_gap: workloads execute unobserved. no_enforcement: threats are seen but not blocked.
export type RuntimeExploitClass = 'detection_gap' | 'no_enforcement'

export type RuntimeThreatSeverity = 'critical' | 'high' | 'medium' | 'low'

export interface RuntimeThreatFinding {
    /** The agent the finding concerns, or '(none)' for a cluster-wide absence. */
    agent: string
    exploitClasses: RuntimeExploitClass[]
    impact: string
    suggestedProbe: string
    severity: RuntimeThreatSeverity
}

export interface RuntimeThreatGraph {
    daemonsetsScanned: number
    agentsDetected: number
    findings: RuntimeThreatFinding[]
    /** Raw inventory retained for the agent — every known agent and its coverage. */
    agents: AgentStatus[]
    blindSpots: string[]
}

// ---------------------------------------------------------------------------
// Node inventory (see nodes command). Inventory, not a threat graph — kernel /
// runtime / security-feature facts the agent uses as context, not scored chains.
// ---------------------------------------------------------------------------

export interface NodeInfo {
    name: string
    os: string
    kernel: string
    runtime: string
    appArmorEnabled: boolean
    /**
     * The kubelet's seccomp-default posture is set by the --seccomp-default flag, which is not
     * exposed in node status — so this is 'unknown', never fabricated. Confirm per-pod with probe run.
     */
    seccompDefault: string
}

export interface ReconOptions {
    namespace: string
    context?: string
    verbose?: boolean
    /** Include kube-system service accounts — off by default to reduce noise. */
    includeSystem?: boolean
    /** Force a specific policy engine instead of auto-detecting. */
    engine?: string
}
