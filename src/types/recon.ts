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

// One namespace's reachable pods sharing the same PSA enforcement gap.
export interface PsaThreatFinding {
    namespace: string
    /** A reachable running pod in this namespace — the concrete entry point. */
    examplePod: string
    /** How many running pods in this namespace share this exposure profile. */
    podCount: number
    enforceLevel: PsaEnforceLevel
    /** True when audit/warn labels exist but no enforce label — non-compliant pods are still admitted. */
    auditOnly: boolean
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

export interface ReconOptions {
    namespace: string
    context?: string
    verbose?: boolean
    /** Include kube-system service accounts — off by default to reduce noise. */
    includeSystem?: boolean
    /** Force a specific policy engine instead of auto-detecting. */
    engine?: string
}
