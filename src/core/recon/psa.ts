import * as k8s from '@kubernetes/client-node'
import { coreV1Api } from '../kube/client.js'
import { reconWrapper, SYSTEM_NAMESPACES } from '../utils/recon.js'
import type {
    ReconFinding,
    ReconOptions,
    ReconToolResult,
    PsaEnforceLevel,
    PsaExploitClass,
    PsaObservedTrait,
    PsaThreatFinding,
    PsaThreatGraph,
    PsaThreatSeverity,
} from '../../types/recon.js'

// Reads the pod-security.kubernetes.io/enforce label; absent maps to 'none'.
function extractEnforceLevel(labels: Record<string, string>): PsaEnforceLevel {
    const level = labels['pod-security.kubernetes.io/enforce']
    if (level === 'privileged' || level === 'baseline' || level === 'restricted') return level
    return 'none'
}

// Returns true when audit/warn labels exist but no enforce label — the namespace logs violations but admits them.
function isAuditOnly(labels: Record<string, string>): boolean {
    return !labels['pod-security.kubernetes.io/enforce'] &&
        !!(labels['pod-security.kubernetes.io/audit'] || labels['pod-security.kubernetes.io/warn'])
}

// The node-escape traits — privileged, host namespace sharing, host filesystem mounts, and
// dangerous capabilities. PSA baseline+ blocks every one of these; only none/privileged admit them.
const NODE_ESCAPE_TRAITS: readonly PsaObservedTrait[] = [
    'privileged', 'host_namespaces', 'host_path', 'dangerous_capabilities',
]

// baseline permits adding only NET_BIND_SERVICE; any other added capability is a violation.
const BASELINE_ALLOWED_CAP = 'NET_BIND_SERVICE'

/**
 * Inspects a pod spec for the dangerous traits PSA is meant to block. This is the
 * ground-truth half of the correlation: what the pod *actually does*, not what its
 * namespace would merely permit. Covers init, regular, and ephemeral containers.
 * @param pod The running pod whose spec is examined.
 */
function observeTraits(pod: k8s.V1Pod): PsaObservedTrait[] {
    const spec = pod.spec
    if (!spec) return []
    const traits = new Set<PsaObservedTrait>()

    // Pod-level host namespace sharing and host filesystem mounts.
    if (spec.hostNetwork || spec.hostPID || spec.hostIPC) traits.add('host_namespaces')
    if ((spec.volumes ?? []).some(v => v.hostPath)) traits.add('host_path')

    // Container-level securityContext across every container type.
    const containers = [
        ...(spec.initContainers ?? []),
        ...(spec.containers ?? []),
        ...(spec.ephemeralContainers ?? []),
    ]
    for (const c of containers) {
        const sc = c.securityContext
        if (!sc) continue
        if (sc.privileged) traits.add('privileged')
        if (sc.allowPrivilegeEscalation === true) traits.add('privilege_escalation')
        for (const cap of sc.capabilities?.add ?? [])
            if (cap !== BASELINE_ALLOWED_CAP) traits.add('dangerous_capabilities')
    }

    return [...traits]
}

/**
 * Whether a namespace's PSA enforce level admits a given dangerous trait. A trait is only a
 * reachable chain when the level would *not* have blocked it at admission:
 *  - none/privileged admit everything,
 *  - baseline blocks the node-escape traits but still admits privilege_escalation,
 *  - restricted admits nothing.
 */
function levelAdmitsTrait(level: PsaEnforceLevel, trait: PsaObservedTrait): boolean {
    switch (level) {
        case 'none':
        case 'privileged': return true
        case 'baseline': return trait === 'privilege_escalation'
        case 'restricted': return false
    }
}

/**
 * Maps a PSA gap and the traits a reachable pod actually exercises to exploit classes, impact
 * narrative, suggested probe, and severity. Returns null for enforce=restricted — the secure
 * posture, which emits no finding.
 *
 * Severity is correlation-aware: a confirmed node-escape trait outranks a merely-permissive
 * namespace (critical vs high), and a confirmed privilege-escalation pod outranks a permissive
 * baseline namespace (high vs medium).
 * @param ns Namespace name — used to build the namespace-targeted suggested probe.
 * @param enforceLevel Effective PSA enforce level for the namespace.
 * @param auditOnly Whether the namespace has audit/warn labels but no enforce.
 * @param observedTraits Admitted dangerous traits confirmed across the namespace's reachable pods.
 */
function classifyExposure(
    ns: string,
    enforceLevel: PsaEnforceLevel,
    auditOnly: boolean,
    observedTraits: PsaObservedTrait[],
): Pick<PsaThreatFinding, 'exploitClasses' | 'impact' | 'suggestedProbe' | 'severity' | 'observedTraits' | 'confirmed'> | null {
    const confirmed = observedTraits.length > 0
    const traitList = observedTraits.join(', ')

    if (enforceLevel === 'none' || enforceLevel === 'privileged') {
        // Build a context-aware reason string that the agent can surface verbatim.
        const reason = auditOnly
            ? 'PSA in audit/warn mode only — violations logged but pods admitted without restriction'
            : enforceLevel === 'privileged'
                ? 'PSA enforce=privileged — all pod security restrictions explicitly disabled'
                : 'no PSA enforce label'
        // A confirmed node-escape trait is a reachable host breakout, not just a permissive namespace.
        const hasNodeEscape = observedTraits.some(t => NODE_ESCAPE_TRAITS.includes(t))
        const impact = confirmed
            ? `${reason} → a running pod exercises [${traitList}] that PSA does not block → confirmed ${hasNodeEscape ? 'node breakout' : 'privilege escalation'}`
            : `${reason} → admits privileged pods, hostNetwork/hostPID, and host filesystem mounts → node breakout (no running pod currently exercises this)`
        return {
            exploitClasses: ['node_escape'] as PsaExploitClass[],
            impact,
            // Running the full preventive pack in the target namespace exercises all seven admission scenarios.
            suggestedProbe: `probe run --pack preventive-baseline --namespace ${ns}`,
            severity: hasNodeEscape ? 'critical' : 'high',
            observedTraits,
            confirmed,
        }
    }

    if (enforceLevel === 'baseline') {
        // baseline blocks the worst (hostNetwork, privileged) but still admits allowPrivilegeEscalation.
        const impact = confirmed
            ? `PSA=baseline → a running pod sets allowPrivilegeEscalation:true and baseline admits it → confirmed container privilege escalation`
            : `PSA=baseline → admits pods with allowPrivilegeEscalation:true and unrestricted Linux capabilities → container privilege escalation`
        return {
            exploitClasses: ['container_escape'] as PsaExploitClass[],
            impact,
            suggestedProbe: `probe run --scenario deny-privilege-escalation --namespace ${ns}`,
            // A confirmed escalating pod is a reachable chain; a permissive baseline namespace is only potential.
            severity: confirmed ? 'high' : 'medium',
            observedTraits,
            confirmed,
        }
    }

    // enforce=restricted is the secure posture — no finding.
    return null
}

const SEVERITY_BADGE: Record<PsaThreatSeverity, ReconFinding['severity']> = {
    critical: 'CRITICAL',
    high: 'HIGH',
    medium: 'WARN',
    low: 'INFO',
}

// Projects the threat graph into the shared ReconFinding shape for terminal rendering and the recon summary roll-up.
function toReconFindings(graph: PsaThreatGraph): ReconFinding[] {
    if (graph.findings.length === 0) {
        return [{
            severity: 'INFO',
            title: `No PSA enforcement gaps found across ${graph.podsScanned} reachable pod(s)`,
            detail: `${graph.namespacesScanned} namespace(s) surveyed; all pods run under PSA enforce=restricted.`,
        }]
    }

    return graph.findings.map(f => ({
        severity: SEVERITY_BADGE[f.severity],
        title: `${f.namespace} → ${f.examplePod}${f.podCount > 1 ? ` (+${f.podCount - 1} more)` : ''} (${f.exploitClasses.join(', ')})`,
        detail: f.impact,
    }))
}

/**
 * Pod-first PSA recon: evaluates each running pod's namespace PSA enforce label and, crucially,
 * intersects the gap with the dangerous traits the pod's spec actually exercises. This turns
 * "this namespace would admit a privileged pod" (a config gap) into "this pod IS privileged and
 * PSA does not block it" (a confirmed reachable chain) and scores severity accordingly. Namespaces
 * with no running pods are out of scope — an unenforced label is only a finding when a reachable
 * pod sits behind it.
 * @param kc Loaded kubeconfig — used to list pods and namespaces cluster-wide.
 * @param options Recon options; includeSystem pulls in system namespaces (off by default).
 */
export function surveyPsa(kc: k8s.KubeConfig, options: ReconOptions): Promise<ReconToolResult> {
    const core = coreV1Api(kc)

    return reconWrapper('psa', {
        title: 'PSA recon skipped',
        detail: 'Cannot list pods or namespaces — insufficient permissions',
        missingPermission: 'list pods, namespaces',
        coverageImpact: 'Pod Security Admission enforcement gaps from reachable workloads cannot be identified',
    }, async () => {
        // Fetch pods and namespace labels in parallel to reduce latency.
        const [podsRes, namespacesRes] = await Promise.all([
            core.listPodForAllNamespaces(),
            core.listNamespace(),
        ])

        // Build namespace → labels map so each pod lookup is O(1).
        const nsLabels = new Map<string, Record<string, string>>()
        for (const ns of namespacesRes.items) {
            const name = ns.metadata?.name ?? ''
            if (name) nsLabels.set(name, ns.metadata?.labels ?? {})
        }

        // Evaluate each running pod: its namespace's PSA gap plus the dangerous traits the pod
        // actually exercises that the gap admits (the confirmed, reachable subset).
        const evaluations = podsRes.items
            .filter(p => p.status?.phase === 'Running')
            .filter(p => options.includeSystem || !SYSTEM_NAMESPACES.has(p.metadata?.namespace ?? ''))
            .map(p => {
                const ns = p.metadata?.namespace ?? ''
                const enforceLevel = extractEnforceLevel(nsLabels.get(ns) ?? {})
                return {
                    pod: p.metadata?.name ?? '',
                    namespace: ns,
                    enforceLevel,
                    auditOnly: isAuditOnly(nsLabels.get(ns) ?? {}),
                    // Only traits the namespace's level admits count — a privileged pod in a restricted
                    // namespace would have been blocked at admission, so it is not a reachable chain here.
                    observedTraits: observeTraits(p).filter(t => levelAdmitsTrait(enforceLevel, t)),
                }
            })
            .filter(e => e.pod)

        // Collapse pods sharing an exposure profile within a namespace — replicas add noise, not signal.
        // restricted namespaces are the secure posture and never form a group.
        const groups = new Map<string, typeof evaluations>()
        for (const e of evaluations) {
            if (e.enforceLevel === 'restricted') continue
            const key = `${e.namespace}|${e.enforceLevel}|${e.auditOnly}`
            groups.set(key, [...(groups.get(key) ?? []), e])
        }

        const findings: PsaThreatFinding[] = [...groups.values()].map(group => {
            // Union the confirmed traits across the group and prefer a confirming pod as the entry point,
            // so the example pod shown is the actual smoking gun rather than an arbitrary replica.
            const confirmedTraits = [...new Set(group.flatMap(e => e.observedTraits))]
            const entry = group.find(e => e.observedTraits.length > 0) ?? group[0]!
            // classifyExposure is non-null here — restricted namespaces were filtered out above.
            const classification = classifyExposure(entry.namespace, entry.enforceLevel, entry.auditOnly, confirmedTraits)!
            return {
                namespace: entry.namespace,
                examplePod: entry.pod,
                podCount: group.length,
                enforceLevel: entry.enforceLevel,
                auditOnly: entry.auditOnly,
                ...classification,
            }
        })

        // Surface the most severe gaps first — confirmed chains (critical) ahead of permissive namespaces.
        const order: PsaThreatSeverity[] = ['critical', 'high', 'medium', 'low']
        findings.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity))

        const blindSpots = [
            'PSA labels are enforced by the Kubernetes API server — other admission controllers (Gatekeeper, Kyverno) may provide equivalent protections without PSA labels; cross-reference recon webhooks.',
            'enforce=baseline still admits allowPrivilegeEscalation:true; confirmed traits reflect only the specs of currently running pods, so a permissive namespace with benign pods today can still admit a privileged pod tomorrow. Confirm enforcement with probe run.',
            'PSA labels apply at admission time only — non-compliant pods already running in a newly labelled (e.g. restricted) namespace are not retroactively ejected and are not counted here.',
        ]

        const graph: PsaThreatGraph = {
            podsScanned: evaluations.length,
            namespacesScanned: nsLabels.size,
            findings,
            blindSpots,
        }

        return { findings: toReconFindings(graph), data: graph }
    })
}
