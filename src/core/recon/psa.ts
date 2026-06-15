import * as k8s from '@kubernetes/client-node'
import { coreV1Api } from '../kube/client.js'
import { reconWrapper, SYSTEM_NAMESPACES } from '../utils/recon.js'
import type {
    ReconFinding,
    ReconOptions,
    ReconToolResult,
    PsaEnforceLevel,
    PsaExploitClass,
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

/**
 * Maps a PSA enforce level to exploit classes, impact narrative, suggested probe, and severity.
 * Returns null for enforce=restricted — that is the secure posture and emits no finding.
 * @param ns Namespace name — used to build the namespace-targeted suggested probe.
 * @param enforceLevel Effective PSA enforce level for the namespace.
 * @param auditOnly Whether the namespace has audit/warn labels but no enforce.
 */
function classifyExposure(
    ns: string,
    enforceLevel: PsaEnforceLevel,
    auditOnly: boolean,
): Pick<PsaThreatFinding, 'exploitClasses' | 'impact' | 'suggestedProbe' | 'severity'> | null {
    if (enforceLevel === 'none' || enforceLevel === 'privileged') {
        // Build a context-aware reason string that the agent can surface verbatim.
        const reason = auditOnly
            ? 'PSA in audit/warn mode only — violations logged but pods admitted without restriction'
            : enforceLevel === 'privileged'
                ? 'PSA enforce=privileged — all pod security restrictions explicitly disabled'
                : 'no PSA enforce label'
        return {
            exploitClasses: ['node_escape'] as PsaExploitClass[],
            impact: `${reason} → admits privileged pods, hostNetwork/hostPID, and host filesystem mounts → node breakout`,
            // Running the full preventive pack in the target namespace exercises all seven admission scenarios.
            suggestedProbe: `probe run --pack preventive-baseline --namespace ${ns}`,
            severity: 'high',
        }
    }

    if (enforceLevel === 'baseline') {
        return {
            exploitClasses: ['container_escape'] as PsaExploitClass[],
            // baseline blocks the worst (hostNetwork, privileged) but still admits allowPrivilegeEscalation.
            impact: `PSA=baseline → admits pods with allowPrivilegeEscalation:true and unrestricted Linux capabilities → container privilege escalation`,
            suggestedProbe: `probe run --scenario deny-privilege-escalation --namespace ${ns}`,
            severity: 'medium',
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
 * Pod-first PSA recon: evaluates the PSA enforce label on each running pod's namespace
 * and flags gaps that permit privileged or escalatable workloads. Namespaces with no
 * running pods are out of scope — an unenforced label is only a finding when a reachable
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

        // Evaluate each running pod's PSA exposure from its namespace's enforce label.
        const evaluations = podsRes.items
            .filter(p => p.status?.phase === 'Running')
            .filter(p => options.includeSystem || !SYSTEM_NAMESPACES.has(p.metadata?.namespace ?? ''))
            .map(p => {
                const ns = p.metadata?.namespace ?? ''
                const labels = nsLabels.get(ns) ?? {}
                // Determine both the enforce level and whether the namespace is in audit-only mode.
                return {
                    pod: p.metadata?.name ?? '',
                    namespace: ns,
                    enforceLevel: extractEnforceLevel(labels),
                    auditOnly: isAuditOnly(labels),
                }
            })
            .filter(e => e.pod)

        // Collapse pods sharing an exposure profile within a namespace — replicas add noise, not signal.
        const groups = new Map<string, typeof evaluations>()
        for (const e of evaluations) {
            if (!classifyExposure(e.namespace, e.enforceLevel, e.auditOnly)) continue
            const key = `${e.namespace}|${e.enforceLevel}|${e.auditOnly}`
            groups.set(key, [...(groups.get(key) ?? []), e])
        }

        const findings: PsaThreatFinding[] = [...groups.values()].map(group => {
            const first = group[0]!
            // classifyExposure is non-null here — groups only holds exposures that classified.
            const classification = classifyExposure(first.namespace, first.enforceLevel, first.auditOnly)!
            return {
                namespace: first.namespace,
                examplePod: first.pod,
                podCount: group.length,
                enforceLevel: first.enforceLevel,
                auditOnly: first.auditOnly,
                ...classification,
            }
        })

        // Surface the most severe gaps first.
        const order: PsaThreatSeverity[] = ['critical', 'high', 'medium', 'low']
        findings.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity))

        const blindSpots = [
            'PSA labels are enforced by the Kubernetes API server — other admission controllers (Gatekeeper, Kyverno) may provide equivalent protections without PSA labels; cross-reference recon webhooks.',
            'enforce=baseline prevents the worst exploits (privileged, hostNetwork) but still admits allowPrivilegeEscalation:true — this may be intentional; confirm with probe run.',
            'PSA labels apply at admission time only — non-compliant pods already running in a newly labelled namespace are not retroactively ejected.',
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
