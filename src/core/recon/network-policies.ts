import * as k8s from '@kubernetes/client-node'
import { coreV1Api, networkingV1Api } from '../kube/client.js'
import { reconWrapper, SYSTEM_NAMESPACES } from '../utils/recon.js'
import type {
    ReconFinding,
    ReconOptions,
    ReconToolResult,
    NetpolExploitClass,
    NetpolThreatFinding,
    NetpolThreatGraph,
    NetpolThreatSeverity,
} from '../../types/recon.js'

// The cloud instance metadata endpoint — reachable from any pod with open egress
// and the highest-value target: it yields the node's IAM/role credentials.
const METADATA_ENDPOINT = 'http://169.254.169.254/latest/meta-data/'

// A reachable pod and the network exposure its NetworkPolicy coverage leaves open.
interface PodExposure {
    pod: string
    namespace: string
    egressOpen: boolean
    ingressOpen: boolean
}

/**
 * Whether a NetworkPolicy podSelector selects a pod. An empty selector ({}) selects
 * every pod in the namespace. Supports matchLabels and matchExpressions so a policy
 * that scopes to specific pods is not mistaken for namespace-wide coverage.
 */
function selectorMatchesPod(selector: k8s.V1LabelSelector | undefined, labels: Record<string, string>): boolean {
    if (!selector || (!selector.matchLabels && !selector.matchExpressions?.length)) return true

    for (const [key, value] of Object.entries(selector.matchLabels ?? {}))
        if (labels[key] !== value) return false

    for (const expr of selector.matchExpressions ?? []) {
        const value = labels[expr.key]
        const present = value !== undefined
        const inSet = value !== undefined && (expr.values ?? []).includes(value)
        switch (expr.operator) {
            case 'In': if (!present || !inSet) return false; break
            case 'NotIn': if (present && inSet) return false; break
            case 'Exists': if (!present) return false; break
            case 'DoesNotExist': if (present) return false; break
            default: return false
        }
    }
    return true
}

/**
 * An egress rule allows all destinations when it lists no peers (`egress: [{}]`)
 * or explicitly permits the whole IPv4 space. Ports and ipBlock `except` are not
 * yet evaluated — a broad CIDR is treated as open (the safe, over-reporting side).
 */
function egressRuleAllowsAll(rule: k8s.V1NetworkPolicyEgressRule): boolean {
    const to = rule.to ?? []
    if (to.length === 0) return true
    return to.some(peer => peer.ipBlock?.cidr === '0.0.0.0/0')
}

/**
 * An ingress rule allows all sources when it lists no peers (`ingress: [{}]`),
 * permits every namespace (empty namespaceSelector), or the whole IPv4 space.
 */
function ingressRuleAllowsAll(rule: k8s.V1NetworkPolicyIngressRule): boolean {
    // client-node renames the wire field `from` to `_from` (reserved word).
    const from = rule._from ?? []
    if (from.length === 0) return true
    return from.some(peer =>
        peer.ipBlock?.cidr === '0.0.0.0/0' ||
        (peer.namespaceSelector !== undefined && !peer.namespaceSelector.matchLabels && !peer.namespaceSelector.matchExpressions?.length))
}

/**
 * Evaluates whether the policies selecting this pod leave egress or ingress open.
 * A pod is "open" in a direction when it is not isolated in that direction, OR a
 * selecting policy's rules allow-all — so a policy named `allow-all` with
 * `egress: [{}]` is correctly read as open, not as coverage. A policy with no
 * explicit policyTypes defaults to Ingress (Kubernetes semantics).
 */
function evaluateExposure(labels: Record<string, string>, policies: k8s.V1NetworkPolicy[]): { egressOpen: boolean; ingressOpen: boolean } {
    let egressIsolated = false, egressAllowsAll = false
    let ingressIsolated = false, ingressAllowsAll = false

    for (const policy of policies) {
        if (!selectorMatchesPod(policy.spec?.podSelector, labels)) continue
        const types = policy.spec?.policyTypes ?? []

        if (types.length === 0 || types.includes('Ingress')) {
            ingressIsolated = true
            if ((policy.spec?.ingress ?? []).some(ingressRuleAllowsAll)) ingressAllowsAll = true
        }
        if (types.includes('Egress')) {
            egressIsolated = true
            if ((policy.spec?.egress ?? []).some(egressRuleAllowsAll)) egressAllowsAll = true
        }
    }

    return {
        egressOpen: !egressIsolated || egressAllowsAll,
        ingressOpen: !ingressIsolated || ingressAllowsAll,
    }
}

// Builds the exploit classes, impact narrative, suggested probe, and severity for an open path.
function classifyExposure(ns: string, egressOpen: boolean, ingressOpen: boolean): Pick<NetpolThreatFinding, 'exploitClasses' | 'impact' | 'suggestedProbe' | 'severity'> {
    const classes: NetpolExploitClass[] = []
    const impacts: string[] = []

    if (egressOpen) {
        classes.push('metadata_exposure', 'egress_exfiltration')
        impacts.push(`outbound traffic is unrestricted → the cloud metadata endpoint (169.254.169.254) is reachable for node-credential theft, and data can be exfiltrated to any external host`)
    }
    if (ingressOpen) {
        classes.push('lateral_movement')
        impacts.push(`pods are reachable from any pod cluster-wide → a compromised neighbour can pivot into this workload`)
    }

    // Egress (metadata credential theft) is the headline; ingress-only is lateral movement.
    const suggestedProbe = egressOpen
        ? `probe network --namespace ${ns} --from <probe-pod.yaml> --target ${METADATA_ENDPOINT} --expect unreachable`
        : `probe network --namespace ${ns} --from <probe-pod.yaml> --target <neighbour-service>:<port> --expect unreachable`

    return {
        exploitClasses: classes,
        impact: impacts.join('; '),
        suggestedProbe,
        severity: egressOpen ? 'high' : 'medium',
    }
}

const SEVERITY_BADGE: Record<NetpolThreatSeverity, ReconFinding['severity']> = {
    critical: 'CRITICAL',
    high: 'HIGH',
    medium: 'WARN',
    low: 'INFO',
}

/**
 * Pod-first NetworkPolicy recon: enumerates running pods, evaluates the egress/ingress
 * coverage actually selecting each one, and flags open paths (metadata exposure, egress
 * exfiltration, lateral movement). Empty namespaces are out of scope — an open policy gap
 * is only a finding when a reachable pod sits behind it.
 * @param kc Loaded kubeconfig — used to list pods and NetworkPolicies cluster-wide.
 * @param options Recon options; includeSystem pulls in system namespaces (off by default).
 */
export function surveyNetworkPolicies(kc: k8s.KubeConfig, options: ReconOptions): Promise<ReconToolResult> {
    const networking = networkingV1Api(kc)
    const core = coreV1Api(kc)

    return reconWrapper('network-policies', {
        title: 'Network policy recon skipped',
        detail: 'Cannot list pods or NetworkPolicies cluster-wide — insufficient permissions',
        missingPermission: 'list pods, networkpolicies (all namespaces)',
        coverageImpact: 'Open network paths from reachable pods cannot be identified',
    }, async () => {
        // Fetch pods and policies in parallel to reduce latency.
        const [podsRes, policiesRes] = await Promise.all([
            core.listPodForAllNamespaces(),
            networking.listNetworkPolicyForAllNamespaces(),
        ])

        // Group policies by namespace so each pod is evaluated only against its own.
        const policiesByNamespace = new Map<string, k8s.V1NetworkPolicy[]>()
        for (const policy of policiesRes.items) {
            const ns = policy.metadata?.namespace ?? ''
            policiesByNamespace.set(ns, [...(policiesByNamespace.get(ns) ?? []), policy])
        }

        // Reachable entry points: running pods, optionally excluding system namespaces.
        const exposures: PodExposure[] = podsRes.items
            .filter(p => p.status?.phase === 'Running')
            .filter(p => options.includeSystem || !SYSTEM_NAMESPACES.has(p.metadata?.namespace ?? ''))
            .map(p => {
                const ns = p.metadata?.namespace ?? ''
                const { egressOpen, ingressOpen } = evaluateExposure(p.metadata?.labels ?? {}, policiesByNamespace.get(ns) ?? [])
                return { pod: p.metadata?.name ?? '', namespace: ns, egressOpen, ingressOpen }
            })
            .filter(e => e.pod)

        // Collapse pods sharing an exposure profile within a namespace — replicas add noise, not signal.
        const groups = new Map<string, PodExposure[]>()
        for (const e of exposures) {
            if (!e.egressOpen && !e.ingressOpen) continue
            const key = `${e.namespace}|${e.egressOpen}|${e.ingressOpen}`
            groups.set(key, [...(groups.get(key) ?? []), e])
        }

        const findings: NetpolThreatFinding[] = [...groups.values()].map(group => {
            const first = group[0]!
            return {
                namespace: first.namespace,
                examplePod: first.pod,
                podCount: group.length,
                egressOpen: first.egressOpen,
                ingressOpen: first.ingressOpen,
                ...classifyExposure(first.namespace, first.egressOpen, first.ingressOpen),
            }
        })

        // Surface the most severe paths first.
        const order: NetpolThreatSeverity[] = ['critical', 'high', 'medium', 'low']
        findings.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity))

        // Honest about what coverage analysis structurally cannot prove.
        const blindSpots = [
            'NetworkPolicy enforcement depends on the CNI plugin; a policy existing does not prove it is enforced (flannel, for example, ignores them). Confirm open paths with probe network.',
            'hostNetwork pods bypass NetworkPolicy entirely — cross-reference recon psa for namespaces that admit them.',
        ]

        const graph: NetpolThreatGraph = {
            podsScanned: exposures.length,
            policiesScanned: policiesRes.items.length,
            findings,
            blindSpots,
        }

        return { findings: toReconFindings(graph), data: graph }
    })
}

/**
 * Projects the threat graph into the shared ReconFinding shape so it renders in
 * the terminal Findings section and the recon summary roll-up.
 */
function toReconFindings(graph: NetpolThreatGraph): ReconFinding[] {
    if (graph.findings.length === 0) {
        return [{
            severity: 'INFO',
            title: `No open network paths found across ${graph.podsScanned} reachable pod(s)`,
            detail: `${graph.policiesScanned} NetworkPolicy/policies evaluated; every reachable pod is covered for ingress and egress.`,
        }]
    }

    return graph.findings.map(f => ({
        severity: SEVERITY_BADGE[f.severity],
        title: `${f.namespace} → ${f.examplePod}${f.podCount > 1 ? ` (+${f.podCount - 1} more)` : ''} (${f.exploitClasses.join(', ')})`,
        detail: f.impact,
    }))
}
