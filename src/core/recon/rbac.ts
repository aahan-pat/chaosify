import * as k8s from '@kubernetes/client-node'
import { coreV1Api, authorizationV1Api, kubeConfigWithToken } from '../kube/client.js'
import { execInPod } from '../kube/pod.js'
import { reconWrapper, SYSTEM_NAMESPACES } from '../utils/recon.js'
import type {
    ReconFinding,
    ReconOptions,
    ReconToolResult,
    RbacExploitClass,
    RbacDangerousPermission,
    RbacThreatFinding,
    RbacThreatGraph,
    RbacThreatSeverity,
} from '../../types/recon.js'

// Projected ServiceAccount token path mounted into every pod with automount enabled.
const TOKEN_PATH = '/var/run/secrets/kubernetes.io/serviceaccount/token'

// One reachable pod and the identity it carries — the entry point for recon.
interface PodEntryPoint {
    pod: string
    namespace: string
    serviceAccount: string
    automountToken: boolean
    container: string
    projectedTokenPaths: string[]
}

// A dangerous-permission matcher: when its predicate hits an effective rule it
// contributes its exploit class and a narrative fragment to the threat finding.
interface DangerMatcher {
    classes: RbacExploitClass[]
    reason: string
    match: (has: { verb: (...v: string[]) => boolean; resource: (...r: string[]) => boolean }) => boolean
}

// Matchers map directly to the exploit classes enumerated in docs/rbac-command.md.
const MATCHERS: DangerMatcher[] = [
    // Privilege escalation — paths to cluster-admin or node compromise.
    {
        classes: ['privilege_escalation'],
        reason: 'create clusterrolebindings → bind to cluster-admin → full cluster compromise',
        match: h => h.resource('clusterrolebindings') && h.verb('create', 'update', 'patch'),
    },
    {
        classes: ['privilege_escalation'],
        reason: 'create rolebindings → grant itself additional roles in the namespace',
        match: h => h.resource('rolebindings') && h.verb('create', 'update', 'patch'),
    },
    {
        classes: ['privilege_escalation'],
        reason: 'use bind/escalate verb → grant privileges beyond its own',
        match: h => h.verb('bind', 'escalate'),
    },
    {
        classes: ['privilege_escalation'],
        reason: 'create pods → schedule a privileged pod and break out to the node',
        match: h => h.resource('pods') && h.verb('create'),
    },
    {
        classes: ['privilege_escalation'],
        reason: 'mint serviceaccount tokens → impersonate other identities',
        match: h => h.resource('serviceaccounts/token') && h.verb('create'),
    },
    {
        classes: ['privilege_escalation'],
        reason: 'impersonate users/groups/serviceaccounts → act as any identity including cluster-admin',
        match: h => h.verb('impersonate') && h.resource('users', 'groups', 'serviceaccounts', 'userextras'),
    },
    {
        classes: ['privilege_escalation'],
        reason: 'write webhook configs → intercept and mutate all API traffic cluster-wide',
        match: h => h.resource('mutatingwebhookconfigurations', 'validatingwebhookconfigurations') && h.verb('create', 'update', 'patch', 'delete'),
    },
    {
        classes: ['privilege_escalation'],
        reason: 'patch/update namespaces → strip PSA enforcement labels, bypassing admission controls',
        match: h => h.resource('namespaces') && h.verb('patch', 'update'),
    },
    // Lateral movement — pivot to other workloads and identities.
    {
        classes: ['lateral_movement'],
        reason: 'exec/attach into running pods → pivot to higher-privilege identities',
        match: h => h.resource('pods/exec', 'pods/attach') && h.verb('create', 'get'),
    },
    {
        classes: ['lateral_movement'],
        reason: 'delete network policies → remove namespace network isolation',
        match: h => h.resource('networkpolicies') && h.verb('delete'),
    },
    // Secret / data access.
    {
        classes: ['secret_access'],
        reason: 'read secrets in the namespace, including other ServiceAccount tokens',
        match: h => h.resource('secrets') && h.verb('get', 'list', 'watch'),
    },
    {
        classes: ['secret_access'],
        reason: 'read configmaps that may expose credentials or connection strings',
        match: h => h.resource('configmaps') && h.verb('get', 'list', 'watch'),
    },
]

/**
 * Inspects one effective rule and returns the exploit classes, narrative
 * fragments, and API groups it triggers. Wildcards ('*') in verbs or resources match anything.
 */
function classifyRule(rule: k8s.V1ResourceRule): { classes: RbacExploitClass[]; reasons: string[]; apiGroups: string[] } {
    const verbs = rule.verbs ?? []
    const resources = rule.resources ?? []
    const has = {
        verb: (...v: string[]) => verbs.includes('*') || v.some(x => verbs.includes(x)),
        resource: (...r: string[]) => resources.includes('*') || r.some(x => resources.includes(x)),
    }

    const classes = new Set<RbacExploitClass>()
    const reasons: string[] = []
    for (const m of MATCHERS) {
        if (m.match(has)) {
            for (const c of m.classes) classes.add(c)
            reasons.push(m.reason)
        }
    }
    return { classes: [...classes], reasons, apiGroups: rule.apiGroups ?? [] }
}

// Privilege escalation is the most severe — it leads to cluster-admin or node escape.
function severityFor(classes: RbacExploitClass[]): RbacThreatSeverity {
    if (classes.includes('privilege_escalation')) return 'critical'
    if (classes.includes('secret_access') || classes.includes('lateral_movement')) return 'high'
    return 'low'
}

const SEVERITY_BADGE: Record<RbacThreatSeverity, ReconFinding['severity']> = {
    critical: 'CRITICAL',
    high: 'HIGH',
    medium: 'WARN',
    low: 'INFO',
}

/**
 * Reasons over a token's effective rules (potentially from multiple namespaces)
 * and, if any are exploitable, builds a threat finding mapping the entry-point pod to its impact.
 * @param entry The pod entry point carrying the token.
 * @param rules Effective rules from the pod's own namespace.
 * @param crossNamespaceRules Map of namespace → rules for namespaces other than the pod's own.
 */
/**
 * Collapses permission blocks that are identical on (apiGroups, resources, verbs)
 * into one entry, unioning their exploit classes. The same effective rule is
 * processed once per namespace scanned, so duplicates are expected and carry no
 * extra information.
 * @param perms Raw permission blocks, possibly containing duplicates.
 */
function dedupePermissions(perms: RbacDangerousPermission[]): RbacDangerousPermission[] {
    const byKey = new Map<string, RbacDangerousPermission>()
    for (const p of perms) {
        const key = JSON.stringify([[...p.apiGroups].sort(), [...p.resources].sort(), [...p.verbs].sort()])
        const existing = byKey.get(key)
        if (existing) {
            for (const c of p.exploitClasses) if (!existing.exploitClasses.includes(c)) existing.exploitClasses.push(c)
        } else {
            byKey.set(key, { ...p, exploitClasses: [...p.exploitClasses] })
        }
    }
    return [...byKey.values()]
}

function buildThreatFinding(
    entry: PodEntryPoint,
    rules: k8s.V1ResourceRule[],
    crossNamespaceRules: Map<string, k8s.V1ResourceRule[]> = new Map(),
): RbacThreatFinding | undefined {
    const dangerous: RbacDangerousPermission[] = []
    const classes = new Set<RbacExploitClass>()
    const reasons: string[] = []
    let crossNamespaceAccess = false

    const processRules = (ruleSet: k8s.V1ResourceRule[]) => {
        for (const rule of ruleSet) {
            const { classes: ruleClasses, reasons: ruleReasons, apiGroups } = classifyRule(rule)
            if (ruleClasses.length === 0) continue
            for (const c of ruleClasses) classes.add(c)
            for (const r of ruleReasons) if (!reasons.includes(r)) reasons.push(r)
            dangerous.push({
                resources: rule.resources ?? ['*'],
                verbs: rule.verbs ?? [],
                apiGroups,
                exploitClasses: ruleClasses,
            })
        }
    }

    processRules(rules)

    for (const [ns, nsRules] of crossNamespaceRules) {
        const before = classes.size
        processRules(nsRules)
        if (classes.size > before) {
            crossNamespaceAccess = true
            reasons.push(`cross-namespace access detected in ns '${ns}'`)
        }
    }

    // Only identities that enable at least one exploit class are findings.
    if (classes.size === 0) return undefined

    // Collapse identical permission blocks. The same rule is processed once per
    // namespace (own + each cross-namespace set), so without this the array
    // repeats verbatim — the single largest source of bloat in the artifact.
    const dedupedPermissions = dedupePermissions(dangerous)

    const exploitClasses = [...classes]
    const origin = entry.pod === '<none — orphaned secret>'
        ? `Orphaned SA token secret for '${entry.serviceAccount}' (ns ${entry.namespace})`
        : `Exec into ${entry.pod} (ns ${entry.namespace}) → harvest '${entry.serviceAccount}' SA token`
    const attackChain = `${origin} → ${reasons.join('; ')}`

    return {
        pod: entry.pod,
        namespace: entry.namespace,
        serviceAccount: entry.serviceAccount,
        automountToken: entry.automountToken,
        tokenHarvested: true,
        exploitClasses,
        dangerousPermissions: dedupedPermissions,
        attackChain,
        severity: severityFor(exploitClasses),
        crossNamespaceAccess,
    }
}

/**
 * Fingerprints a harvested token's effective permissions in the given namespace
 * via SelfSubjectRulesReview — ground truth that accounts for every binding and
 * aggregated role without needing direct RBAC API access.
 * Returns an empty array on any error so a single namespace failure never aborts a survey.
 */
async function reviewRules(base: k8s.KubeConfig, token: string, namespace: string): Promise<k8s.V1ResourceRule[]> {
    try {
        const authz = authorizationV1Api(kubeConfigWithToken(base, token))
        const review = await authz.createSelfSubjectRulesReview({
            body: {
                apiVersion: 'authorization.k8s.io/v1',
                kind: 'SelfSubjectRulesReview',
                spec: { namespace },
            },
        })
        return review.status?.resourceRules ?? []
    } catch {
        return []
    }
}

/**
 * Extracts projected service account token mount paths from a pod spec.
 * Covers pods using IRSA, Workload Identity, or other projected volume token patterns
 * that mount tokens at paths other than the default TOKEN_PATH.
 */
function extractProjectedTokenPaths(pod: k8s.V1Pod): string[] {
    const paths: string[] = []
    for (const volume of pod.spec?.volumes ?? []) {
        const tokenSource = (volume.projected?.sources ?? []).find(s => s.serviceAccountToken?.path)
        if (!tokenSource?.serviceAccountToken?.path) continue
        for (const container of pod.spec?.containers ?? []) {
            const mount = container.volumeMounts?.find(m => m.name === volume.name)
            if (mount) paths.push(`${mount.mountPath}/${tokenSource.serviceAccountToken!.path}`)
        }
    }
    return paths
}

/**
 * Pod-first RBAC recon: enumerates running pods, harvests each mounted
 * ServiceAccount token via exec, fingerprints its effective permissions, and
 * flags exploitable privilege chains. See docs/rbac-command.md.
 * @param kc Loaded kubeconfig — used both to list/exec pods and to interrogate harvested tokens.
 * @param options Recon options; includeSystem pulls in system namespaces (off by default).
 */
export function surveyRbac(kc: k8s.KubeConfig, options: ReconOptions): Promise<ReconToolResult> {
    const core = coreV1Api(kc)

    return reconWrapper('rbac', {
        title: 'RBAC recon skipped',
        detail: 'Cannot list pods cluster-wide — insufficient permissions',
        missingPermission: 'list pods (all namespaces)',
        coverageImpact: 'ServiceAccount privilege chains cannot be discovered',
    }, async () => {
        const pods = (await core.listPodForAllNamespaces()).items

        // Reachable entry points: running pods, optionally excluding system namespaces.
        const entries: PodEntryPoint[] = pods
            .filter(p => p.status?.phase === 'Running')
            .filter(p => options.includeSystem || !SYSTEM_NAMESPACES.has(p.metadata?.namespace ?? ''))
            .map(p => ({
                pod: p.metadata?.name ?? '',
                namespace: p.metadata?.namespace ?? '',
                serviceAccount: p.spec?.serviceAccountName ?? 'default',
                // automountServiceAccountToken defaults to true unless explicitly disabled.
                automountToken: p.spec?.automountServiceAccountToken !== false,
                container: p.spec?.containers?.[0]?.name ?? '',
                projectedTokenPaths: extractProjectedTokenPaths(p),
            }))
            .filter(e => e.pod && e.container)

        // Collect all unique pod namespaces upfront for cross-namespace review.
        const allPodNamespaces = [...new Set(entries.map(e => e.namespace))]

        const findings: RbacThreatFinding[] = []
        const blindSpots: string[] = []
        const seenIdentities = new Set<string>()
        let tokensHarvested = 0

        for (const entry of entries) {
            // One identity per (namespace, ServiceAccount) — replicas add noise, not signal.
            const identityKey = `${entry.namespace}/${entry.serviceAccount}`
            if (seenIdentities.has(identityKey)) continue
            seenIdentities.add(identityKey)

            if (!entry.automountToken) {
                blindSpots.push(`${identityKey}: automountServiceAccountToken disabled — no token to harvest from ${entry.pod}`)
                continue
            }

            try {
                // Try the default path first, then any projected volume token paths found in the pod spec.
                let token = ''
                for (const path of [TOKEN_PATH, ...entry.projectedTokenPaths]) {
                    const { stdout, exitCode } = await execInPod(kc, entry.namespace, entry.pod, entry.container, ['cat', path])
                    if (exitCode === 0 && stdout.trim()) { token = stdout.trim(); break }
                }

                if (!token) {
                    blindSpots.push(`${identityKey}: token not readable in ${entry.pod} (tried default and ${entry.projectedTokenPaths.length} projected path(s))`)
                    continue
                }
                tokensHarvested++

                // Review in the pod's own namespace.
                const homeRules = await reviewRules(kc, token, entry.namespace)

                // Review in every other pod namespace to catch cross-namespace RoleBindings.
                const crossNamespaceRules = new Map<string, k8s.V1ResourceRule[]>()
                for (const ns of allPodNamespaces) {
                    if (ns === entry.namespace) continue
                    const nsRules = await reviewRules(kc, token, ns)
                    if (nsRules.length > 0) crossNamespaceRules.set(ns, nsRules)
                }

                const finding = buildThreatFinding(entry, homeRules, crossNamespaceRules)
                if (finding) findings.push(finding)
            } catch (err) {
                // A single pod failing must never abort the survey (recon design rule).
                blindSpots.push(`${identityKey}: recon failed on ${entry.pod} — ${err instanceof Error ? err.message : String(err)}`)
            }
        }

        // Enumerate orphaned SA token secrets — long-lived pre-1.24 tokens not mounted in any running pod.
        try {
            const secrets = (await core.listSecretForAllNamespaces()).items
                .filter(s => s.type === 'kubernetes.io/service-account-token')

            for (const secret of secrets) {
                const ns = secret.metadata?.namespace ?? ''
                const sa = secret.metadata?.annotations?.['kubernetes.io/service-account.name'] ?? ''
                if (!ns || !sa) continue

                const identityKey = `${ns}/${sa}`
                if (seenIdentities.has(identityKey)) continue
                seenIdentities.add(identityKey)

                const rawToken = secret.data?.['token']
                if (!rawToken) continue

                const token = Buffer.from(rawToken, 'base64').toString('utf8')
                tokensHarvested++

                const homeRules = await reviewRules(kc, token, ns)
                const crossNamespaceRules = new Map<string, k8s.V1ResourceRule[]>()
                for (const podNs of allPodNamespaces) {
                    if (podNs === ns) continue
                    const nsRules = await reviewRules(kc, token, podNs)
                    if (nsRules.length > 0) crossNamespaceRules.set(podNs, nsRules)
                }

                const fakeEntry: PodEntryPoint = {
                    pod: '<none — orphaned secret>',
                    namespace: ns,
                    serviceAccount: sa,
                    automountToken: false,
                    container: '',
                    projectedTokenPaths: [],
                }
                const finding = buildThreatFinding(fakeEntry, homeRules, crossNamespaceRules)
                if (finding) findings.push(finding)
            }
        } catch {
            blindSpots.push('SA token secrets: insufficient permission to list secrets cluster-wide — orphaned long-lived tokens not checked')
        }

        // Honest about what pod-first recon structurally cannot see.
        blindSpots.push('Roles not bound to any running pod and without a long-lived token secret are out of scope.')

        // Surface the most severe chains first.
        const order: RbacThreatSeverity[] = ['critical', 'high', 'medium', 'low']
        findings.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity))

        const graph: RbacThreatGraph = {
            podsScanned: entries.length,
            tokensHarvested,
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
function toReconFindings(graph: RbacThreatGraph): ReconFinding[] {
    if (graph.findings.length === 0) {
        return [{
            severity: 'INFO',
            title: `No exploitable privilege chains found across ${graph.podsScanned} reachable pod(s)`,
            detail: `${graph.tokensHarvested} ServiceAccount token(s) interrogated; none granted a flagged exploit class.`,
        }]
    }

    return graph.findings.map(f => ({
        severity: SEVERITY_BADGE[f.severity],
        title: `${f.pod} → ${f.serviceAccount} (${f.exploitClasses.join(', ')})`,
        detail: f.attackChain,
    }))
}
