import * as k8s from '@kubernetes/client-node'
import { admissionregistrationV1Api } from '../kube/client.js'
import { reconWrapper } from '../utils/recon.js'
import type {
    ReconFinding,
    ReconOptions,
    ReconToolResult,
    WebhookInfo,
    WebhookThreatFinding,
    WebhookThreatGraph,
    WebhookThreatSeverity,
} from '../../types/recon.js'

// Re-exported for callers that still import the inventory type from this module.
export type { WebhookInfo } from '../../types/recon.js'

// Determine webhook scope by checking whether a namespace selector constrains it.
function formatScope(selector?: k8s.V1LabelSelector | null): string {
    if (!selector?.matchExpressions?.length && !selector?.matchLabels) return 'cluster-wide'
    return 'namespace-scoped'
}

const SEVERITY_BADGE: Record<WebhookThreatSeverity, ReconFinding['severity']> = {
    critical: 'CRITICAL',
    high: 'HIGH',
    medium: 'WARN',
    low: 'INFO',
}

/**
 * Builds a threat finding for a fail-open webhook. A failurePolicy of Ignore means admission is
 * silently bypassed for the webhook's scope whenever its backend is unreachable — so a cluster-wide
 * fail-open webhook is a wider, higher-severity bypass than a namespace-scoped one.
 */
function classifyFailOpen(wh: WebhookInfo): WebhookThreatFinding {
    const clusterWide = wh.scope === 'cluster-wide'
    return {
        webhook: wh.name,
        type: wh.type,
        scope: wh.scope,
        failurePolicy: wh.failurePolicy,
        ruleCount: wh.ruleCount,
        exploitClasses: ['admission_bypass'],
        impact: `failurePolicy: Ignore → if this ${wh.type} webhook's backend is unreachable, admission is bypassed for its ${wh.scope} scope. An attacker who can disrupt the webhook (or simply deploys during an outage) gets unrestricted admission across ${clusterWide ? 'the whole cluster' : 'its namespaces'}.`,
        // The pack confirms what actually slips through admission today; webhook reachability itself is not probeable from here.
        suggestedProbe: `probe run --pack preventive-baseline`,
        severity: clusterWide ? 'high' : 'medium',
    }
}

/**
 * Projects the threat graph into the shared ReconFinding shape. The two cluster-level states —
 * no webhooks at all, and all webhooks fail-closed — are summary findings; each fail-open webhook
 * is an individual scored finding.
 */
function toReconFindings(graph: WebhookThreatGraph): ReconFinding[] {
    if (graph.webhooksScanned === 0) {
        return [{
            severity: 'HIGH',
            title: 'No admission webhooks detected',
            detail: 'The cluster has no Kyverno, OPA/Gatekeeper, or custom webhook-based admission controls. Enforcement relies entirely on built-in PSA and ResourceQuota — cross-reference recon psa and recon policies.',
        }]
    }

    if (graph.findings.length === 0) {
        return [{
            severity: 'INFO',
            title: `All ${graph.webhooksScanned} admission webhook(s) use failurePolicy: Fail`,
            detail: 'No webhook fails open — admission is denied if a webhook is unreachable.',
        }]
    }

    return graph.findings.map(f => ({
        severity: SEVERITY_BADGE[f.severity],
        title: `${f.webhook} — failurePolicy: Ignore (${f.exploitClasses.join(', ')})`,
        detail: f.impact,
    }))
}

/**
 * Surveys admission webhooks and scores failure-open configurations as admission-bypass paths.
 * @param kc Loaded kubeconfig to use for all API calls.
 * @param options Recon options containing namespace and optional context.
 */
export function surveyWebhooks(kc: k8s.KubeConfig, options: ReconOptions): Promise<ReconToolResult> {
    const admission = admissionregistrationV1Api(kc)
    return reconWrapper('webhooks', {
        title: 'Webhook recon skipped',
        detail: 'Cannot list validatingwebhookconfigurations or mutatingwebhookconfigurations',
        missingPermission: 'list validatingwebhookconfigurations, mutatingwebhookconfigurations',
        coverageImpact: 'Admission controller coverage and failure-open risk cannot be assessed',
    }, async () => {
        // Fetch both webhook types in parallel to reduce total latency.
        const [validatingRes, mutatingRes] = await Promise.all([
            admission.listValidatingWebhookConfiguration(),
            admission.listMutatingWebhookConfiguration(),
        ])

        const webhooks: WebhookInfo[] = []

        // Flatten each WebhookConfiguration (which can contain multiple webhooks) into individual entries.
        for (const config of validatingRes.items)
            for (const wh of config.webhooks ?? [])
                webhooks.push({ name: wh.name, type: 'validating', ruleCount: wh.rules?.length ?? 0, failurePolicy: wh.failurePolicy ?? 'Fail', scope: formatScope(wh.namespaceSelector) })

        for (const config of mutatingRes.items)
            for (const wh of config.webhooks ?? [])
                webhooks.push({ name: wh.name, type: 'mutating', ruleCount: wh.rules?.length ?? 0, failurePolicy: wh.failurePolicy ?? 'Fail', scope: formatScope(wh.namespaceSelector) })

        // Each fail-open webhook is a reachable admission-bypass path; cluster-wide first.
        const findings: WebhookThreatFinding[] = webhooks
            .filter(w => w.failurePolicy === 'Ignore')
            .map(classifyFailOpen)
        const order: WebhookThreatSeverity[] = ['critical', 'high', 'medium', 'low']
        findings.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity))

        const blindSpots = [
            'Webhook backend reachability and health are not tested — a fail-closed webhook whose backend is down blocks all admission (an availability risk), while a fail-open one silently admits everything. Confirm real behaviour with probe run.',
            'Rule introspection is shallow: this survey counts rules but does not evaluate which operations or resources each webhook governs. A fail-closed webhook scoped to irrelevant resources provides no protection.',
            'Absence of webhooks is not absence of admission control, and presence is not proof of coverage — a webhook may duplicate PSA or a policy engine. Cross-reference recon psa and recon policies.',
        ]

        const graph: WebhookThreatGraph = {
            webhooksScanned: webhooks.length,
            findings,
            webhooks,
            blindSpots,
        }

        return { findings: toReconFindings(graph), data: graph }
    })
}
