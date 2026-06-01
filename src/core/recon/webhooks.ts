import * as k8s from '@kubernetes/client-node'
import { admissionregistrationV1Api } from '../kube/client.js'
import { reconWrapper } from '../utils/recon.js'
import type { ReconFinding, ReconOptions, ReconToolResult } from '../../types/recon.js'

export interface WebhookInfo {
    name: string
    type: 'validating' | 'mutating'
    ruleCount: number
    failurePolicy: string
    scope: string
}

// Determine webhook scope by checking whether a namespace selector constrains it.
function formatScope(selector?: k8s.V1LabelSelector | null): string {
    if (!selector?.matchExpressions?.length && !selector?.matchLabels) return 'cluster-wide'
    return 'namespace-scoped'
}

function analyze(webhooks: WebhookInfo[]): ReconFinding[] {
    const findings: ReconFinding[] = []

    // No webhooks at all is HIGH — admission enforcement falls entirely on PSA.
    if (webhooks.length === 0) {
        findings.push({
            severity: 'HIGH',
            title: 'No admission webhooks detected',
            detail: 'The cluster has no Kyverno, OPA/Gatekeeper, or custom webhook-based admission controls. Enforcement relies entirely on built-in PSA and ResourceQuota.',
        })
        return findings
    }

    // A webhook with failurePolicy: Ignore bypasses admission entirely when unreachable.
    const failOpen = webhooks.filter(w => w.failurePolicy === 'Ignore')
    for (const wh of failOpen) findings.push({
        severity: 'HIGH',
        title: `${wh.name} — failurePolicy: Ignore`,
        detail: `If this webhook is unreachable, admission is bypassed for its scope (${wh.scope})`,
    })

    // All webhooks fail closed — confirm secure posture.
    if (failOpen.length === 0) findings.push({
        severity: 'INFO',
        title: 'All admission webhooks use failurePolicy: Fail',
        detail: 'No webhook fails open — admission is denied if a webhook is unreachable',
    })

    return findings
}

/**
 * Surveys admission webhooks and identifies failure-open configurations.
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

        return { findings: analyze(webhooks), data: { webhooks } }
    })
}
