import * as k8s from '@kubernetes/client-node'
import { coreV1Api, networkingV1Api } from '../kube/client.js'
import { isForbidden } from '../kube/errors.js'
import type { ReconFinding, ReconOptions, ReconToolResult } from '../../types/recon.js'

export interface NamespaceNetworkStatus {
    namespace: string
    policyCount: number
    hasIngress: boolean
    hasEgress: boolean
}

// Kube generated namespaces to ignore
const SYSTEM_NAMESPACES = new Set(['kube-system', 'kube-public', 'kube-node-lease'])

function analyze(namespaces: NamespaceNetworkStatus[]): ReconFinding[] {
    const findings: ReconFinding[] = []
    const unprotected = namespaces.filter(n => n.policyCount === 0)
    const ingressOnly = namespaces.filter(n => n.policyCount > 0 && !n.hasEgress)

    // Raise to HIGH when 'default' is unprotected.
    if (unprotected.length > 0) findings.push({
        severity: unprotected.some(n => n.namespace === 'default') ? 'HIGH' : 'WARN',
        title: `${unprotected.length} namespace(s) have no NetworkPolicies`,
        detail: `All pod-to-pod traffic is unrestricted in: ${unprotected.map(n => n.namespace).join(', ')}`,
    })

    if (ingressOnly.length > 0) findings.push({
        severity: 'WARN',
        title: `${ingressOnly.length} namespace(s) have no egress NetworkPolicies`,
        detail: `Outbound traffic is unrestricted in: ${ingressOnly.map(n => n.namespace).join(', ')}`,
    })

    // Positively confirm full coverage when no gaps are found.
    if (unprotected.length === 0 && ingressOnly.length === 0 && namespaces.length > 0) findings.push({
        severity: 'INFO',
        title: 'All user namespaces have NetworkPolicies with ingress and egress rules',
        detail: 'Network segmentation is in place across all non-system namespaces',
    })

    return findings
}

/**
 * Surveys NetworkPolicy coverage across all user namespaces.
 * @param kc Loaded kubeconfig to use for all API calls.
 * @param options Recon options containing namespace and optional context.
 */
export async function surveyNetworkPolicies(kc: k8s.KubeConfig, options: ReconOptions): Promise<ReconToolResult> {
    const networking = networkingV1Api(kc)
    const core = coreV1Api(kc)

    try {
        // Fetch policies and namespaces in parallel to reduce latency.
        const [policiesRes, namespacesRes] = await Promise.all([
            networking.listNetworkPolicyForAllNamespaces(),
            core.listNamespace(),
        ])

        // Extract non-empty namespace names, excluding system namespaces.
        const userNamespaces = namespacesRes.items
            .map(n => n.metadata?.name ?? '')
            .filter(n => n && !SYSTEM_NAMESPACES.has(n))

        // Insert all user namespaces into map so those with zero policies are not silently omitted.
        const byNamespace = new Map<string, k8s.V1NetworkPolicy[]>()
        for (const ns of userNamespaces) byNamespace.set(ns, [])
        for (const policy of policiesRes.items) {
            const ns = policy.metadata?.namespace ?? ''
            if (!SYSTEM_NAMESPACES.has(ns)) byNamespace.set(ns, [...(byNamespace.get(ns) ?? []), policy])
        }

        // Build a status object per namespace summarizing policy count and ingress/egress coverage.
        const namespaces: NamespaceNetworkStatus[] = [...byNamespace.entries()].map(([ns, policies]) => ({
            namespace: ns,
            policyCount: policies.length,
            // A policy with no policyTypes defaults to Ingress.
            hasIngress: policies.some(p => {
                const types = p.spec?.policyTypes ?? []
                return types.includes('Ingress') || types.length === 0
            }),
            hasEgress: policies.some(p => (p.spec?.policyTypes ?? []).includes('Egress')),
        }))

        return { tool: 'network-policies', status: 'ok', findings: analyze(namespaces), data: { namespaces } }
    } catch (err) {
        // Return status for error
        if (isForbidden(err)) {
            return {
                tool: 'network-policies',
                status: 'skip',
                findings: [{
                    severity: 'SKIP',
                    title: 'Network policy recon skipped',
                    detail: 'Cannot list NetworkPolicies cluster-wide — insufficient permissions',
                    missingPermission: 'list networkpolicies (all namespaces)',
                    coverageImpact: 'Network segmentation gaps cannot be identified',
                }],
                data: {},
            }
        }
        return { tool: 'network-policies', status: 'error', findings: [], data: { error: err instanceof Error ? err.message : String(err) } }
    }
}
