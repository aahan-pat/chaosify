import * as k8s from '@kubernetes/client-node'
import { coreV1Api } from '../kube/client.js'
import { reconWrapper, SYSTEM_NAMESPACES } from '../utils/recon.js'
import type { ReconFinding, ReconOptions, ReconToolResult } from '../../types/recon.js'

export type PsaLevel = 'privileged' | 'baseline' | 'restricted'

export interface NamespacePsaStatus {
    namespace: string
    enforce?: PsaLevel
    audit?: PsaLevel
    warn?: PsaLevel
    isSystem: boolean
}

// Extracts the PSA label triplet from a namespace and flags system namespaces.
function extractPsaStatus(ns: k8s.V1Namespace): NamespacePsaStatus {
    const name = ns.metadata?.name ?? ''
    const labels = ns.metadata?.labels ?? {}
    return {
        namespace: name,
        enforce: labels['pod-security.kubernetes.io/enforce'] as PsaLevel | undefined,
        audit: labels['pod-security.kubernetes.io/audit'] as PsaLevel | undefined,
        warn: labels['pod-security.kubernetes.io/warn'] as PsaLevel | undefined,
        isSystem: SYSTEM_NAMESPACES.has(name),
    }
}

function analyze(namespaces: NamespacePsaStatus[]): ReconFinding[] {
    const findings: ReconFinding[] = []
    const userNamespaces = namespaces.filter(n => !n.isSystem)

    // Namespaces with no labels have completely unenforced pod security.
    const noLabels = userNamespaces.filter(n => !n.enforce && !n.audit && !n.warn)
    // Namespaces with only audit/warn labels log violations but still admit non-compliant pods.
    const auditOnly = userNamespaces.filter(n => !n.enforce && (n.audit || n.warn))

    if (noLabels.length > 0) findings.push({
        severity: 'WARN',
        title: `${noLabels.length} user namespace(s) have no PSA labels`,
        detail: `Pod security is entirely unenforced in: ${noLabels.map(n => n.namespace).join(', ')}`,
    })

    if (auditOnly.length > 0) findings.push({
        severity: 'WARN',
        title: `${auditOnly.length} namespace(s) have PSA in audit/warn mode only`,
        detail: `No enforce label — violations are logged but non-compliant pods are admitted: ${auditOnly.map(n => n.namespace).join(', ')}`,
    })

    // Confirm secure posture when all user namespaces carry an enforce label.
    if (noLabels.length === 0 && auditOnly.length === 0 && userNamespaces.length > 0) findings.push({
        severity: 'INFO',
        title: 'All user namespaces have PSA enforce labels',
        detail: 'Pod Security Admission enforcement is active across all non-system namespaces',
    })

    return findings
}

/**
 * Surveys Pod Security Admission labels across all namespaces to identify enforcement gaps.
 * @param kc Loaded kubeconfig to use for all API calls.
 * @param options Recon options containing namespace and optional context.
 */
export function surveyPsa(kc: k8s.KubeConfig, options: ReconOptions): Promise<ReconToolResult> {
    const core = coreV1Api(kc)
    return reconWrapper('psa', {
        title: 'PSA recon skipped',
        detail: 'Cannot list namespaces — insufficient permissions',
        missingPermission: 'list namespaces',
        coverageImpact: 'Pod Security Admission label coverage cannot be assessed',
    }, async () => {
        const namespaces = (await core.listNamespace()).items.map(extractPsaStatus)
        return { findings: analyze(namespaces), data: { namespaces } }
    })
}
