import * as k8s from '@kubernetes/client-node'
import { isForbidden, isNotFound } from '../kube/errors.js'
import type { ReconFinding, ReconOptions, ReconToolResult } from '../../types/recon.js'

export type PolicyEngine = 'kyverno' | 'gatekeeper' | 'none'

export interface PolicyInfo {
    name: string
    engine: PolicyEngine
    /** 'Enforce' | 'Audit' for Kyverno; Gatekeeper does not surface this field. */
    validationFailureAction?: string
}

interface EngineProbeResult {
    installed: boolean
    permissionDenied: boolean
    policies: PolicyInfo[]
}

// Probes Kyverno ClusterPolicies to confirm installation and enumerate enforcement modes.
async function probeKyverno(kc: k8s.KubeConfig): Promise<EngineProbeResult> {
    const customApi = kc.makeApiClient(k8s.CustomObjectsApi)
    try {
        const response = await customApi.listClusterCustomObject({
            group: 'kyverno.io',
            version: 'v1',
            plural: 'clusterpolicies',
        }) as { items?: unknown[] }

        // Map each ClusterPolicy to a flat PolicyInfo, capturing the enforcement action.
        const policies: PolicyInfo[] = (response.items ?? []).map((item: unknown) => {
            const obj = item as Record<string, unknown>
            const spec = obj['spec'] as Record<string, unknown> | undefined
            const meta = obj['metadata'] as Record<string, unknown> | undefined
            return {
                name: meta?.['name'] as string ?? 'unknown',
                engine: 'kyverno',
                validationFailureAction: spec?.['validationFailureAction'] as string | undefined,
            }
        })

        return { installed: true, permissionDenied: false, policies }
    } catch (err) {
        // 404 Kyverno engine is absent.
        if (isNotFound(err)) return { installed: false, permissionDenied: false, policies: [] }
        // 403 lack read permission for its policies.
        if (isForbidden(err)) return { installed: true, permissionDenied: true, policies: [] }
        return { installed: false, permissionDenied: false, policies: [] }
    }
}

// Probes Gatekeeper ConstraintTemplates to confirm installation and count constraints.
async function probeGatekeeper(kc: k8s.KubeConfig): Promise<EngineProbeResult> {
    const customApi = kc.makeApiClient(k8s.CustomObjectsApi)
    try {
        const response = await customApi.listClusterCustomObject({
            group: 'constraints.gatekeeper.sh',
            version: 'v1beta1',
            plural: 'constrainttemplates',
        }) as { items?: unknown[] }

        // Map each ConstraintTemplate to a flat PolicyInfo.
        const policies: PolicyInfo[] = (response.items ?? []).map((item: unknown) => {
            const obj = item as Record<string, unknown>
            const meta = obj['metadata'] as Record<string, unknown> | undefined
            return {
                name: meta?.['name'] as string ?? 'unknown',
                engine: 'gatekeeper',
            }
        })

        return { installed: true, permissionDenied: false, policies }
    } catch (err) {
        if (isNotFound(err)) return { installed: false, permissionDenied: false, policies: [] }
        if (isForbidden(err)) return { installed: true, permissionDenied: true, policies: [] }
        return { installed: false, permissionDenied: false, policies: [] }
    }
}

/**
 * Detects which policy engine is installed and surveys enforcement modes for audit-only gaps.
 * @param kc Loaded kubeconfig to use for all API calls.
 * @param options Recon options; `options.engine` forces kyverno, gatekeeper, or auto-detection.
 */
export async function surveyPolicies(kc: k8s.KubeConfig, options: ReconOptions): Promise<ReconToolResult> {
    const engineOverride = options.engine ?? 'auto'
    const findings: ReconFinding[] = []
    const policies: PolicyInfo[] = []
    let detectedEngine: PolicyEngine = 'none'

    // Probe Kyverno first in auto mode; skip if the operator forced a different engine.
    if (engineOverride === 'auto' || engineOverride === 'kyverno') {
        const result = await probeKyverno(kc)
        if (result.installed) {
            detectedEngine = 'kyverno'
            policies.push(...result.policies)
            if (result.permissionDenied) {
                findings.push({
                    severity: 'SKIP',
                    title: 'Kyverno policy read skipped',
                    detail: 'Kyverno is installed but clusterpolicies cannot be listed — insufficient permissions',
                    missingPermission: 'list clusterpolicies.kyverno.io',
                    coverageImpact: 'Kyverno policy enforcement modes cannot be assessed',
                })
            }
        }
    }

    // Only probe Gatekeeper if Kyverno was not found (in auto mode) or if explicitly forced.
    if (detectedEngine === 'none' && (engineOverride === 'auto' || engineOverride === 'gatekeeper')) {
        const result = await probeGatekeeper(kc)
        if (result.installed) {
            detectedEngine = 'gatekeeper'
            policies.push(...result.policies)
            if (result.permissionDenied) {
                findings.push({
                    severity: 'SKIP',
                    title: 'Gatekeeper constraint read skipped',
                    detail: 'Gatekeeper is installed but constrainttemplates cannot be listed — insufficient permissions',
                    missingPermission: 'list constrainttemplates.constraints.gatekeeper.sh',
                    coverageImpact: 'Gatekeeper constraint coverage cannot be assessed',
                })
            }
        }
    }

    if (detectedEngine === 'none') {
        // No engine is a CRITICAL gap — all preventive-baseline scenarios will likely be SKIPPED.
        findings.push({
            severity: 'CRITICAL',
            title: 'No policy engine detected',
            detail: 'Kyverno and OPA/Gatekeeper are not installed. The cluster has no admission-level policy enforcement beyond built-in PSA. All preventive-baseline scenarios will likely be SKIPPED.',
        })
    } else if (policies.length > 0) {
        // Each audit-only policy logs violations but admits non-compliant resources — flag individually.
        const auditOnly = policies.filter(p => p.validationFailureAction?.toLowerCase() === 'audit')
        for (const p of auditOnly) {
            findings.push({
                severity: 'WARN',
                title: `${p.name} is in Audit mode`,
                detail: 'Violations are logged but non-compliant workloads are admitted — this policy does not block anything',
            })
        }
        if (auditOnly.length === 0) {
            findings.push({
                severity: 'INFO',
                title: `${policies.length} ${detectedEngine} policy/policies detected — all in Enforce mode`,
                detail: 'All policies are actively blocking non-compliant resources',
            })
        }
    }

    // Status is 'skip' only when a permission error prevented all policy reads.
    const isSkipped = findings.some(f => f.severity === 'SKIP') && policies.length === 0
    return { tool: 'policies', status: isSkipped ? 'skip' : 'ok', findings, data: { engine: detectedEngine, policies } }
}
