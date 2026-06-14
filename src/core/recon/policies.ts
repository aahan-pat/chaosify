import * as k8s from '@kubernetes/client-node'
import { isForbidden, isNotFound } from '../kube/errors.js'
import type {
    ReconFinding,
    ReconOptions,
    ReconToolResult,
    PolicyEngine,
    PolicyInfo,
    PolicyThreatFinding,
    PolicyThreatGraph,
    PolicyThreatSeverity,
} from '../../types/recon.js'

// Re-exported for callers that still import these from this module.
export type { PolicyEngine, PolicyInfo } from '../../types/recon.js'

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

const SEVERITY_BADGE: Record<PolicyThreatSeverity, ReconFinding['severity']> = {
    critical: 'CRITICAL',
    high: 'HIGH',
    medium: 'WARN',
    low: 'INFO',
}

// An Audit-mode policy logs violations but admits the workloads it claims to govern — a confirmed bypass.
function classifyAuditPolicy(p: PolicyInfo): PolicyThreatFinding {
    return {
        policy: p.name,
        engine: p.engine,
        exploitClasses: ['admission_bypass'],
        impact: `${p.name} is in Audit mode → violations are logged but non-compliant workloads are still admitted. For the rules this policy covers, the cluster behaves as if it had no policy at all.`,
        suggestedProbe: `probe run --pack preventive-baseline`,
        severity: 'high',
    }
}

/**
 * Projects the threat graph into the shared ReconFinding shape. The no-engine state is a
 * cluster-level CRITICAL; each Audit-mode policy is an individual scored bypass; an all-Enforce
 * engine is a positive INFO. SKIP findings from permission denial are prepended by the caller.
 */
function toReconFindings(graph: PolicyThreatGraph): ReconFinding[] {
    if (graph.engine === 'none') {
        return [{
            severity: 'CRITICAL',
            title: 'No policy engine detected',
            detail: 'Kyverno and OPA/Gatekeeper are not installed. The cluster has no admission-level policy enforcement beyond built-in PSA. All preventive-baseline scenarios will likely be SKIPPED — cross-reference recon psa and recon webhooks.',
        }]
    }

    // Engine present but no policies readable (e.g. permission denied) — the SKIP finding carries the signal.
    if (graph.policiesScanned === 0) return []

    if (graph.findings.length > 0) {
        return graph.findings.map(f => ({
            severity: SEVERITY_BADGE[f.severity],
            title: `${f.policy} is in Audit mode (${f.exploitClasses.join(', ')})`,
            detail: f.impact,
        }))
    }

    return [{
        severity: 'INFO',
        title: `${graph.policiesScanned} ${graph.engine} policy/policies detected — all in Enforce mode`,
        detail: 'All policies are actively blocking non-compliant resources.',
    }]
}

/**
 * Detects which policy engine is installed and scores enforcement-mode gaps as admission-bypass paths.
 * @param kc Loaded kubeconfig to use for all API calls.
 * @param options Recon options; `options.engine` forces kyverno, gatekeeper, or auto-detection.
 */
export async function surveyPolicies(kc: k8s.KubeConfig, options: ReconOptions): Promise<ReconToolResult> {
    const engineOverride = options.engine ?? 'auto'
    const skipFindings: ReconFinding[] = []
    const policies: PolicyInfo[] = []
    let detectedEngine: PolicyEngine = 'none'

    // Probe Kyverno first in auto mode; skip if the operator forced a different engine.
    if (engineOverride === 'auto' || engineOverride === 'kyverno') {
        const result = await probeKyverno(kc)
        if (result.installed) {
            detectedEngine = 'kyverno'
            policies.push(...result.policies)
            if (result.permissionDenied) skipFindings.push({
                severity: 'SKIP',
                title: 'Kyverno policy read skipped',
                detail: 'Kyverno is installed but clusterpolicies cannot be listed — insufficient permissions',
                missingPermission: 'list clusterpolicies.kyverno.io',
                coverageImpact: 'Kyverno policy enforcement modes cannot be assessed',
            })
        }
    }

    // Only probe Gatekeeper if Kyverno was not found (in auto mode) or if explicitly forced.
    if (detectedEngine === 'none' && (engineOverride === 'auto' || engineOverride === 'gatekeeper')) {
        const result = await probeGatekeeper(kc)
        if (result.installed) {
            detectedEngine = 'gatekeeper'
            policies.push(...result.policies)
            if (result.permissionDenied) skipFindings.push({
                severity: 'SKIP',
                title: 'Gatekeeper constraint read skipped',
                detail: 'Gatekeeper is installed but constrainttemplates cannot be listed — insufficient permissions',
                missingPermission: 'list constrainttemplates.constraints.gatekeeper.sh',
                coverageImpact: 'Gatekeeper constraint coverage cannot be assessed',
            })
        }
    }

    // Each Audit-mode policy is a confirmed admission-bypass path.
    const findings: PolicyThreatFinding[] = policies
        .filter(p => p.validationFailureAction?.toLowerCase() === 'audit')
        .map(classifyAuditPolicy)

    const blindSpots = [
        'Policy rule scope is not simulated — this survey reads enforcement *mode*, not which workloads each policy matches. An Enforce-mode policy scoped to the wrong namespaces or resources still leaves gaps. Confirm with probe run.',
        'Kyverno background scans report violations on already-running pods but do not block them; only admission-time enforcement (Enforce mode) prevents creation.',
        'Gatekeeper enforcementAction (deny/dryrun/warn) lives on individual Constraints, not the ConstraintTemplates probed here — Gatekeeper dryrun constraints are not flagged.',
        'Namespaced Kyverno Policies and Gatekeeper Constraint instances are not enumerated — engine presence does not prove cluster-wide coverage. A policy engine may also overlap PSA; cross-reference recon psa and recon webhooks.',
    ]

    const graph: PolicyThreatGraph = {
        engine: detectedEngine,
        policiesScanned: policies.length,
        findings,
        policies,
        blindSpots,
    }

    const reconFindings = [...skipFindings, ...toReconFindings(graph)]

    // Status is 'skip' only when a permission error prevented all policy reads.
    const isSkipped = skipFindings.length > 0 && policies.length === 0
    return { tool: 'policies', status: isSkipped ? 'skip' : 'ok', findings: reconFindings, data: graph }
}
