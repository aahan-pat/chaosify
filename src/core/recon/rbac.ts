import * as k8s from '@kubernetes/client-node'
import { rbacV1Api } from '../kube/client.js'
import { isForbidden } from '../kube/errors.js'
import { SYSTEM_NAMESPACES } from '../utils/recon.js'
import type { ReconFinding, ReconOptions, ReconToolResult } from '../../types/recon.js'

function analyze(
    roles: k8s.V1ClusterRole[],
    bindings: k8s.V1ClusterRoleBinding[],
    includeSystem: boolean,
): ReconFinding[] {
    const findings: ReconFinding[] = []

    // Flag non-built-in bindings that grant cluster-admin, skipping the default binding every cluster ships with.
    const adminBindings = bindings.filter(b => b.roleRef.name === 'cluster-admin' && b.metadata?.name !== 'cluster-admin')
    for (const binding of adminBindings) {
        const subjects = (binding.subjects ?? [])
            .filter(s => includeSystem || !SYSTEM_NAMESPACES.has(s.namespace ?? ''))
            .map(s => `${s.kind}: ${s.name}${s.namespace ? ` (${s.namespace})` : ''}`)
            .join(', ')
        // Groups and Users get HIGH — any member gains unrestricted cluster access.
        // ServiceAccounts stay WARN — scoped to a single workload identity.
        if (subjects) {
            const hasGroupOrUser = (binding.subjects ?? [])
                .filter(s => includeSystem || !SYSTEM_NAMESPACES.has(s.namespace ?? ''))
                .some(s => s.kind === 'Group' || s.kind === 'User')
            findings.push({
                severity: hasGroupOrUser ? 'HIGH' : 'WARN',
                title: 'cluster-admin bound to non-system principal(s)',
                detail: `${subjects} — via ClusterRoleBinding "${binding.metadata?.name}"`,
            })
        }
    }

    // Build a role lookup so binding resolution doesn't require a linear scan per binding.
    const roleMap = new Map(roles.map(r => [r.metadata?.name ?? '', r]))
    for (const binding of bindings) {
        const role = roleMap.get(binding.roleRef.name)
        if (!role) continue

        // A rule grants broad secret read when it covers secrets (or *), covers a read verb, and is not scoped to specific names.
        const hasClusterWideSecretRead = (role.rules ?? []).some(rule => {
            const resources = rule.resources ?? []
            const verbs = rule.verbs ?? []
            const coversSecrets = resources.includes('secrets') || resources.includes('*')
            const coversRead = verbs.some(v => ['get', 'list', 'watch', '*'].includes(v))
            return coversSecrets && coversRead && !rule.resourceNames?.length
        })

        if (!hasClusterWideSecretRead) continue

        // Emit a HIGH finding per non-system service account holding this privilege.
        const serviceAccounts = (binding.subjects ?? [])
            .filter(s => s.kind === 'ServiceAccount')
            .filter(s => includeSystem || !SYSTEM_NAMESPACES.has(s.namespace ?? ''))

        for (const sa of serviceAccounts) {
            findings.push({
                severity: 'HIGH',
                title: `${sa.namespace ?? '?'}/${sa.name} has cluster-wide secret read access`,
                detail: `Via ClusterRoleBinding "${binding.metadata?.name}" → ClusterRole "${role.metadata?.name}". A compromised token exposes all secrets in all namespaces.`,
            })
        }
    }

    return findings
}

/**
 * Surveys RBAC posture: cluster-admin bindings and service accounts with cluster-wide secret read.
 * @param kc Loaded kubeconfig to use for all API calls.
 * @param options Recon options; `options.includeSystem` includes kube-system accounts in findings.
 */
export async function surveyRbac(kc: k8s.KubeConfig, options: ReconOptions): Promise<ReconToolResult> {
    const rbac = rbacV1Api(kc)
    const includeSystem = options.includeSystem ?? false

    let roles: k8s.V1ClusterRole[] = []
    let bindings: k8s.V1ClusterRoleBinding[] = []
    const skipFindings: ReconFinding[] = []

    // Fetch roles and bindings independently — partial results are still useful for analysis.
    try {
        roles = (await rbac.listClusterRole()).items
    } catch (err) {
        if (isForbidden(err)) skipFindings.push({
            severity: 'SKIP',
            title: 'ClusterRole list skipped',
            detail: 'Cannot list clusterroles — insufficient permissions',
            missingPermission: 'list clusterroles',
            coverageImpact: 'Available cluster-level privilege definitions cannot be enumerated',
        })
    }

    try {
        bindings = (await rbac.listClusterRoleBinding()).items
    } catch (err) {
        if (isForbidden(err)) skipFindings.push({
            severity: 'SKIP',
            title: 'ClusterRoleBinding list skipped',
            detail: 'Cannot list clusterrolebindings — insufficient permissions',
            missingPermission: 'list clusterrolebindings',
            coverageImpact: 'Who holds cluster-level privileges cannot be determined',
        })
    }

    const analysisFindings = analyze(roles, bindings, includeSystem)
    // Analysis findings first so they appear before permission-skip notices.
    const findings: ReconFinding[] = [...analysisFindings, ...skipFindings]
    const isFullySkipped = skipFindings.length > 0 && analysisFindings.length === 0

    return {
        tool: 'rbac',
        status: isFullySkipped ? 'skip' : 'ok',
        findings,
        data: {
            clusterRoleCount: roles.length,
            clusterRoleBindingCount: bindings.length,
            partial: skipFindings.length > 0,
        },
    }
}
