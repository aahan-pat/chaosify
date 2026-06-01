import * as k8s from '@kubernetes/client-node'
import { coreV1Api, rbacV1Api } from '../kube/client.js'
import { isConflict } from '../kube/errors.js'
import { runStep, type Step } from '../utils/step.js'
import type { ReconOptions } from '../../types/recon.js'

export interface InitResult {
    clusterContext: string
    namespace: string
    steps: Step[]
    alreadyExisted: boolean
}

// Applies the ResourceQuota, patching on 409 to keep limits current, then re-throws so runStep() maps it to already-existed.
async function applyQuota(core: k8s.CoreV1Api, namespace: string): Promise<void> {
    const body: k8s.V1ResourceQuota = {
        metadata: { name: 'chaosclaw-quota', namespace },
        spec: { hard: { pods: '10', 'requests.cpu': '2', 'requests.memory': '2Gi', 'limits.cpu': '4', 'limits.memory': '4Gi' } }
    }
    try {
        await core.createNamespacedResourceQuota({ namespace, body })
    } catch (err) {
        if (isConflict(err)) {
            await core.replaceNamespacedResourceQuota({ name: 'chaosclaw-quota', namespace, body }).catch(() => {})
        }
        throw err
    }
}

/**
 * Creates the chaosclaw namespace and applies RBAC scoping. Idempotent.
 * @param kc Loaded kubeconfig to use for all API calls.
 * @param options Recon options containing namespace and optional context.
 */
export async function initNamespace(kc: k8s.KubeConfig, options: ReconOptions): Promise<InitResult> {
    const ns = options.namespace
    // Create API clients once and share across all setup steps.
    const core = coreV1Api(kc)
    const rbac = rbacV1Api(kc)

    const nsStep = await runStep(`Namespace ${ns}`, () =>
        core.createNamespace({ body: { metadata: { name: ns } } }).then(() => {})
    )

    // All subsequent steps depend on the namespace existing.
    if (nsStep.status === 'failed') {
        return { clusterContext: kc.getCurrentContext(), namespace: ns, steps: [nsStep], alreadyExisted: false }
    }

    // Run remaining setup steps in dependency order — quota, identity, then RBAC binding.
    const steps: Step[] = [
        nsStep,
        await runStep('ResourceQuota', () => applyQuota(core, ns)),
        await runStep('ServiceAccount chaosclaw-runner', () =>
            core.createNamespacedServiceAccount({
                namespace: ns,
                body: { metadata: { name: 'chaosclaw-runner', namespace: ns } }
            }).then(() => {})
        ),
        await runStep('Role chaosclaw-runner', () =>
            rbac.createNamespacedRole({
                namespace: ns,
                body: {
                    metadata: { name: 'chaosclaw-runner', namespace: ns },
                    rules: [{ apiGroups: [''], resources: ['pods', 'pods/exec', 'pods/log'], verbs: ['get', 'list', 'create', 'delete'] }]
                }
            }).then(() => {})
        ),
        await runStep('RoleBinding chaosclaw-runner', () =>
            rbac.createNamespacedRoleBinding({
                namespace: ns,
                body: {
                    metadata: { name: 'chaosclaw-runner', namespace: ns },
                    subjects: [{ kind: 'ServiceAccount', name: 'chaosclaw-runner', namespace: ns }],
                    roleRef: { apiGroup: 'rbac.authorization.k8s.io', kind: 'Role', name: 'chaosclaw-runner' }
                }
            }).then(() => {})
        ),
    ]

    return { clusterContext: kc.getCurrentContext(), namespace: ns, steps, alreadyExisted: nsStep.status === 'already-existed' }
}
