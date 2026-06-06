import * as k8s from '@kubernetes/client-node'
import { coreV1Api, rbacV1Api } from '../kube/client.js'
import { isConflict } from '../kube/errors.js'
import { runStep, type Step } from '../utils/step.js'
import type { ReconOptions } from '../../types/recon.js'
import { RESOURCE_QUOTA_NAME, RUNNER_NAME } from '../../constants.js'

export interface InitResult {
    clusterContext: string
    namespace: string
    steps: Step[]
    alreadyExisted: boolean
}

// Applies the ResourceQuota, patching on 409 to keep limits current, then re-throws so runStep() maps it to already-existed.
async function applyQuota(core: k8s.CoreV1Api, namespace: string): Promise<void> {
    const body: k8s.V1ResourceQuota = {
        metadata: { name: RESOURCE_QUOTA_NAME, namespace },
        spec: { hard: { pods: '10', 'requests.cpu': '2', 'requests.memory': '2Gi', 'limits.cpu': '4', 'limits.memory': '4Gi' } }
    }
    try {
        await core.createNamespacedResourceQuota({ namespace, body })
    } catch (err) {
        if (isConflict(err)) {
            await core.replaceNamespacedResourceQuota({ name: RESOURCE_QUOTA_NAME, namespace, body }).catch(() => {})
        }
        throw err
    }
}

/**
 * Creates the chaosify namespace and applies RBAC scoping. Idempotent.
 * @param kc Loaded kubeconfig to use for all API calls.
 * @param options Options containing namespace and optional context.
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
        await runStep(`ServiceAccount ${RUNNER_NAME}`, () =>
            core.createNamespacedServiceAccount({
                namespace: ns,
                body: { metadata: { name: RUNNER_NAME, namespace: ns } }
            }).then(() => {})
        ),
        await runStep(`Role ${RUNNER_NAME}`, () =>
            rbac.createNamespacedRole({
                namespace: ns,
                body: {
                    metadata: { name: RUNNER_NAME, namespace: ns },
                    rules: [{ apiGroups: [''], resources: ['pods', 'pods/exec', 'pods/log'], verbs: ['get', 'list', 'create', 'delete'] }]
                }
            }).then(() => {})
        ),
        await runStep(`RoleBinding ${RUNNER_NAME}`, () =>
            rbac.createNamespacedRoleBinding({
                namespace: ns,
                body: {
                    metadata: { name: RUNNER_NAME, namespace: ns },
                    subjects: [{ kind: 'ServiceAccount', name: RUNNER_NAME, namespace: ns }],
                    roleRef: { apiGroup: 'rbac.authorization.k8s.io', kind: 'Role', name: RUNNER_NAME }
                }
            }).then(() => {})
        ),
    ]

    return { clusterContext: kc.getCurrentContext(), namespace: ns, steps, alreadyExisted: nsStep.status === 'already-existed' }
}
