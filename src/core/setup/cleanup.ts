import * as k8s from '@kubernetes/client-node'
import { coreV1Api, rbacV1Api } from '../kube/client.js'
import { isNotFound } from '../kube/errors.js'
import { runStep, type Step } from '../utils/step.js'
import type { ReconOptions } from '../../types/recon.js'

export interface TeardownResult {
    clusterContext: string
    namespace: string
    steps: Step[]
}

// Swallows 404 so deletion steps report 'ok' when the resource is already gone.
async function deleteIfExists(fn: () => Promise<unknown>): Promise<void> {
    try {
        await fn()
    } catch (err) {
        if (!isNotFound(err)) throw err
    }
}

/**
 * Deletes the chaosify namespace and all scoped resources created by initNamespace. Idempotent.
 * @param kc Loaded kubeconfig to use for all API calls.
 * @param options Options containing namespace and optional context.
 */
export async function teardownNamespace(kc: k8s.KubeConfig, options: ReconOptions): Promise<TeardownResult> {
    const ns = options.namespace
    // Create API clients once and share across all teardown steps.
    const core = coreV1Api(kc)
    const rbac = rbacV1Api(kc)

    // Delete namespace-scoped resources in reverse-init order, then delete the namespace itself.
    const steps: Step[] = [
        await runStep('RoleBinding chaosify-runner', () => deleteIfExists(() => rbac.deleteNamespacedRoleBinding({ name: 'chaosify-runner', namespace: ns }))),
        await runStep('Role chaosify-runner', () => deleteIfExists(() => rbac.deleteNamespacedRole({ name: 'chaosify-runner', namespace: ns }))),
        await runStep('ServiceAccount chaosify-runner', () => deleteIfExists(() => core.deleteNamespacedServiceAccount({ name: 'chaosify-runner', namespace: ns }))),
        await runStep('ResourceQuota chaosify-quota', () => deleteIfExists(() => core.deleteNamespacedResourceQuota({ name: 'chaosify-quota', namespace: ns }))),
        await runStep(`Namespace ${ns}`, () => deleteIfExists(() => core.deleteNamespace({ name: ns }))),
    ]

    return { clusterContext: kc.getCurrentContext(), namespace: ns, steps }
}
