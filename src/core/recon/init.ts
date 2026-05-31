import * as k8s from '@kubernetes/client-node'
import { coreV1Api, rbacV1Api } from '../kube/client.js'
import { isConflict } from '../kube/errors.js'
import type { ReconOptions } from '../../types/recon.js'

export interface InitStep {
    name: string
    status: 'ok' | 'already-existed' | 'failed'
    detail?: string
}

export interface InitResult {
    clusterContext: string
    namespace: string
    steps: InitStep[]
    alreadyExisted: boolean
}

// Runs fn and collapses the result into an InitStep, mapping 409 to already-existed.
async function attempt(name: string, fn: () => Promise<void>): Promise<InitStep> {
    try {
        await fn()
        return { name, status: 'ok' }
    } catch (err) {
        if (isConflict(err)) return { name, status: 'already-existed' }
        return { name, status: 'failed', detail: err instanceof Error ? err.message : String(err) }
    }
}

export class ReconInitEngine {
    constructor(private readonly kc: k8s.KubeConfig) {}

    /**
     * Creates the chaosclaw namespace and applies RBAC scoping. Idempotent.
     * @param options Recon options containing namespace and optional context.
     */
    async run(options: ReconOptions): Promise<InitResult> {
        const ns = options.namespace
        // Create API clients once and share across all setup steps.
        const core = coreV1Api(this.kc)
        const rbac = rbacV1Api(this.kc)

        const nsStep = await attempt(`Namespace ${ns}`, () =>
            core.createNamespace({ body: { metadata: { name: ns } } }).then(() => {})
        )

        // Bail early — all subsequent steps depend on the namespace existing.
        if (nsStep.status === 'failed') {
            return { clusterContext: this.kc.getCurrentContext(), namespace: ns, steps: [nsStep], alreadyExisted: false }
        }

        const steps: InitStep[] = [
            nsStep,
            await attempt('ResourceQuota', () => this.applyQuota(core, ns)),
            await attempt('ServiceAccount chaosclaw-runner', () =>
                core.createNamespacedServiceAccount({
                    namespace: ns,
                    body: { metadata: { name: 'chaosclaw-runner', namespace: ns } }
                }).then(() => {})
            ),
            await attempt('Role chaosclaw-runner', () =>
                rbac.createNamespacedRole({
                    namespace: ns,
                    body: {
                        metadata: { name: 'chaosclaw-runner', namespace: ns },
                        rules: [{ apiGroups: [''], resources: ['pods', 'pods/exec', 'pods/log'], verbs: ['get', 'list', 'create', 'delete'] }]
                    }
                }).then(() => {})
            ),
            await attempt('RoleBinding chaosclaw-runner', () =>
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

        return { clusterContext: this.kc.getCurrentContext(), namespace: ns, steps, alreadyExisted: nsStep.status === 'already-existed' }
    }

    // Applies the ResourceQuota, patching on 409 to keep limits current, then re-throws so attempt() maps it to already-existed.
    private async applyQuota(core: k8s.CoreV1Api, namespace: string): Promise<void> {
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
}
