// Validates cluster reachability and credential permissions before any scenarios are submitted.
import * as k8s from '@kubernetes/client-node'

/** warn = non-blocking; fail = run should not proceed */
export type PreflightCheckStatus = 'pass' | 'fail' | 'warn'

export interface PreflightCheck {
    name: string
    status: PreflightCheckStatus
    /** Human-readable detail shown when the check does not pass */
    detail?: string
}

/** Aggregate result from all preflight checks. */
export interface PreflightResult {
    clusterContext: string
    namespace: string
    checks: PreflightCheck[]
    /** True when no check has status 'fail' (warnings are allowed) */
    passed: boolean
    hasWarnings: boolean
}

export interface PreflightOptions {
    /** Override the active kubeconfig context */
    context?: string
    namespace: string
}

/**
 * Runs read-only cluster checks using SelfSubjectAccessReview — no elevated permissions needed.
 */
export class PreflightEngine {
    private readonly kc: k8s.KubeConfig

    constructor() {
        this.kc = new k8s.KubeConfig()
        this.kc.loadFromDefault()
    }

    /**
     * Runs all preflight checks sequentially, ordered from most fundamental to most specific
     * so the first failure is the most actionable.
     */
    async run(options: PreflightOptions): Promise<PreflightResult> {
        if (options.context) {
            this.kc.setCurrentContext(options.context)
        }
        const context = this.kc.getCurrentContext()

        const checks: PreflightCheck[] = []

        checks.push(await this.checkClusterReachable())
        checks.push(await this.checkAuthentication())
        checks.push(await this.checkNamespaceCreation(options.namespace))
        checks.push(await this.checkPodPermissions(options.namespace))
        // Cleanup failure is downgraded to a warning â€” scenarios can still run.
        checks.push(await this.checkCleanupPermissions(options.namespace))

        const passed = checks.every(c => c.status !== 'fail')
        const hasWarnings = checks.some(c => c.status === 'warn')

        return { clusterContext: context, namespace: options.namespace, checks, passed, hasWarnings }
    }

    /** Verifies API server reachability via a namespace list. */
    private async checkClusterReachable(): Promise<PreflightCheck> {
        try {
            const coreApi = this.kc.makeApiClient(k8s.CoreV1Api)
            await coreApi.listNamespace()
            return { name: 'Cluster reachable', status: 'pass' }
        } catch {
            return { name: 'Cluster reachable', status: 'fail', detail: 'Could not reach the Kubernetes API server' }
        }
    }

    /** Probes TokenReview with a dummy token; any non-401 response confirms valid credentials. */
    private async checkAuthentication(): Promise<PreflightCheck> {
        try {
            const authApi = this.kc.makeApiClient(k8s.AuthenticationV1Api)
            await authApi.createTokenReview({
                body: {
                    apiVersion: 'authentication.k8s.io/v1',
                    kind: 'TokenReview',
                    spec: { token: 'probe' },
                },
            })
            return { name: 'Authentication valid', status: 'pass' }
        } catch (err: unknown) {
            const status = (err as { response?: { statusCode?: number } }).response?.statusCode
            // Only 401 definitively indicates bad credentials.
            if (status === 401) {
                return { name: 'Authentication valid', status: 'fail', detail: 'Credentials are invalid or expired' }
            }
            // 403 on the TokenReview resource itself still means we're authenticated.
            return { name: 'Authentication valid', status: 'pass' }
        }
    }

    /** Checks namespace create permission via SelfSubjectAccessReview. */
    private async checkNamespaceCreation(namespace: string): Promise<PreflightCheck> {
        try {
            const authzApi = this.kc.makeApiClient(k8s.AuthorizationV1Api)
            const review = await authzApi.createSelfSubjectAccessReview({
                body: {
                    apiVersion: 'authorization.k8s.io/v1',
                    kind: 'SelfSubjectAccessReview',
                    spec: {
                        resourceAttributes: { verb: 'create', resource: 'namespaces', namespace },
                    },
                },
            })
            const allowed = review.status?.allowed === true
            return {
                name: 'Namespace creation allowed',
                status: allowed ? 'pass' : 'fail',
                detail: allowed ? undefined : `Cannot create namespace "${namespace}" â€” use --namespace to specify an existing one`,
            }
        } catch {
            return { name: 'Namespace creation allowed', status: 'fail', detail: 'Could not check namespace permissions' }
        }
    }

    /** Checks pod create permission in the test namespace. */
    private async checkPodPermissions(namespace: string): Promise<PreflightCheck> {
        try {
            const authzApi = this.kc.makeApiClient(k8s.AuthorizationV1Api)
            const review = await authzApi.createSelfSubjectAccessReview({
                body: {
                    apiVersion: 'authorization.k8s.io/v1',
                    kind: 'SelfSubjectAccessReview',
                    spec: {
                        resourceAttributes: { verb: 'create', resource: 'pods', namespace },
                    },
                },
            })
            const allowed = review.status?.allowed === true
            return {
                name: 'Pod create/delete permissions available',
                status: allowed ? 'pass' : 'fail',
                detail: allowed ? undefined : 'Cannot create pods in the test namespace',
            }
        } catch {
            return { name: 'Pod create/delete permissions available', status: 'fail', detail: 'Could not check pod permissions' }
        }
    }

    /** Checks pod delete permission, downgraded to 'warn' so scenarios can still run without cleanup. */
    private async checkCleanupPermissions(namespace: string): Promise<PreflightCheck> {
        try {
            const authzApi = this.kc.makeApiClient(k8s.AuthorizationV1Api)
            const review = await authzApi.createSelfSubjectAccessReview({
                body: {
                    apiVersion: 'authorization.k8s.io/v1',
                    kind: 'SelfSubjectAccessReview',
                    spec: {
                        resourceAttributes: { verb: 'delete', resource: 'pods', namespace },
                    },
                },
            })
            const allowed = review.status?.allowed === true
            return {
                name: 'Cleanup permissions available',
                status: allowed ? 'pass' : 'warn',
                detail: allowed ? undefined : 'Cannot delete pods â€” cleanup may fail after runs',
            }
        } catch {
            return { name: 'Cleanup permissions available', status: 'warn', detail: 'Could not verify cleanup permissions' }
        }
    }
}
