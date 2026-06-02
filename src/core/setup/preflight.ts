// Validates that the cluster is reachable and that the current credentials have the
// permissions needed to run scenarios before any test manifests are submitted.
import * as k8s from '@kubernetes/client-node'

/** Individual check result â€” warn means non-blocking, fail means a run should not proceed */
export type PreflightCheckStatus = 'pass' | 'fail' | 'warn'

export interface PreflightCheck {
    name: string
    status: PreflightCheckStatus
    /** Human-readable detail shown when the check does not pass */
    detail?: string
}

/** Aggregate result returned after all preflight checks complete */
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
 * Runs a series of read-only cluster checks before scenario execution.
 * All checks use SelfSubjectAccessReview so no elevated permissions are needed
 * to determine what the current identity is allowed to do.
 */
export class PreflightEngine {
    private readonly kc: k8s.KubeConfig

    constructor() {
        // Load credentials from the default kubeconfig location (~/.kube/config or in-cluster).
        this.kc = new k8s.KubeConfig()
        this.kc.loadFromDefault()
    }

    /**
     * Runs all preflight checks sequentially and returns an aggregate result.
     * Checks are intentionally ordered from most fundamental (reachability) to
     * most specific (cleanup permissions) so the first failure is the most actionable.
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

    /** Verifies the API server is reachable by listing namespaces (a lightweight call) */
    private async checkClusterReachable(): Promise<PreflightCheck> {
        try {
            const coreApi = this.kc.makeApiClient(k8s.CoreV1Api)
            await coreApi.listNamespace()
            return { name: 'Cluster reachable', status: 'pass' }
        } catch {
            return { name: 'Cluster reachable', status: 'fail', detail: 'Could not reach the Kubernetes API server' }
        }
    }

    /**
     * Probes the TokenReview API with a dummy token to verify the API server
     * can process authentication requests. Any response other than 401 means
     * the current credentials are valid enough to talk to the cluster.
     */
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
            // 401 is the only status that definitively indicates bad credentials.
            if (status === 401) {
                return { name: 'Authentication valid', status: 'fail', detail: 'Credentials are invalid or expired' }
            }
            // Any other error (e.g. 403 on the TokenReview resource itself) still means we're authenticated.
            return { name: 'Authentication valid', status: 'pass' }
        }
    }

    /** Uses SelfSubjectAccessReview to check if the current identity can create namespaces */
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

    /** Checks that the current identity can create pods in the test namespace (required for execution) */
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

    /**
     * Checks delete permission for pods. Downgraded to 'warn' (not 'fail') because
     * scenarios can still run and produce results even if cleanup cannot be performed.
     */
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
