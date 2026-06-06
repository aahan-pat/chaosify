// Applies scenario manifests to a live Kubernetes cluster and translates the API
// response into a structured ObservedOutcome (allowed, rejected, timeout, or error).
import * as k8s from '@kubernetes/client-node'
import type { ScenarioDefinition } from '../../../types/scenario.js'
import { injectNamespace } from './pod-runner.js'

/** All possible outcomes that the Kubernetes API can produce for an apply attempt */
export type ObservedOutcome = 'admission_rejected' | 'admission_allowed' | 'timeout' | 'api_error'

/** Full result of a single scenario execution, including timing and evidence fields */
export interface ExecutionResult {
    observedOutcome: ObservedOutcome
    /** Raw API response text, preserved for the evidence artifact */
    rawResponse: string
    /** The manifest that was actually submitted (after namespace injection) */
    manifestSnapshot: string
    startedAt: string
    endedAt: string
    /** Name of the resource if the cluster admitted it (needed for cleanup) */
    createdResourceName?: string
}

export interface ExecutorOptions {
    namespace: string
    timeoutMs?: number
}

import { DEFAULT_ADMISSION_TIMEOUT_MS } from '../../../constants.js'

/**
 * Applies scenario manifests to a live Kubernetes cluster and records what happened.
 * Admission rejections (HTTP 400/403) are treated as intentional policy responses,
 * not errors, so the caller can compare them against the scenario's expected outcome.
 */
export class ScenarioExecutor {
    private readonly kc: k8s.KubeConfig

    constructor(kc: k8s.KubeConfig) {
        this.kc = kc
    }

    /**
     * Execute a scenario against the cluster.
     * Injects the target namespace into the manifest before submission so test
     * resources are always isolated and namespaced correctly.
     */
    async execute(scenario: ScenarioDefinition, options: ExecutorOptions): Promise<ExecutionResult> {
        const startedAt = new Date().toISOString()
        const manifest = injectNamespace(scenario.manifest, options.namespace)
        const manifestSnapshot = JSON.stringify(manifest)

        try {
            const result = await this.applyWithTimeout(manifest, options.namespace, options.timeoutMs ?? DEFAULT_ADMISSION_TIMEOUT_MS)
            return { ...result, manifestSnapshot, startedAt, endedAt: new Date().toISOString() }
        } catch (err: unknown) {
            const endedAt = new Date().toISOString()
            // Distinguish a deliberate admission denial from an unexpected infrastructure error.
            if (this.isAdmissionRejection(err)) {
                return { observedOutcome: 'admission_rejected', rawResponse: this.formatError(err), manifestSnapshot, startedAt, endedAt }
            }
            return { observedOutcome: 'api_error', rawResponse: this.formatError(err), manifestSnapshot, startedAt, endedAt }
        }
    }

    /**
     * Wraps applyManifest with a hard timeout.
     * Uses Promise.race so the apply is abandoned (and reported as 'timeout') if
     * the Kubernetes API takes longer than timeoutMs to respond.
     */
    private async applyWithTimeout(
        manifest: Record<string, unknown>,
        namespace: string,
        timeoutMs: number,
    ): Promise<Pick<ExecutionResult, 'observedOutcome' | 'rawResponse' | 'createdResourceName'>> {
        const timeoutPromise = new Promise<never>((_, reject) =>
            setTimeout(() => reject(new Error('timeout')), timeoutMs),
        )
        return Promise.race([this.applyManifest(manifest, namespace), timeoutPromise])
    }

    /**
     * Submits the manifest to the Kubernetes API.
     * Currently only Pod resources are supported; other kinds throw an error so
     * the caller receives an 'api_error' outcome rather than silently doing nothing.
     */
    private async applyManifest(
        manifest: Record<string, unknown>,
        namespace: string,
    ): Promise<Pick<ExecutionResult, 'observedOutcome' | 'rawResponse' | 'createdResourceName'>> {
        const coreApi = this.kc.makeApiClient(k8s.CoreV1Api)
        const kind = manifest['kind'] as string | undefined

        if (kind === 'Pod') {
            const pod = manifest as k8s.V1Pod
            const created = await coreApi.createNamespacedPod({ namespace, body: pod })
            return {
                observedOutcome: 'admission_allowed',
                rawResponse: JSON.stringify({ status: 'created', name: created.metadata?.name }),
                // Capture the server-assigned name so CleanupManager can delete it later.
                createdResourceName: created.metadata?.name,
            }
        }

        throw new Error(`Unsupported manifest kind: ${kind ?? 'unknown'}`)
    }

    /**
     * Returns true when the HTTP status code indicates an admission webhook or RBAC
     * rejection (400 Bad Request or 403 Forbidden) rather than an infrastructure fault.
     */
    private isAdmissionRejection(err: unknown): boolean {
        const status = (err as { response?: { statusCode?: number } }).response?.statusCode
        return status === 403 || status === 400
    }

    /** Safely converts an unknown thrown value to a plain string for evidence logging */
    private formatError(err: unknown): string {
        if (err instanceof Error) return err.message
        return String(err)
    }
}
