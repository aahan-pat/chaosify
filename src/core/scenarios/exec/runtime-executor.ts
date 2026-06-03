// Executes runtime detection scenarios against a live Kubernetes cluster.
// Unlike the admission-based ScenarioExecutor, runtime scenarios expect the workload
// to be admitted â€” the signal under test is whether the runtime security tool fires
// an alert after the threat command is executed inside the running pod.
import * as k8s from '@kubernetes/client-node'
import type { RuntimeScenarioDefinition, RuntimeScenarioExecStep } from '../../../types/runtime-scenario.js'
import type { RuntimeAlertSource, RuntimeAlert } from '../../alert-sources/types.js'
import { submitPod, waitForPodRunning, injectNamespace } from './pod-runner.js'

export type { RuntimeAlertSource, RuntimeAlert }

/**
 * All possible outcomes for a runtime detection scenario.
 * These are distinct from admission outcomes — the workload is expected to be
 * created successfully; the signal is whether the runtime tool responded.
 */
export type RuntimeObservedOutcome =
    | 'alert_fired'    // Runtime tool detected the action and emitted an alert
    | 'action_blocked' // Runtime tool prevented the action at the syscall/process level
    | 'no_alert'       // Observation window closed with no matching alert — control gap
    | 'timeout'        // Executor gave up waiting before any outcome could be determined
    | 'api_error'      // Kubernetes API call failed before the scenario could execute

/** Full result of a single runtime scenario execution */
export interface RuntimeExecutionResult {
    observedOutcome: RuntimeObservedOutcome
    /** The alert payload from the runtime tool, if one was captured */
    alertDetail?: RuntimeAlert
    /** Raw Kubernetes API response for the workload creation step */
    rawResponse: string
    /** The manifest that was submitted to the cluster */
    manifestSnapshot: string
    startedAt: string
    endedAt: string
    /** Name of the created resource — needed by CleanupManager */
    createdResourceName?: string
}

export interface RuntimeExecutorOptions {
    namespace: string
    /** How long to wait for a runtime alert before declaring no_alert (ms) */
    observationWindowMs?: number
    /** Hard timeout for the entire scenario including pod startup and observation (ms) */
    timeoutMs?: number
}

const DEFAULT_OBSERVATION_WINDOW_MS = 10_000
const DEFAULT_TIMEOUT_MS = 60_000

/**
 * Executes runtime detection scenarios against a live Kubernetes cluster.
 * Flow: submit pod â†’ wait Running â†’ exec threat â†’ observe alert â†’ record outcome.
 * The exec step is non-fatal: even if the command exits with an error, the
 * syscall attempt is often enough to trigger a Falco/Tetragon rule.
 */
export class RuntimeScenarioExecutor {
    private readonly kc: k8s.KubeConfig
    private readonly alertSource: RuntimeAlertSource

    constructor(kc: k8s.KubeConfig, alertSource: RuntimeAlertSource) {
        this.kc = kc
        this.alertSource = alertSource
    }

    /**
     * Execute a runtime detection scenario.
     * A hard timeout (timeoutMs) caps the entire execution including pod startup.
     */
    async execute(
        scenario: RuntimeScenarioDefinition,
        options: RuntimeExecutorOptions,
    ): Promise<RuntimeExecutionResult> {
        const startedAt = new Date().toISOString()
        const observationWindowMs = options.observationWindowMs ?? DEFAULT_OBSERVATION_WINDOW_MS
        const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
        const manifest = injectNamespace(scenario.manifest, options.namespace)
        const manifestSnapshot = JSON.stringify(manifest)

        const timeoutSignal = new Promise<never>((_, reject) =>
            setTimeout(() => reject(new Error('timeout')), timeoutMs),
        )

        try {
            return await Promise.race([
                this.runScenario(scenario, manifest, manifestSnapshot, options.namespace, observationWindowMs, timeoutMs, startedAt),
                timeoutSignal,
            ])
        } catch (err: unknown) {
            return {
                observedOutcome: err instanceof Error && err.message === 'timeout' ? 'timeout' : 'api_error',
                rawResponse: this.formatError(err),
                manifestSnapshot,
                startedAt,
                endedAt: new Date().toISOString(),
            }
        }
    }

    /**
     * Inner execution flow wrapped so it can be raced against the hard timeout.
     * Throws on unrecoverable errors (submit failure, pod startup failure); the
     * exec step is deliberately non-fatal.
     */
    private async runScenario(
        scenario: RuntimeScenarioDefinition,
        manifest: Record<string, unknown>,
        manifestSnapshot: string,
        namespace: string,
        observationWindowMs: number,
        timeoutMs: number,
        startedAt: string,
    ): Promise<RuntimeExecutionResult> {
        const podName = await submitPod(this.kc, namespace, manifest)
        const submitRawResponse = JSON.stringify({ status: 'created', name: podName })

        await waitForPodRunning(this.kc, namespace, podName, timeoutMs)

        // Phase 3: exec the threat trigger â€” non-fatal, record error but continue.
        let execError: string | undefined
        try {
            await this.execInPod(namespace, podName, scenario.execStep)
        } catch (err: unknown) {
            execError = this.formatError(err)
        }

        // Phase 4: observe for an alert correlated to this pod.
        const windowStart = new Date().toISOString()
        let alert: RuntimeAlert | null = null
        let observeError: string | undefined
        try {
            alert = await this.alertSource.pollForAlert(namespace, 'chaosclaw-test-', windowStart, observationWindowMs)
        } catch (err: unknown) {
            observeError = this.formatError(err)
        }

        if (observeError !== undefined) {
            return {
                observedOutcome: 'api_error',
                rawResponse: observeError,
                manifestSnapshot,
                startedAt,
                endedAt: new Date().toISOString(),
                createdResourceName: podName,
            }
        }

        return {
            observedOutcome: this.resolveOutcome(alert),
            alertDetail: alert ?? undefined,
            rawResponse: execError
                ? JSON.stringify({ status: 'created', name: podName, execError })
                : submitRawResponse,
            manifestSnapshot,
            startedAt,
            endedAt: new Date().toISOString(),
            createdResourceName: podName,
        }
    }

    /**
     * Factory method for the Exec client. Extracted so tests can override it
     * without needing to mock the entire @kubernetes/client-node module.
     */
    protected createExec(): k8s.Exec {
        return new k8s.Exec(this.kc)
    }

    /**
     * Exec a command inside a running container via the Kubernetes exec API.
     * Resolves as soon as the status callback fires regardless of exit code â€”
     * the threat-trigger intent is fulfilled once the syscall runs.
     */
    private async execInPod(
        namespace: string,
        podName: string,
        step: RuntimeScenarioExecStep,
    ): Promise<void> {
        const exec = this.createExec()
        const timeoutMs = step.timeoutMs ?? 10_000

        await new Promise<void>((resolve, reject) => {
            const timer = setTimeout(() => reject(new Error('exec timeout')), timeoutMs)

            exec.exec(
                namespace,
                podName,
                step.container,
                step.command,
                null,  // stdout â€” output not needed, only the side-effect matters
                null,  // stderr
                null,  // stdin
                false, // tty
                (_status: k8s.V1Status) => {
                    clearTimeout(timer)
                    resolve()
                },
            ).catch((err: unknown) => {
                clearTimeout(timer)
                reject(err instanceof Error ? err : new Error(String(err)))
            })
        })
    }

    /**
     * Translate a RuntimeAlert presence/absence into a RuntimeObservedOutcome.
     * Any non-null alert maps to alert_fired unless the source signals action blocked.
     */
    private resolveOutcome(alert: RuntimeAlert | null): RuntimeObservedOutcome {
        if (alert === null) return 'no_alert'
        if (alert.action === 'blocked') return 'action_blocked'
        return 'alert_fired'
    }

    /** Safely converts an unknown thrown value to a plain string for evidence logging */
    private formatError(err: unknown): string {
        if (err instanceof Error) return err.message
        return String(err)
    }
}
