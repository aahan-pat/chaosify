// Implements "chaosclaw verify exec" â€” the runtime binary execution primitive.
// Submits a pod, execs a command inside it, captures exit code + stdout + stderr,
// and optionally polls a runtime detection tool for a correlated alert.
import { basename } from 'node:path'
import type { Command } from 'commander'
import {
    loadPodManifest, resolveFirstContainer, injectNamespace,
    ensureNamespace, submitPod, waitForPodRunning, execCapturing,
} from '../../../core/scenarios/exec/pod-runner.js'
import { buildAlertSource } from '../../../core/alert-sources/index.js'
import { CleanupManager } from '../../../core/teardown/cleanup.js'
import { EvidenceBuilder } from '../../../core/teardown/evidence-builder.js'
import { header, field, section, indent, outcomeLabel, blank, printAlertSection, printCleanupWarning } from '../../output.js'
import { buildKubeConfig } from '../recon/utils/shared.js'
import { DEFAULT_VERIFY_NAMESPACE } from './utils/shared.js'

const DEFAULT_POD_TIMEOUT_S = 60
const DEFAULT_EXEC_TIMEOUT_S = 30
const DEFAULT_OBSERVATION_WINDOW_S = 10

const VALID_EXPECTS = ['succeeded', 'failed', 'denied'] as const
type ExecExpect = (typeof VALID_EXPECTS)[number]

/**
 * Attaches the "exec" subcommand to the verify command group.
 * @param verify The verify command group to attach to.
 */
export function exec(verify: Command): void {
    verify
        .command('exec')
        .description('Submit a pod, exec a command inside it, and verify the outcome')
        .requiredOption('--pod <path>', 'Pod manifest to submit (YAML or JSON)')
        .requiredOption('--run <command>', 'Command to exec inside the container')
        .option('--container <name>', 'Container to exec into (default: first container in the pod spec)')
        .requiredOption('--expect <outcome>', 'Expected outcome: succeeded, failed, denied')
        .option('--alert-source <tool>', 'Also poll this runtime tool for a correlated alert: none (default), falco, tetragon, kubearmor', 'none')
        .option('--observation-window <seconds>', `Alert poll window when using --alert-source (default: ${DEFAULT_OBSERVATION_WINDOW_S})`, String(DEFAULT_OBSERVATION_WINDOW_S))
        .option('--pod-timeout <seconds>', `Max wait for pod Running (default: ${DEFAULT_POD_TIMEOUT_S})`, String(DEFAULT_POD_TIMEOUT_S))
        .option('--exec-timeout <seconds>', `Max time for the command (default: ${DEFAULT_EXEC_TIMEOUT_S})`, String(DEFAULT_EXEC_TIMEOUT_S))
        .option('--context <name>', 'Kubernetes context to use')
        .option('--namespace <name>', 'Test namespace', DEFAULT_VERIFY_NAMESPACE)
        .option('--output <path>', 'Write JSON evidence artifact to file')
        .option('--format <mode>', 'Output mode: table, json', 'table')
        .option('--cleanup <mode>', 'Cleanup mode: always, on-success', 'always')
        .action(async (opts: {
            pod: string
            run: string
            container?: string
            expect: string
            alertSource: string
            observationWindow: string
            podTimeout: string
            execTimeout: string
            context?: string
            namespace: string
            output?: string
            format: string
            cleanup: string
        }) => {
            // Validate --expect before touching the cluster so the error is immediate and clear.
            if (!VALID_EXPECTS.includes(opts.expect as ExecExpect)) {
                console.error(`\nError\n  --expect must be one of: ${VALID_EXPECTS.join(', ')}. Got: "${opts.expect}"`)
                process.exit(4)
            }

            // Load and validate the manifest; exits with code 4 on any parse error.
            const manifest = await loadPodManifest(opts.pod)
            const container = opts.container ?? resolveFirstContainer(manifest)
            if (!container) {
                console.error('\nError\n  Could not determine container name â€” specify --container or ensure the pod spec includes named containers')
                process.exit(4)
            }

            const { kc, clusterContext } = buildKubeConfig(opts.context)

            await ensureNamespace(kc, opts.namespace)

            // Convert all timeout/window options from seconds to milliseconds.
            const podTimeoutMs = parseInt(opts.podTimeout, 10) * 1_000
            const execTimeoutMs = parseInt(opts.execTimeout, 10) * 1_000
            const observationWindowMs = parseInt(opts.observationWindow, 10) * 1_000
            const command = opts.run.split(' ')
            const alertSource = buildAlertSource(opts.alertSource, kc)
            const cleanup = new CleanupManager(kc)
            const builder = new EvidenceBuilder({ clusterContext, startedAt: new Date().toISOString() })
            const startedAt = new Date().toISOString()
            // Build a unique scenario ID from the manifest filename so evidence artifacts are traceable.
            const scenarioId = `exec:${basename(opts.pod)}`

            if (opts.format !== 'json') {
                header('ChaosClaw Exec')
                field('Cluster Context', clusterContext)
                field('Pod Manifest', opts.pod)
                field('Command', opts.run)
                field('Container', container)
                field('Expect', opts.expect)
                if (opts.alertSource !== 'none') field('Alert Source', opts.alertSource)
                field('Test Namespace', opts.namespace)
                section('Running')
            }

            const injected = injectNamespace(manifest, opts.namespace)
            let podName: string | undefined
            let observedOutcome: string
            let likelyIssue: string | undefined
            let rawResponse: string
            let alertJson: string | undefined

            try {
                // Submit the pod, wait for it to be Running, then exec the command inside it.
                podName = await submitPod(kc, opts.namespace, injected)
                await waitForPodRunning(kc, opts.namespace, podName, podTimeoutMs)

                // Record the exec start time so the alert poll window is anchored to the right moment.
                const windowStart = new Date().toISOString()
                const execResult = await execCapturing(kc, opts.namespace, podName, container, command, execTimeoutMs)
                observedOutcome = execResult.result

                rawResponse = JSON.stringify({
                    exitCode: execResult.exitCode,
                    stdout: execResult.stdout,
                    stderr: execResult.stderr,
                })

                // If an alert source is configured, poll for a correlated alert after the exec.
                if (opts.alertSource !== 'none') {
                    const alert = await alertSource.pollForAlert(opts.namespace, 'chaosclaw-test-', windowStart, observationWindowMs)
                    if (alert) {
                        alertJson = JSON.stringify(alert)
                        rawResponse = JSON.stringify({ exitCode: execResult.exitCode, stdout: execResult.stdout, stderr: execResult.stderr, alert })
                    }
                }
            } catch (err: unknown) {
                observedOutcome = 'api_error'
                rawResponse = err instanceof Error ? err.message : String(err)
                likelyIssue = 'Kubernetes API error â€” check cluster connectivity and RBAC'
            }

            // Map observed outcome to Pass/Fail/Error by comparing against the expected value.
            const status = observedOutcome === 'api_error' ? 'Error' as const
                : observedOutcome === opts.expect ? 'Pass' as const
                : 'Fail' as const

            if (status === 'Fail') likelyIssue = diagnoseExec(opts.expect as ExecExpect, observedOutcome)

            // Only include the pod in cleanup targets if it was actually created.
            const createdResources = podName
                ? [{ kind: 'Pod' as const, name: podName, namespace: opts.namespace }]
                : []
            const shouldCleanup = opts.cleanup === 'always' || (opts.cleanup === 'on-success' && status === 'Pass')
            const cleanupResult = shouldCleanup
                ? await cleanup.cleanup(createdResources)
                : { status: 'skipped' as const, remainingResources: [] }

            const result = {
                scenarioId,
                version: 1,
                status,
                expectedOutcome: opts.expect,
                observedOutcome,
                cleanupStatus: cleanupResult.status,
                startedAt,
                endedAt: new Date().toISOString(),
                rawResponse,
                likelyIssue,
            }

            builder.addResult(result)
            const evidence = builder.build(new Date().toISOString())

            if (opts.format === 'json') {
                console.log(JSON.stringify(evidence, null, 2))
                process.exit(status === 'Pass' ? 0 : 1)
            }

            indent(`${outcomeLabel(result.status)} ${scenarioId}`)

            section('Summary')
            indent(`Status:   ${status}`)
            indent(`Expected: ${opts.expect}`)
            indent(`Observed: ${observedOutcome}`)
            if (likelyIssue) indent(`Issue:    ${likelyIssue}`)

            // Re-parse the alert JSON for display if an alert was captured.
            if (alertJson) printAlertSection(JSON.parse(alertJson) as { source: string; ruleName: string; podName: string; triggeredAt: string; action?: string })

            printCleanupWarning(cleanupResult.remainingResources)

            if (opts.output) {
                await builder.writeToFile(opts.output, evidence)
                section('Artifacts')
                indent(`JSON report written to: ${opts.output}`)
            }

            blank()
            process.exit(status === 'Pass' ? 0 : 1)
        })
}

// Return a targeted diagnostic hint based on the direction of the expectation mismatch.
function diagnoseExec(expected: ExecExpect, observed: string): string {
    if (expected === 'denied' && observed === 'succeeded') {
        return 'pods/exec is permitted â€” RBAC does not restrict exec into pods in this namespace'
    }
    if (expected === 'denied' && observed === 'failed') {
        return 'Command ran (exec was permitted) but exited non-zero â€” RBAC does not restrict exec'
    }
    if (expected === 'succeeded' && observed === 'denied') {
        return 'RBAC blocked the exec call â€” grant pods/exec in this namespace'
    }
    if (expected === 'succeeded' && observed === 'failed') {
        return 'Command exited with a non-zero exit code â€” check the stderr in the raw response'
    }
    if (expected === 'failed' && observed === 'succeeded') {
        return 'Command exited with code 0 â€” expected a non-zero exit'
    }
    return 'Unexpected outcome â€” inspect the raw response for details'
}
