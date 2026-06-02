// Implements "chaosclaw verify preflight" â€” delegates cluster readiness checks to
// PreflightEngine and formats the result as a human-readable table or raw JSON.
import type { Command } from 'commander'
import { PreflightEngine } from '../../../core/setup/preflight.js'
import { header, field, section, indent, preflightLabel, blank } from '../../output.js'
import { DEFAULT_VERIFY_NAMESPACE } from './utils/shared.js'

/**
 * Attaches the "preflight" subcommand to the verify command group.
 * Exit codes: 0 = all checks passed, 2 = unexpected error, 3 = one or more checks failed.
 */
export function preflight(verify: Command): void {
    verify
        .command('preflight')
        .description('Check that the target cluster is ready for verification')
        .option('--context <name>', 'Kubernetes context to use')
        .option('--namespace <name>', 'Test namespace', DEFAULT_VERIFY_NAMESPACE)
        .option('--format <mode>', 'Output mode: table, json', 'table')
        .action(async (opts: { context?: string; namespace: string; format: string }) => {
            const engine = new PreflightEngine()

            let result
            try {
                result = await engine.run({ context: opts.context, namespace: opts.namespace })
            } catch (err: unknown) {
                console.error('Error running preflight:', err instanceof Error ? err.message : String(err))
                process.exit(2)
            }

            // Emit raw JSON for CI pipelines and exit immediately.
            if (opts.format === 'json') {
                console.log(JSON.stringify(result, null, 2))
                process.exit(result.passed ? 0 : 3)
            }

            header('ChaosClaw Preflight')
            field('Cluster Context', result.clusterContext)
            field('Test Namespace', result.namespace)

            section('Checks')
            for (const check of result.checks) {
                indent(`${preflightLabel(check.status)} ${check.name}`)
                // Indent failure/warning detail one level deeper for visual hierarchy.
                if (check.detail) indent(`  ${check.detail}`, 4)
            }

            section('Result')
            if (!result.passed) {
                indent('Preflight failed')
            } else if (result.hasWarnings) {
                indent('Preflight passed with warnings')
            } else {
                indent('Preflight passed')
            }

            // Only show the next-step prompt when the cluster is ready to run scenarios.
            if (result.passed) {
                blank()
                section('Next')
                const contextFlag = opts.context ? ` --context ${opts.context}` : ''
                indent(`chaosclaw verify run --pack preventive-baseline${contextFlag}`)
            }

            blank()
            process.exit(result.passed ? 0 : 3)
        })
}
