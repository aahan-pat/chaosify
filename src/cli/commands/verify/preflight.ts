// Implements “chaosclaw probe preflight” — runs PreflightEngine and renders results as a table or JSON.
import type { Command } from 'commander'
import { PreflightEngine } from '../../../core/setup/preflight.js'
import { header, field, section, indent, preflightLabel, blank } from '../../output.js'
import { DEFAULT_PROBE_NAMESPACE } from './utils/shared.js'

/**
 * Attaches the "preflight" subcommand to the probe command group.
 * Exit codes: 0 = passed, 2 = unexpected error, 3 = checks failed.
 */
export function preflight(probe: Command): void {
    probe
        .command('preflight')
        .description('Check that the target cluster is ready for verification')
        .option('--context <name>', 'Kubernetes context to use')
        .option('--namespace <name>', 'Test namespace', DEFAULT_PROBE_NAMESPACE)
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

            // Raw JSON for CI pipelines.
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

            // Offer the next command only on success.
            if (result.passed) {
                blank()
                section('Next')
                const contextFlag = opts.context ? ` --context ${opts.context}` : ''
                indent(`chaosclaw probe run --pack preventive-baseline${contextFlag}`)
            }

            blank()
            process.exit(result.passed ? 0 : 3)
        })
}
