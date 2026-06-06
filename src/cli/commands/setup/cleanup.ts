// Implements "chaosify setup cleanup" — removes the chaosify namespace and all scoped resources.
import type { Command } from 'commander'
import { teardownNamespace, type TeardownResult } from '../../../core/setup/cleanup.js'
import { header, field, section, indent, blank, badge } from '../../output.js'
import { buildKubeConfig } from '../recon/utils/shared.js'
import { DEFAULT_RECON_NAMESPACE } from '../../../constants.js'

/**
 * Attaches the "cleanup" subcommand to the setup command group.
 * @param setup The setup command group to attach to.
 */
export function cleanup(setup: Command): void {
    setup
        .command('cleanup')
        .description('Remove the chaosify test namespace and all scoped resources')
        .option('--context <name>', 'Kubernetes context to use')
        .option('--namespace <name>', 'Test namespace name', DEFAULT_RECON_NAMESPACE)
        .option('--format <mode>', 'Output mode: table, json', 'table')
        .action(async (opts: { context?: string; namespace: string; format: string }) => {
            const { kc, clusterContext } = buildKubeConfig(opts.context)

            let result: TeardownResult
            try {
                result = await teardownNamespace(kc, { namespace: opts.namespace, context: opts.context })
            } catch (err) {
                console.error(`\nError\n  Could not clean up namespace: ${err instanceof Error ? err.message : String(err)}`)
                process.exit(2)
            }

            // Emit raw JSON for CI pipelines and exit immediately.
            if (opts.format === 'json') {
                console.log(JSON.stringify(result, null, 2))
                process.exit(result.steps.some(s => s.status === 'failed') ? 2 : 0)
            }

            header('Chaosify Setup — Namespace Cleanup')
            field('Cluster Context', clusterContext)
            field('Namespace', opts.namespace)

            section('Teardown')
            for (const step of result.steps) {
                indent(`${badge[step.status]} ${step.name}`)
                if (step.status === 'failed' && step.detail) indent(step.detail, 9)
            }

            // Surface the first failure and exit non-zero so callers know cleanup did not complete.
            const failed = result.steps.find(s => s.status === 'failed')
            if (failed) {
                blank()
                section('Error')
                indent(`Could not fully clean up namespace "${opts.namespace}"`)
                if (failed.detail) indent(failed.detail, 4)
                blank()
                process.exit(2)
            }

            blank()
            section('Done')
            indent(`Namespace ${opts.namespace} and all scoped resources removed`)
            blank()
            process.exit(0)
        })
}
