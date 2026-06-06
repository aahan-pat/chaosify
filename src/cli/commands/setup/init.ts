// Implements "chaosify setup init" — creates the chaosify namespace and applies RBAC scoping.
import type { Command } from 'commander'
import chalk from 'chalk'
import { initNamespace, type InitResult } from '../../../core/setup/init.js'
import { header, field, section, indent, blank, badge } from '../../output.js'
import { buildKubeConfig } from '../recon/utils/shared.js'
import { DEFAULT_RECON_NAMESPACE } from '../../../constants.js'

/**
 * Attaches the "init" subcommand to the setup command group.
 * @param setup The setup command group to attach to.
 */
export function init(setup: Command): void {
    setup
        .command('init')
        .description('Initialize the chaosify test namespace with RBAC scoping and resource quota')
        .option('--context <name>', 'Kubernetes context to use')
        .option('--namespace <name>', 'Test namespace name', DEFAULT_RECON_NAMESPACE)
        .option('--format <mode>', 'Output mode: table, json', 'table')
        .action(async (opts: { context?: string; namespace: string; format: string }) => {
            const { kc, clusterContext } = buildKubeConfig(opts.context)

            let result: InitResult
            try {
                result = await initNamespace(kc, { namespace: opts.namespace, context: opts.context })
            } catch (err) {
                console.error(`\nError\n  Could not initialize namespace: ${err instanceof Error ? err.message : String(err)}`)
                process.exit(2)
            }

            // Emit raw JSON for CI pipelines and exit immediately.
            if (opts.format === 'json') {
                console.log(JSON.stringify(result, null, 2))
                process.exit(result.steps.some(s => s.status === 'failed') ? 2 : 0)
            }

            header('Chaosify Setup — Namespace Init')
            field('Cluster Context', clusterContext)
            field('Namespace', opts.namespace)

            if (result.alreadyExisted) {
                blank()
                console.log(chalk.yellow('Warning'))
                indent(`Namespace ${opts.namespace} already exists`)
            }

            section('Setup')
            for (const step of result.steps) {
                indent(`${badge[step.status]} ${step.name}`)
                if (step.status === 'failed' && step.detail) indent(step.detail, 9)
            }

            // Surface the first failure and exit non-zero so callers know init did not complete.
            const failed = result.steps.find(s => s.status === 'failed')
            if (failed) {
                blank()
                section('Error')
                indent(`Cannot initialize namespace "${opts.namespace}"`)
                if (failed.detail) indent(failed.detail, 4)
                blank()
                process.exit(2)
            }

            blank()
            section('Ready')
            indent(`All pentest activity will be confined to namespace: ${opts.namespace}`)
            blank()
            process.exit(0)
        })
}
