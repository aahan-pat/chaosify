import type { Command } from 'commander'
import chalk from 'chalk'
import { surveyWebhooks, type WebhookInfo } from '../../../core/recon/webhooks.js'
import { header, field, section, indent, blank, renderFindings } from '../../output.js'
import { buildKubeConfig, DEFAULT_RECON_NAMESPACE, writeJsonToFile } from './utils/shared.js'

/**
 * Attaches the "webhooks" subcommand to the recon command group.
 * @param recon The recon command group to attach to.
 */
export function webhooks(recon: Command): void {
    recon
        .command('webhooks')
        .description('Survey admission webhooks and detect failure-open configurations')
        .option('--context <name>', 'Kubernetes context to use')
        .option('--namespace <name>', 'Recon namespace', DEFAULT_RECON_NAMESPACE)
        .option('--format <mode>', 'Output mode: table, json', 'table')
        .option('--output <path>', 'Write JSON result to file')
        .action(async (opts: { context?: string; namespace: string; format: string; output?: string }) => {
            const { kc, clusterContext } = buildKubeConfig(opts.context)

            let result
            try {
                result = await surveyWebhooks(kc, { namespace: opts.namespace, context: opts.context })
            } catch (err) {
                console.error(`\nError\n  Webhook recon failed: ${err instanceof Error ? err.message : String(err)}`)
                process.exit(2)
            }

            if (opts.output) await writeJsonToFile(opts.output, result)

            if (opts.format === 'json') {
                console.log(JSON.stringify(result, null, 2))
                process.exit(0)
            }

            header('Chaosify Recon — Admission Webhooks')
            field('Cluster Context', clusterContext)

            if (result.status === 'skip' || result.status === 'error') {
                renderFindings(result.findings)
                blank()
                process.exit(0)
            }

            const webhookList = (result.data as { webhooks?: WebhookInfo[] }).webhooks ?? []
            const validating = webhookList.filter(w => w.type === 'validating')
            const mutating = webhookList.filter(w => w.type === 'mutating')

            if (webhookList.length === 0) {
                section('Admission Webhooks')
                indent('None found')
            }

            if (validating.length > 0) {
                section(`Validating Webhooks (${validating.length})`)
                for (const wh of validating) {
                    // Highlight failure-open webhooks inline so they stand out immediately.
                    const failMark = wh.failurePolicy === 'Ignore' ? chalk.yellow('  ← fails open') : ''
                    blank()
                    indent(wh.name)
                    indent(`Rules: ${wh.ruleCount}    Failure policy: ${wh.failurePolicy}    Scope: ${wh.scope}${failMark}`, 4)
                }
            }

            if (mutating.length > 0) {
                section(`Mutating Webhooks (${mutating.length})`)
                for (const wh of mutating) {
                    blank()
                    indent(wh.name)
                    indent(`Rules: ${wh.ruleCount}    Failure policy: ${wh.failurePolicy}    Scope: ${wh.scope}`, 4)
                }
            }

            renderFindings(result.findings)

            if (opts.output) {
                section('Artifacts')
                indent(`JSON report written to: ${opts.output}`)
            }

            blank()
            process.exit(0)
        })
}
