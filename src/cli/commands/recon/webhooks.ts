import type { Command } from 'commander'
import chalk from 'chalk'
import { surveyWebhooks } from '../../../core/recon/webhooks.js'
import { header, field, section, indent, blank, renderFindings } from '../../output.js'
import { buildKubeConfig, writeJsonToFile, writeTextToFile } from './utils/shared.js'
import { buildReconSummary } from '../../recon-summary.js'
import { DEFAULT_RECON_NAMESPACE } from '../../../constants.js'
import type { WebhookThreatGraph } from '../../../types/recon.js'

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
        .option('--format <mode>', 'Output mode: table, json, summary', 'table')
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

            if (opts.format === 'summary') {
                const text = buildReconSummary(result)
                if (opts.output) await writeTextToFile(opts.output, text)
                process.stdout.write(text + '\n')
                process.exit(0)
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

            const data = result.data as WebhookThreatGraph
            const webhookList = data.webhooks ?? []
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
                    const failMark = wh.failurePolicy === 'Ignore' ? chalk.yellow('  ← fails open') : ''
                    blank()
                    indent(wh.name)
                    indent(`Rules: ${wh.ruleCount}    Failure policy: ${wh.failurePolicy}    Scope: ${wh.scope}${failMark}`, 4)
                }
            }

            // webhook → bypassable admission → impact, one block per fail-open path.
            if ((data.findings ?? []).length > 0) {
                section('Admission Bypass Paths')
                for (const f of data.findings) {
                    blank()
                    indent(`${f.webhook}  [${f.severity}]  scope: ${f.scope}`)
                    indent(`Exploit classes: ${f.exploitClasses.join(', ')}`, 4)
                    indent(`Impact: ${f.impact}`, 4)
                    indent(`Probe:  ${f.suggestedProbe}`, 4)
                }
            }

            renderFindings(result.findings)

            // Surface what coverage analysis could not prove so conclusions stay scoped.
            if ((data.blindSpots ?? []).length > 0) {
                section('Blind Spots')
                for (const b of data.blindSpots) indent(b)
            }

            if (opts.output) {
                section('Artifacts')
                indent(`JSON report written to: ${opts.output}`)
            }

            blank()
            process.exit(0)
        })
}
