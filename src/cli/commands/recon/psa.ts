import type { Command } from 'commander'
import chalk from 'chalk'
import { surveyPsa, type NamespacePsaStatus } from '../../../core/recon/psa.js'
import { header, field, section, indent, blank, renderFindings } from '../../output.js'
import { buildKubeConfig, writeJsonToFile } from './utils/shared.js'
import { DEFAULT_RECON_NAMESPACE } from '../../../constants.js'

/**
 * Attaches the "psa" subcommand to the recon command group.
 * @param recon The recon command group to attach to.
 */
export function psa(recon: Command): void {
    recon
        .command('psa')
        .description('Survey Pod Security Admission labels across all namespaces')
        .option('--context <name>', 'Kubernetes context to use')
        .option('--namespace <name>', 'Recon namespace', DEFAULT_RECON_NAMESPACE)
        .option('--format <mode>', 'Output mode: table, json', 'table')
        .option('--output <path>', 'Write JSON result to file')
        .action(async (opts: { context?: string; namespace: string; format: string; output?: string }) => {
            const { kc, clusterContext } = buildKubeConfig(opts.context)

            let result
            try {
                result = await surveyPsa(kc, { namespace: opts.namespace, context: opts.context })
            } catch (err) {
                console.error(`\nError\n  PSA recon failed: ${err instanceof Error ? err.message : String(err)}`)
                process.exit(2)
            }

            if (opts.output) await writeJsonToFile(opts.output, result)

            if (opts.format === 'json') {
                console.log(JSON.stringify(result, null, 2))
                process.exit(0)
            }

            header('Chaosify Recon — Pod Security Admission')
            field('Cluster Context', clusterContext)

            if (result.status === 'skip' || result.status === 'error') {
                renderFindings(result.findings)
                blank()
                process.exit(0)
            }

            const namespaces = (result.data as { namespaces?: NamespacePsaStatus[] }).namespaces ?? []
            // Pad a PSA level to a fixed column width, replacing absent labels with '—'.
            const col = (s: string | undefined, width = 14) => (s ?? '—').padEnd(width)

            section('Namespace PSA Labels')
            blank()
            // Fixed-width header row so columns align with the data rows below.
            indent(`${'Namespace'.padEnd(28)} ${'Enforce'.padEnd(14)} ${'Audit'.padEnd(14)} Warn`)
            indent('─'.repeat(72))
            for (const ns of namespaces) {
                // Flag non-system namespaces with no labels — they are completely unprotected.
                const mark = !ns.enforce && !ns.audit && !ns.warn && !ns.isSystem
                    ? chalk.yellow('  ← no labels')
                    : ''
                indent(`${ns.namespace.padEnd(28)} ${col(ns.enforce)} ${col(ns.audit)} ${col(ns.warn)}${mark}`)
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
