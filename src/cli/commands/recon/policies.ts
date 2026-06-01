import type { Command } from 'commander'
import chalk from 'chalk'
import { surveyPolicies, type PolicyEngine, type PolicyInfo } from '../../../core/recon/policies.js'
import { header, field, section, indent, blank, renderFindings } from '../../output.js'
import { buildKubeConfig, DEFAULT_RECON_NAMESPACE, writeJsonToFile } from './utils/shared.js'

/**
 * Attaches the "policies" subcommand to the recon command group.
 * @param recon The recon command group to attach to.
 */
export function policies(recon: Command): void {
    recon
        .command('policies')
        .description('Detect policy engine (Kyverno / Gatekeeper) and survey enforcement modes')
        .option('--context <name>', 'Kubernetes context to use')
        .option('--namespace <name>', 'Recon namespace', DEFAULT_RECON_NAMESPACE)
        .option('--engine <name>', 'Force a specific engine: kyverno, gatekeeper, auto', 'auto')
        .option('--format <mode>', 'Output mode: table, json', 'table')
        .option('--output <path>', 'Write JSON result to file')
        .action(async (opts: { context?: string; namespace: string; engine: string; format: string; output?: string }) => {
            const { kc, clusterContext } = buildKubeConfig(opts.context)

            let result
            try {
                result = await surveyPolicies(kc, { namespace: opts.namespace, context: opts.context, engine: opts.engine })
            } catch (err) {
                console.error(`\nError\n  Policy recon failed: ${err instanceof Error ? err.message : String(err)}`)
                process.exit(2)
            }

            if (opts.output) await writeJsonToFile(opts.output, result)

            if (opts.format === 'json') {
                console.log(JSON.stringify(result, null, 2))
                process.exit(0)
            }

            header('ChaosClaw Recon — Policy Engine')
            field('Cluster Context', clusterContext)

            if (result.status === 'skip' || result.status === 'error') {
                renderFindings(result.findings)
                blank()
                process.exit(0)
            }

            const data = result.data as { engine?: PolicyEngine; policies?: PolicyInfo[] }
            const detectedEngine = data.engine ?? 'none'
            const policyList = data.policies ?? []

            section('Detection')
            if (detectedEngine === 'none') {
                indent('No policy engine detected')
            } else {
                indent(`Engine: ${detectedEngine}`)
                indent(`Policies: ${policyList.length}`)
            }

            if (policyList.length > 0) {
                // Use engine-specific terminology to match the actual Kubernetes resource names.
                section(`${detectedEngine === 'kyverno' ? 'ClusterPolicies' : 'ConstraintTemplates'} (${policyList.length})`)
                for (const p of policyList) {
                    const action = p.validationFailureAction
                    // Annotate audit-only policies inline so operators can immediately identify enforcement gaps.
                    const mark = action?.toLowerCase() === 'audit' ? chalk.yellow('  ← audit only') : ''
                    const actionDisplay = action ? action.padEnd(12) : '—'.padEnd(12)
                    indent(`${p.name.padEnd(40)} ${actionDisplay}${mark}`)
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
