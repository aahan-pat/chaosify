import type { Command } from 'commander'
import { surveyNetworkPolicies } from '../../../core/recon/network-policies.js'
import { header, field, section, indent, blank, renderFindings } from '../../output.js'
import { buildKubeConfig, writeJsonToFile } from './utils/shared.js'
import { DEFAULT_RECON_NAMESPACE } from '../../../constants.js'
import type { NetpolThreatGraph } from '../../../types/recon.js'

/**
 * Attaches the "network-policies" subcommand to the recon command group.
 * @param recon The recon command group to attach to.
 */
export function networkPolicies(recon: Command): void {
    recon
        .command('network-policies')
        .description('Survey NetworkPolicy coverage from reachable pods and flag open network paths')
        .option('--context <name>', 'Kubernetes context to use')
        .option('--namespace <name>', 'Recon namespace', DEFAULT_RECON_NAMESPACE)
        .option('--format <mode>', 'Output mode: table, json', 'table')
        .option('--output <path>', 'Write JSON result to file')
        .option('--include-system', 'Include system-namespace pods (excluded by default)')
        .action(async (opts: { context?: string; namespace: string; format: string; output?: string; includeSystem?: boolean }) => {
            const { kc, clusterContext } = buildKubeConfig(opts.context)

            let result
            try {
                result = await surveyNetworkPolicies(kc, { namespace: opts.namespace, context: opts.context, includeSystem: opts.includeSystem })
            } catch (err) {
                console.error(`\nError\n  Network policy recon failed: ${err instanceof Error ? err.message : String(err)}`)
                process.exit(2)
            }

            if (opts.output) await writeJsonToFile(opts.output, result)

            if (opts.format === 'json') {
                console.log(JSON.stringify(result, null, 2))
                process.exit(0)
            }

            header('Chaosify Recon — Network Policies')
            field('Cluster Context', clusterContext)

            if (result.status === 'skip' || result.status === 'error') {
                renderFindings(result.findings)
                blank()
                process.exit(0)
            }

            const data = result.data as NetpolThreatGraph
            section('Exposure Graph')
            indent(`Pods scanned:     ${data.podsScanned ?? 0}`)
            indent(`Policies scanned: ${data.policiesScanned ?? 0}`)
            indent(`Open paths:       ${data.findings?.length ?? 0}`)

            // namespace → entry-point pod → reachable target → impact, one block per open path.
            for (const f of data.findings ?? []) {
                blank()
                const more = f.podCount > 1 ? `  (+${f.podCount - 1} more pod(s))` : ''
                indent(`${f.namespace}  pod: ${f.examplePod}  [${f.severity}]${more}`)
                indent(`Exploit classes: ${f.exploitClasses.join(', ')}`, 4)
                indent(`Impact: ${f.impact}`, 4)
                indent(`Probe:  ${f.suggestedProbe}`, 4)
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
