import type { Command } from 'commander'
import { surveyPsa } from '../../../core/recon/psa.js'
import { header, field, section, indent, blank, renderFindings } from '../../output.js'
import { buildKubeConfig, writeJsonToFile, writeTextToFile } from './utils/shared.js'
import { buildReconSummary } from '../../recon-summary.js'
import { DEFAULT_RECON_NAMESPACE } from '../../../constants.js'
import type { PsaThreatGraph } from '../../../types/recon.js'

/**
 * Attaches the "psa" subcommand to the recon command group.
 * @param recon The recon command group to attach to.
 */
export function psa(recon: Command): void {
    recon
        .command('psa')
        .description('Survey Pod Security Admission enforcement from reachable pods and flag open security gaps')
        .option('--context <name>', 'Kubernetes context to use')
        .option('--namespace <name>', 'Recon namespace', DEFAULT_RECON_NAMESPACE)
        .option('--format <mode>', 'Output mode: table, json, summary', 'table')
        .option('--output <path>', 'Write JSON result to file')
        .option('--include-system', 'Include system-namespace pods (excluded by default)')
        .action(async (opts: { context?: string; namespace: string; format: string; output?: string; includeSystem?: boolean }) => {
            const { kc, clusterContext } = buildKubeConfig(opts.context)

            let result
            try {
                result = await surveyPsa(kc, { namespace: opts.namespace, context: opts.context, includeSystem: opts.includeSystem })
            } catch (err) {
                console.error(`\nError\n  PSA recon failed: ${err instanceof Error ? err.message : String(err)}`)
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

            header('Chaosify Recon — Pod Security Admission')
            field('Cluster Context', clusterContext)

            if (result.status === 'skip' || result.status === 'error') {
                renderFindings(result.findings)
                blank()
                process.exit(0)
            }

            const data = result.data as PsaThreatGraph
            section('Enforcement Gap Graph')
            indent(`Pods scanned:        ${data.podsScanned ?? 0}`)
            indent(`Namespaces surveyed: ${data.namespacesScanned ?? 0}`)
            indent(`Enforcement gaps:    ${data.findings?.length ?? 0}`)

            // namespace → entry-point pod → PSA gap → impact, one block per open path.
            for (const f of data.findings ?? []) {
                blank()
                const more = f.podCount > 1 ? `  (+${f.podCount - 1} more pod(s))` : ''
                const auditTag = f.auditOnly ? '  [audit-only]' : ''
                // Distinguish a confirmed reachable chain from a merely-permissive namespace.
                const confirmTag = f.confirmed ? '  [confirmed]' : '  [potential]'
                indent(`${f.namespace}  pod: ${f.examplePod}  enforce: ${f.enforceLevel}  [${f.severity}]${confirmTag}${auditTag}${more}`)
                indent(`Exploit classes: ${f.exploitClasses.join(', ')}`, 4)
                if (f.observedTraits.length > 0) indent(`Observed traits: ${f.observedTraits.join(', ')}`, 4)
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
