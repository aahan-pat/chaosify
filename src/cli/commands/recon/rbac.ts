import type { Command } from 'commander'
import { surveyRbac } from '../../../core/recon/rbac.js'
import { header, field, section, indent, blank, renderFindings } from '../../output.js'
import { buildKubeConfig, writeJsonToFile, writeTextToFile } from './utils/shared.js'
import { buildReconSummary } from '../../recon-summary.js'
import { DEFAULT_RECON_NAMESPACE } from '../../../constants.js'
import type { RbacThreatGraph } from '../../../types/recon.js'

/**
 * Attaches the "rbac" subcommand to the recon command group.
 * @param recon The recon command group to attach to.
 */
export function rbac(recon: Command): void {
    recon
        .command('rbac')
        .description('Survey RBAC posture: harvest pod ServiceAccount tokens and flag exploitable privilege chains')
        .option('--context <name>', 'Kubernetes context to use')
        .option('--namespace <name>', 'Recon namespace', DEFAULT_RECON_NAMESPACE)
        .option('--format <mode>', 'Output mode: table, json, summary', 'table')
        .option('--output <path>', 'Write JSON result to file')
        .option('--include-system', 'Include system-namespace pods (excluded by default)')
        .action(async (opts: { context?: string; namespace: string; format: string; output?: string; includeSystem?: boolean }) => {
            const { kc, clusterContext } = buildKubeConfig(opts.context)

            let result
            try {
                result = await surveyRbac(kc, { namespace: opts.namespace, context: opts.context, includeSystem: opts.includeSystem })
            } catch (err) {
                console.error(`\nError\n  RBAC recon failed: ${err instanceof Error ? err.message : String(err)}`)
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

            header('Chaosify Recon — RBAC')
            field('Cluster Context', clusterContext)

            if (result.status === 'skip' || result.status === 'error') {
                renderFindings(result.findings)
                blank()
                process.exit(0)
            }

            const data = result.data as RbacThreatGraph
            section('Threat Graph')
            indent(`Pods scanned: ${data.podsScanned ?? 0}`)
            indent(`Tokens harvested: ${data.tokensHarvested ?? 0}`)
            indent(`Exploit chains:  ${data.findings?.length ?? 0}`)

            // Pod → SA → Permissions → Impact, one block per discovered chain.
            for (const f of data.findings ?? []) {
                blank()
                const crossNs = f.crossNamespaceAccess ? '  [cross-namespace]' : ''
                indent(`${f.pod} (ns ${f.namespace})  sa: ${f.serviceAccount}  [${f.severity}]${crossNs}`)
                indent(`Exploit classes: ${f.exploitClasses.join(', ')}`, 4)
                for (const p of f.dangerousPermissions) {
                    const groups = p.apiGroups.length > 0 ? ` (apiGroups: ${p.apiGroups.join(',')})` : ''
                    indent(`${p.verbs.join(',')} on ${p.resources.join(',')}${groups}`, 4)
                }
                indent(`Chain: ${f.attackChain}`, 4)
            }

            renderFindings(result.findings)

            // Surface what pod-first recon could not see so conclusions stay scoped.
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
