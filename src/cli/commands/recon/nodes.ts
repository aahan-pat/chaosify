import type { Command } from 'commander'
import { surveyNodes, type NodeInfo } from '../../../core/recon/nodes.js'
import { header, field, section, indent, blank, renderFindings } from '../../output.js'
import { buildKubeConfig, writeJsonToFile } from './utils/shared.js'
import { DEFAULT_RECON_NAMESPACE } from '../../../constants.js'

/**
 * Attaches the "nodes" subcommand to the recon command group.
 * @param recon The recon command group to attach to.
 */
export function nodes(recon: Command): void {
    recon
        .command('nodes')
        .description('Survey node security posture: kernel, container runtime, AppArmor and seccomp')
        .option('--context <name>', 'Kubernetes context to use')
        .option('--namespace <name>', 'Recon namespace', DEFAULT_RECON_NAMESPACE)
        .option('--format <mode>', 'Output mode: table, json', 'table')
        .option('--output <path>', 'Write JSON result to file')
        .action(async (opts: { context?: string; namespace: string; format: string; output?: string }) => {
            const { kc, clusterContext } = buildKubeConfig(opts.context)

            let result
            try {
                result = await surveyNodes(kc, { namespace: opts.namespace, context: opts.context })
            } catch (err) {
                console.error(`\nError\n  Node recon failed: ${err instanceof Error ? err.message : String(err)}`)
                process.exit(2)
            }

            if (opts.output) await writeJsonToFile(opts.output, result)

            if (opts.format === 'json') {
                console.log(JSON.stringify(result, null, 2))
                process.exit(0)
            }

            header('Chaosify Recon — Node Security Posture')
            field('Cluster Context', clusterContext)

            if (result.status === 'skip' || result.status === 'error') {
                renderFindings(result.findings)
                blank()
                process.exit(0)
            }

            const nodeList = (result.data as { nodes?: NodeInfo[] }).nodes ?? []
            section(`Nodes (${nodeList.length})`)
            for (const node of nodeList) {
                blank()
                indent(node.name)
                indent(`OS: ${node.os} Kernel: ${node.kernel}`, 4)
                indent(`Runtime: ${node.runtime} Seccomp: ${node.seccompDefault}`, 4)
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
