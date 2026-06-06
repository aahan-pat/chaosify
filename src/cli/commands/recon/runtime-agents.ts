import type { Command } from 'commander'
import { surveyRuntimeAgents, type AgentStatus } from '../../../core/recon/runtime-agents.js'
import { header, field, section, indent, blank, renderFindings } from '../../output.js'
import { buildKubeConfig, writeJsonToFile } from './utils/shared.js'
import { DEFAULT_RECON_NAMESPACE } from '../../../constants.js'

/**
 * Attaches the "runtime-agents" subcommand to the recon command group.
 * @param recon The recon command group to attach to.
 */
export function runtimeAgents(recon: Command): void {
    recon
        .command('runtime-agents')
        .description('Detect runtime security agents: Falco, KubeArmor, Tetragon, Tracee')
        .option('--context <name>', 'Kubernetes context to use')
        .option('--namespace <name>', 'Recon namespace', DEFAULT_RECON_NAMESPACE)
        .option('--format <mode>', 'Output mode: table, json', 'table')
        .option('--output <path>', 'Write JSON result to file')
        .action(async (opts: { context?: string; namespace: string; format: string; output?: string }) => {
            const { kc, clusterContext } = buildKubeConfig(opts.context)

            let result
            try {
                result = await surveyRuntimeAgents(kc, { namespace: opts.namespace, context: opts.context })
            } catch (err) {
                console.error(`\nError\n  Runtime agent recon failed: ${err instanceof Error ? err.message : String(err)}`)
                process.exit(2)
            }

            if (opts.output) await writeJsonToFile(opts.output, result)

            if (opts.format === 'json') {
                console.log(JSON.stringify(result, null, 2))
                process.exit(0)
            }

            header('Chaosify Recon — Runtime Agents')
            field('Cluster Context', clusterContext)

            if (result.status === 'skip' || result.status === 'error') {
                renderFindings(result.findings)
                blank()
                process.exit(0)
            }

            const data = result.data as { daemonsetsScanned?: number; agents?: AgentStatus[] }
            section('Runtime Detection')
            for (const agent of data.agents ?? []) {
                if (agent.detected) {
                    // Show partial coverage inline so under-rolled DaemonSets are immediately visible.
                    const coverage = agent.readyNodes === agent.desiredNodes
                        ? 'full node coverage'
                        : `${agent.readyNodes}/${agent.desiredNodes} nodes`
                    indent(`${agent.name}: detected (${coverage})`)
                } else {
                    indent(`${agent.name}: not detected`)
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
