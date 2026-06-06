import type { Command } from 'commander'
import chalk from 'chalk'
import { surveyTopology, GRAPHNETES_REPO } from '../../../core/recon/topology.js'
import { header, field, section, indent, blank } from '../../output.js'
import { buildKubeConfig, writeJsonToFile } from './utils/shared.js'
import { DEFAULT_RECON_NAMESPACE } from '../../../constants.js'

/**
 * Attaches the "topology" subcommand to the recon command group.
 * @param recon The recon command group to attach to.
 */
export function topology(recon: Command): void {
    recon
        .command('topology')
        .description('Map cluster resource topology using graphnetes: ingress paths, secret mounts, service account bindings')
        .option('--context <name>', 'Kubernetes context to use')
        .option('--namespace <name>', 'Scope graph build to a namespace', DEFAULT_RECON_NAMESPACE)
        .option('--graph <path>', 'Use an existing graphnetes graph.json — skips the build step')
        .option('--format <mode>', 'Output mode: table, json', 'table')
        .option('--output <path>', 'Write JSON result to file')
        .action(async (opts: { context?: string; namespace: string; graph?: string; format: string; output?: string }) => {
            const silent = opts.format === 'json'

            let result
            try {
                result = await surveyTopology(opts.graph, { namespace: opts.namespace, context: opts.context }, silent)
            } catch (err) {
                console.error(`\nError\n  Topology recon failed: ${err instanceof Error ? err.message : String(err)}`)
                process.exit(2)
            }

            if (opts.output) await writeJsonToFile(opts.output, result)

            if (opts.format === 'json') {
                console.log(JSON.stringify(result, null, 2))
                process.exit(0)
            }

            // graphnetes not installed — prompt the user with the install link and exit cleanly.
            if (result.status === 'skip') {
                blank()
                console.log(chalk.yellow('graphnetes is not installed'))
                blank()
                indent('Topology recon requires graphnetes to build a cluster resource graph.')
                indent(`Install it from: ${chalk.cyan(GRAPHNETES_REPO)}`)
                blank()
                indent('Once installed, re-run:')
                indent(`chaosify recon topology${opts.context ? ` --context ${opts.context}` : ''}`, 4)
                blank()
                process.exit(0)
            }

            if (result.status === 'error') {
                const data = result.data as { error?: string }
                console.error(`\nError\n  ${data.error ?? 'Unknown error'}`)
                process.exit(2)
            }

            const { clusterContext } = buildKubeConfig(opts.context)

            header('Chaosify Recon — Cluster Topology')
            field('Cluster Context', clusterContext)
            field('Namespace', opts.namespace)
            if (opts.graph) field('Graph Source', opts.graph)

            const data = result.data as { graphPath?: string }
            if (data.graphPath) {
                section('Graph')
                indent(`Built: ${data.graphPath}`)
            }

            if (opts.output) {
                section('JSON Report')
                indent(`Written to: ${opts.output}`)
            }

            blank()
            process.exit(0)
        })
}
