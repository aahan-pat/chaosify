import type { Command } from 'commander'
import { surveyRbac } from '../../../core/recon/rbac.js'
import { header, field, section, indent, blank, renderFindings } from '../../output.js'
import { buildKubeConfig, DEFAULT_RECON_NAMESPACE, writeJsonToFile } from './utils/shared.js'

/**
 * Attaches the "rbac" subcommand to the recon command group.
 * @param recon The recon command group to attach to.
 */
export function rbac(recon: Command): void {
    recon
        .command('rbac')
        .description('Survey RBAC posture: cluster-admin bindings and high-privilege service accounts')
        .option('--context <name>', 'Kubernetes context to use')
        .option('--namespace <name>', 'Recon namespace', DEFAULT_RECON_NAMESPACE)
        .option('--format <mode>', 'Output mode: table, json', 'table')
        .option('--output <path>', 'Write JSON result to file')
        .option('--include-system', 'Include kube-system service accounts (excluded by default)')
        .action(async (opts: { context?: string; namespace: string; format: string; output?: string; includeSystem?: boolean }) => {
            const { kc, clusterContext } = buildKubeConfig(opts.context)

            let result
            try {
                result = await surveyRbac(kc, { namespace: opts.namespace, context: opts.context, includeSystem: opts.includeSystem })
            } catch (err) {
                console.error(`\nError\n  RBAC recon failed: ${err instanceof Error ? err.message : String(err)}`)
                process.exit(2)
            }

            if (opts.output) await writeJsonToFile(opts.output, result)

            if (opts.format === 'json') {
                console.log(JSON.stringify(result, null, 2))
                process.exit(0)
            }

            header('Chaosify Recon — RBAC Posture')
            field('Cluster Context', clusterContext)
            // Inform the operator when system namespace accounts are included in the analysis.
            if (opts.includeSystem) field('Scope', 'including kube-system')

            if (result.status === 'skip' || result.status === 'error') {
                renderFindings(result.findings)
                blank()
                process.exit(0)
            }

            const data = result.data as { clusterRoleCount?: number; clusterRoleBindingCount?: number; partial?: boolean }
            section('Survey')
            indent(`ClusterRoles scanned: ${data.clusterRoleCount ?? 0}`)
            indent(`ClusterRoleBindings scanned: ${data.clusterRoleBindingCount ?? 0}`)
            // Partial analysis means some resources could not be listed — findings may be incomplete.
            if (data.partial) indent('Note: analysis is partial — some resources could not be listed')

            renderFindings(result.findings)

            if (opts.output) {
                section('Artifacts')
                indent(`JSON report written to: ${opts.output}`)
            }

            blank()
            process.exit(0)
        })
}
