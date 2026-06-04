import type { Command } from 'commander'
import { surveyNetworkPolicies, type NamespaceNetworkStatus } from '../../../core/recon/network-policies.js'
import { header, field, section, indent, blank, renderFindings } from '../../output.js'
import { buildKubeConfig, DEFAULT_RECON_NAMESPACE, writeJsonToFile } from './utils/shared.js'

/**
 * Attaches the "network-policies" subcommand to the recon command group.
 * @param recon The recon command group to attach to.
 */
export function networkPolicies(recon: Command): void {
    recon
        .command('network-policies')
        .description('Survey NetworkPolicy coverage across all user namespaces')
        .option('--context <name>', 'Kubernetes context to use')
        .option('--namespace <name>', 'Recon namespace', DEFAULT_RECON_NAMESPACE)
        .option('--format <mode>', 'Output mode: table, json', 'table')
        .option('--output <path>', 'Write JSON result to file')
        .action(async (opts: { context?: string; namespace: string; format: string; output?: string }) => {
            const { kc, clusterContext } = buildKubeConfig(opts.context)

            let result
            try {
                result = await surveyNetworkPolicies(kc, { namespace: opts.namespace, context: opts.context })
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

            const namespaces = (result.data as { namespaces?: NamespaceNetworkStatus[] }).namespaces ?? []
            const withPolicies = namespaces.filter(n => n.policyCount > 0)
            const withoutPolicies = namespaces.filter(n => n.policyCount === 0)

            if (withPolicies.length > 0) {
                section('Namespaces with policies')
                for (const ns of withPolicies) {
                    // Build a coverage label from boolean flags e.g. 'ingress + egress'.
                    const coverage = [ns.hasIngress ? 'ingress' : null, ns.hasEgress ? 'egress' : null].filter(Boolean).join(' + ')
                    indent(`${ns.namespace} ${ns.policyCount} policies ${coverage}`)
                }
            }

            if (withoutPolicies.length > 0) {
                section('Namespaces without policies')
                for (const ns of withoutPolicies) indent(ns.namespace)
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
