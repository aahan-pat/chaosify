import chalk from 'chalk'
import type { Command } from 'commander'
import type { RunOpts } from './validate-opts.js'
import { validateOpts } from './validate-opts.js'
import { resolveScenarios, isRuntimeScenario } from './resolve.js'
import { loadManifestScenario } from './manifest.js'
import { buildRunContext } from './run-context.js'
import { runScenarios } from './run-scenarios.js'
import { printHeader, printSummary } from './print-results.js'
import { DEFAULT_PROBE_NAMESPACE } from '../utils/shared.js'

/**
 * Attaches the "run" subcommand to the probe command group.
 * Exactly one of --pack, --scenario, or --manifest must be provided.
 * Exit codes: 0 = all pass, 1 = failures, 2 = execution error, 4 = invalid args.
 */
export function run(probe: Command): void {
    probe
        .command('run')
        .description('Run verification scenarios against the target cluster')
        .option('--pack <id>', 'Scenario pack to run')
        .option('--scenario <id>', 'Single scenario to run')
        .option('--manifest <path>', 'Path to a Pod manifest file (YAML or JSON) to test against the cluster')
        .option('--expect <outcome>', 'Expected admission outcome when using --manifest: rejected or allowed')
        .option('--context <name>', 'Kubernetes context to use')
        .option('--namespace <name>', 'Test namespace', DEFAULT_PROBE_NAMESPACE)
        .option('--alert-source <tool>', 'Runtime alert source: none (default), falco, tetragon, kubearmor', 'none')
        .option('--output <path>', 'Write JSON evidence artifact to file')
        .option('--format <mode>', 'Output mode: table, json', 'table')
        .option('--timeout <ms>', 'Per-scenario timeout in milliseconds')
        .option('--fail-fast', 'Stop after first failed scenario')
        .option('--cleanup <mode>', 'Cleanup mode: always, on-success', 'always')
        .option('--verbose', 'Print raw API response and manifest snapshot for each non-passing scenario')
        .action(async (opts: RunOpts) => {
            validateOpts(opts)

            const targetScenarios = opts.manifest
                ? [await loadManifestScenario(opts.manifest, opts.expect!)]
                : await resolveScenarios(opts)

            if (!opts.manifest && targetScenarios.length === 0) {
                console.error(`\nError\n  No scenarios found for ${opts.pack ? `pack "${opts.pack}"` : `scenario "${opts.scenario}"`}`)
                process.exit(4)
            }

            const hasRuntime = targetScenarios.some(isRuntimeScenario)

            if (hasRuntime && opts.alertSource === 'none' && opts.format !== 'json') {
                console.log(chalk.yellow('\n[WARN] No alert source configured (--alert-source none)'))
                console.log(chalk.yellow('       Runtime scenarios will execute but all observed outcomes will be "no_alert".'))
                console.log(chalk.yellow('       Use --alert-source falco, tetragon, or kubearmor to poll a real detection tool.\n'))
            }

            const ctx = await buildRunContext({ ...opts, hasRuntime })

            if (opts.format !== 'json') {
                printHeader(ctx.clusterContext, targetScenarios, { ...opts, hasRuntime })
            }

            const { exitCode, notRun } = await runScenarios(targetScenarios, ctx, opts)

            const evidence = ctx.builder.build(new Date().toISOString())

            if (opts.format === 'json') {
                console.log(JSON.stringify(evidence, null, 2))
                process.exit(exitCode)
            }

            if (opts.output) await ctx.builder.writeToFile(opts.output, evidence)

            printSummary(evidence, notRun, exitCode, opts)

            process.exit(exitCode)
        })
}
