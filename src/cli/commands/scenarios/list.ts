// Implements "chaosify scenarios list" — lists registered packs and their scenarios.
import chalk from 'chalk'
import type { Command } from 'commander'
import { ScenarioRegistry, isRuntimeScenario } from '../../../core/scenarios/registry.js'
import { SCENARIOS_DIR } from '../../../paths.js'
import { header, section, field, indent, blank } from '../../output.js'

/**
 * Attaches the "list" subcommand to the scenarios command group.
 * @param scenarios The scenarios command group to attach to.
 */
export function list(scenarios: Command): void {
    scenarios
        .command('list')
        .description('List all registered scenario packs and their scenarios')
        .option('--pack <id>', 'Show only scenarios in this pack')
        .option('--format <mode>', 'Output mode: table, json', 'table')
        .action(async (opts: { pack?: string; format: string }) => {
            const registry = await ScenarioRegistry.build(SCENARIOS_DIR)

            // Resolve the target pack list — either a single named pack or all packs.
            const packs = opts.pack
                ? [registry.getPack(opts.pack)].filter((p): p is NonNullable<typeof p> => p !== undefined)
                : registry.listPacks()

            if (opts.format === 'json') {
                // Omit the raw manifest from JSON output to keep the payload readable.
                const output = packs.map(pack => ({
                    id: pack.id,
                    name: pack.name,
                    scenarios: registry.getScenariosForPack(pack.id).map(s => ({
                        id: s.id,
                        name: s.name,
                        category: s.category,
                        expectedOutcome: s.expectedOutcome.type,
                    })),
                }))
                console.log(JSON.stringify(output, null, 2))
                process.exit(0)
            }

            header('Chaosify Scenarios')

            if (packs.length === 0) {
                blank()
                indent(opts.pack ? `No pack found: "${opts.pack}"` : 'No scenario packs registered')
                blank()
                process.exit(0)
            }

            for (const pack of packs) {
                const packScenarios = registry.getScenariosForPack(pack.id)
                section(`${pack.name}  ${chalk.dim(`(${pack.id})`)}`)
                field('Scenarios', String(packScenarios.length))

                blank()
                for (const s of packScenarios) {
                    // Color-code the category tag so preventive and detective scenarios are visually distinct.
                    const tag = isRuntimeScenario(s) ? chalk.yellow('[detective]') : chalk.dim('[preventive]')
                    indent(`${tag} ${s.id}`)
                    indent(s.name, 4)
                }
            }

            blank()
            process.exit(0)
        })
}
