// Implements "chaosclaw scenarios show" — displays full detail for a specific scenario by ID.
import type { Command } from 'commander'
import { ScenarioRegistry, isRuntimeScenario } from '../../../core/scenarios/registry.js'
import { SCENARIOS_DIR } from '../../../paths.js'
import { header, field, section, indent, blank } from '../../output.js'

/**
 * Attaches the "show" subcommand to the scenarios command group.
 * @param scenarios The scenarios command group to attach to.
 */
export function show(scenarios: Command): void {
    scenarios
        .command('show <id>')
        .description('Show full detail for a specific scenario')
        .option('--format <mode>', 'Output mode: table, json', 'table')
        .action(async (id: string, opts: { format: string }) => {
            const registry = await ScenarioRegistry.build(SCENARIOS_DIR)
            const scenario = registry.getScenario(id)

            if (!scenario) {
                console.error(`\nError\n  No scenario found with id "${id}"`)
                console.error('  Run "chaosclaw scenarios list" to see all available scenarios')
                process.exit(4)
            }

            if (opts.format === 'json') {
                console.log(JSON.stringify(scenario, null, 2))
                process.exit(0)
            }

            header('ChaosClaw Scenario')
            field('ID', scenario.id)
            field('Name', scenario.name)
            field('Category', scenario.category)
            field('Control', scenario.controlObjective)
            field('Expected Outcome', scenario.expectedOutcome.type.replace(/_/g, ' '))
            field('Safety', `${scenario.safety.level}${scenario.safety.namespaceScoped ? ' (namespace scoped)' : ''}`)
            if (scenario.packMembership?.length) field('Pack', scenario.packMembership.join(', '))

            section('Description')
            indent(scenario.description)

            if (scenario.prerequisites.length > 0) {
                section('Prerequisites')
                for (const p of scenario.prerequisites) {
                    indent(`${p.name}: ${p.description}`)
                }
            }

            // Runtime scenarios carry an exec step that preventive scenarios do not have.
            if (isRuntimeScenario(scenario)) {
                section('Exec Step')
                field('Container', scenario.execStep.container)
                field('Command', scenario.execStep.command.join(' '))
                if (scenario.execStep.timeoutMs !== undefined) field('Timeout', `${scenario.execStep.timeoutMs}ms`)
            }

            blank()
            process.exit(0)
        })
}
