import { ScenarioRegistry } from '../../../../core/scenarios/registry.js'
import { SCENARIOS_DIR } from '../../../../paths.js'

// Re-export so callers (run-scenarios, print-results) keep working without path changes.
export type { AnyScenario } from '../../../../core/scenarios/registry.js'
export { isRuntimeScenario } from '../../../../core/scenarios/registry.js'

/**
 * Resolves the target scenario list from CLI options.
 * @param opts Pack or scenario ID from CLI flags.
 */
export async function resolveScenarios(opts: { pack?: string; scenario?: string }): Promise<import('../../../../core/scenarios/registry.js').AnyScenario[]> {
    const registry = await ScenarioRegistry.build(SCENARIOS_DIR)

    if (opts.pack) return registry.getScenariosForPack(opts.pack)

    if (opts.scenario) {
        const s = registry.getScenario(opts.scenario)
        return s ? [s] : []
    }

    return []
}
