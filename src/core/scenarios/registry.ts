import * as k8s from '@kubernetes/client-node'
import { readFile, readdir } from 'node:fs/promises'
import { join, basename } from 'node:path'
import type { ScenarioDefinition, ScenarioPack } from '../../types/scenario.js'
import type { RuntimeScenarioDefinition } from '../../types/runtime-scenario.js'

// Converts a kebab-case directory name to a human-readable pack name.
function toPackName(dirName: string): string {
    return dirName.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')
}

export type AnyScenario = ScenarioDefinition | RuntimeScenarioDefinition

/** Returns true when the scenario is a runtime detection scenario (has an execStep). */
export function isRuntimeScenario(s: AnyScenario): s is RuntimeScenarioDefinition {
    return 'execStep' in s
}

/**
 * Central store for scenario and pack definitions.
 * Callers register definitions at startup, then query them during execution.
 */
export class ScenarioRegistry {
    private readonly scenarios = new Map<string, AnyScenario>()
    private readonly packs = new Map<string, ScenarioPack>()

    /**
     * Registers a scenario (preventive or runtime).
     * @param scenario Scenario definition to store.
     */
    register(scenario: AnyScenario): void {
        this.scenarios.set(scenario.id, scenario)
    }

    /**
     * Registers a scenario pack.
     * @param pack Pack definition to store.
     */
    registerPack(pack: ScenarioPack): void {
        this.packs.set(pack.id, pack)
    }

    /** Look up a scenario by its ID; returns undefined when not found */
    getScenario(id: string): AnyScenario | undefined {
        return this.scenarios.get(id)
    }

    /** Look up a pack by its ID; returns undefined when not found */
    getPack(id: string): ScenarioPack | undefined {
        return this.packs.get(id)
    }

    /**
     * Resolves a pack to its ordered scenario definitions.
     * IDs listed in the pack but missing from the registry are silently dropped.
     */
    getScenariosForPack(packId: string): AnyScenario[] {
        const pack = this.packs.get(packId)
        if (!pack) return []
        return pack.scenarioIds
            .map(id => this.scenarios.get(id))
            .filter((s): s is AnyScenario => s !== undefined)
    }

    /** Return all registered scenarios as a flat array */
    listScenarios(): AnyScenario[] {
        return Array.from(this.scenarios.values())
    }

    /** Return all registered packs as a flat array */
    listPacks(): ScenarioPack[] {
        return Array.from(this.packs.values())
    }

    hasScenario(id: string): boolean {
        return this.scenarios.has(id)
    }

    hasPack(id: string): boolean {
        return this.packs.has(id)
    }

    /**
     * Loads a pack directory: derives pack metadata from the directory name and registers
     * all *.yaml files as scenarios. No pack.yaml needed — the folder is the pack.
     * @param packDir Absolute path to the pack directory.
     */
    async loadPack(packDir: string): Promise<void> {
        const packId = basename(packDir)

        // Load all scenario files in sorted order so pack membership is deterministic.
        const files = (await readdir(packDir)).filter(f => f.endsWith('.yaml')).sort()
        const scenarioIds: string[] = []
        for (const file of files) {
            const scenario = await this.loadScenarioFile(join(packDir, file), packId)
            scenarioIds.push(scenario.id)
        }

        // Register the pack using the directory name as both id and display name source.
        this.registerPack({ id: packId, version: 1, name: toPackName(packId), description: '', scenarioIds })
    }

    /**
     * Loads a single scenario YAML file, registers it, and returns it.
     * Detects runtime scenarios by the presence of an execStep field.
     * @param filePath Absolute path to the scenario YAML file.
     * @param packId Pack to associate this scenario with.
     */
    async loadScenarioFile(filePath: string, packId: string): Promise<AnyScenario> {
        const raw = await readFile(filePath, 'utf-8')
        const data = k8s.loadYaml(raw) as Record<string, unknown>
        // Assign packMembership from directory context rather than requiring it in every file.
        const scenario = { ...data, packMembership: [packId] } as AnyScenario
        this.register(scenario)
        return scenario
    }

    /**
     * Builds and returns a registry loaded from all pack directories under scenariosDir.
     * Discovers pack directories automatically — each subdirectory must contain a pack.yaml.
     * @param scenariosDir Absolute path to the scenarios root directory.
     */
    static async build(scenariosDir: string): Promise<ScenarioRegistry> {
        const registry = new ScenarioRegistry()
        const entries = await readdir(scenariosDir, { withFileTypes: true })
        for (const entry of entries) {
            if (entry.isDirectory()) {
                await registry.loadPack(join(scenariosDir, entry.name))
            }
        }
        return registry
    }
}
