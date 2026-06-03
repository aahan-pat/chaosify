import { describe, it, expect, beforeEach } from 'vitest'
import { ScenarioRegistry } from '../../../src/core/scenarios/registry.js'
import type { ScenarioDefinition, ScenarioPack } from '../../../src/types/scenario.js'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeScenario(id: string): ScenarioDefinition {
  return {
    id,
    version: 1,
    name: `Scenario ${id}`,
    description: 'Test scenario',
    category: 'preventive',
    controlObjective: 'Prevent X',
    prerequisites: [],
    manifest: {},
    expectedOutcome: { type: 'admission_rejected' },
    cleanup: { deleteCreatedResources: true },
    safety: { level: 'low', namespaceScoped: true },
  }
}

function makePack(id: string, scenarioIds: string[]): ScenarioPack {
  return {
    id,
    version: 1,
    name: `Pack ${id}`,
    description: 'Test pack',
    scenarioIds,
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ScenarioRegistry', () => {
  let registry: ScenarioRegistry

  beforeEach(() => {
    registry = new ScenarioRegistry()
  })

  describe('register / getScenario', () => {
    it('returns a registered scenario by id', () => {
      const s = makeScenario('deny-privileged')
      registry.register(s)
      expect(registry.getScenario('deny-privileged')).toEqual(s)
    })

    it('returns undefined for an unregistered scenario', () => {
      expect(registry.getScenario('not-there')).toBeUndefined()
    })

    it('overwrites a previously registered scenario with the same id', () => {
      registry.register(makeScenario('s1'))
      const updated = { ...makeScenario('s1'), name: 'Updated' }
      registry.register(updated)
      expect(registry.getScenario('s1')?.name).toBe('Updated')
    })
  })

  describe('registerPack / getPack', () => {
    it('returns a registered pack by id', () => {
      const p = makePack('preventive-baseline', ['s1'])
      registry.registerPack(p)
      expect(registry.getPack('preventive-baseline')).toEqual(p)
    })

    it('returns undefined for an unregistered pack', () => {
      expect(registry.getPack('missing-pack')).toBeUndefined()
    })
  })

  describe('getScenariosForPack', () => {
    it('returns all scenarios in the pack when all are registered', () => {
      registry.register(makeScenario('s1'))
      registry.register(makeScenario('s2'))
      registry.registerPack(makePack('pack-a', ['s1', 's2']))

      const results = registry.getScenariosForPack('pack-a')
      expect(results).toHaveLength(2)
      expect(results.map(s => s.id)).toEqual(expect.arrayContaining(['s1', 's2']))
    })

    it('silently drops scenario IDs that are not registered', () => {
      registry.register(makeScenario('s1'))
      registry.registerPack(makePack('pack-b', ['s1', 'missing-scenario']))

      const results = registry.getScenariosForPack('pack-b')
      expect(results).toHaveLength(1)
      expect(results[0]?.id).toBe('s1')
    })

    it('returns an empty array for a pack that has no registered scenarios', () => {
      registry.registerPack(makePack('pack-c', ['ghost1', 'ghost2']))
      expect(registry.getScenariosForPack('pack-c')).toEqual([])
    })

    it('returns an empty array when the pack itself is not registered', () => {
      expect(registry.getScenariosForPack('no-such-pack')).toEqual([])
    })
  })

  describe('listScenarios / listPacks', () => {
    it('returns all registered scenarios', () => {
      registry.register(makeScenario('a'))
      registry.register(makeScenario('b'))
      expect(registry.listScenarios()).toHaveLength(2)
    })

    it('returns an empty array when no scenarios are registered', () => {
      expect(registry.listScenarios()).toEqual([])
    })

    it('returns all registered packs', () => {
      registry.registerPack(makePack('pack-x', []))
      registry.registerPack(makePack('pack-y', []))
      expect(registry.listPacks()).toHaveLength(2)
    })
  })

  describe('hasScenario / hasPack', () => {
    it('returns true for a registered scenario', () => {
      registry.register(makeScenario('exists'))
      expect(registry.hasScenario('exists')).toBe(true)
    })

    it('returns false for an unregistered scenario', () => {
      expect(registry.hasScenario('nope')).toBe(false)
    })

    it('returns true for a registered pack', () => {
      registry.registerPack(makePack('my-pack', []))
      expect(registry.hasPack('my-pack')).toBe(true)
    })

    it('returns false for an unregistered pack', () => {
      expect(registry.hasPack('no-pack')).toBe(false)
    })
  })
})
