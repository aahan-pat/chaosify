import { describe, it, expect } from 'vitest'
import { RuntimeValidationEngine } from '../../../src/core/validation/runtime-validator.js'
import type { RuntimeScenarioDefinition } from '../../../src/types/runtime-scenario.js'
import type { RuntimeExecutionResult } from '../../../src/core/scenarios/exec/runtime-executor.js'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeScenario(expectedOutcome: 'alert_fired' | 'action_blocked'): RuntimeScenarioDefinition {
  return {
    id: 'test-runtime-scenario',
    version: 1,
    name: 'Test runtime scenario',
    description: 'A runtime detection test',
    category: 'detective',
    controlObjective: 'Detect sensitive file read',
    prerequisites: [],
    manifest: {},
    execStep: { container: 'test', command: ['cat', '/etc/shadow'] },
    expectedOutcome: { type: expectedOutcome },
    cleanup: { deleteCreatedResources: true },
    safety: { level: 'low', namespaceScoped: true },
  }
}

function makeExecution(observedOutcome: RuntimeExecutionResult['observedOutcome']): RuntimeExecutionResult {
  return {
    observedOutcome,
    rawResponse: '{}',
    manifestSnapshot: '{}',
    startedAt: new Date().toISOString(),
    endedAt: new Date().toISOString(),
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('RuntimeValidationEngine', () => {
  const engine = new RuntimeValidationEngine()

  describe('infra-level errors', () => {
    it('maps timeout to Error status', () => {
      const result = engine.validate(makeScenario('alert_fired'), makeExecution('timeout'))
      expect(result.status).toBe('Error')
      expect(result.observedOutcome).toBe('timeout')
      expect(result.likelyIssue).toMatch(/timed out/i)
    })

    it('maps api_error to Error status', () => {
      const result = engine.validate(makeScenario('alert_fired'), makeExecution('api_error'))
      expect(result.status).toBe('Error')
      expect(result.observedOutcome).toBe('api_error')
      expect(result.likelyIssue).toMatch(/api error/i)
    })
  })

  describe('passing scenarios', () => {
    it('returns Pass when alert_fired was expected and observed', () => {
      const result = engine.validate(makeScenario('alert_fired'), makeExecution('alert_fired'))
      expect(result.status).toBe('Pass')
      expect(result.likelyIssue).toBeUndefined()
    })

    it('returns Pass when action_blocked was expected and observed', () => {
      const result = engine.validate(makeScenario('action_blocked'), makeExecution('action_blocked'))
      expect(result.status).toBe('Pass')
      expect(result.likelyIssue).toBeUndefined()
    })
  })

  describe('failing scenarios', () => {
    it('returns Fail with runtime-tool hint when alert expected but no alert observed', () => {
      const scenario = makeScenario('alert_fired')
      const result = engine.validate(scenario, makeExecution('no_alert'))
      expect(result.status).toBe('Fail')
      expect(result.observedOutcome).toBe('no alert observed')
      expect(result.likelyIssue).toContain(scenario.controlObjective)
      expect(result.likelyIssue).toMatch(/runtime tool may not be installed/i)
    })

    it('returns Fail with runtime-tool hint when action_blocked expected but no alert observed', () => {
      const scenario = makeScenario('action_blocked')
      const result = engine.validate(scenario, makeExecution('no_alert'))
      expect(result.status).toBe('Fail')
      expect(result.likelyIssue).toMatch(/runtime tool may not be installed/i)
    })

    it('returns Fail for unexpected mismatches (alert_fired vs action_blocked)', () => {
      const result = engine.validate(makeScenario('action_blocked'), makeExecution('alert_fired'))
      expect(result.status).toBe('Fail')
      expect(result.likelyIssue).toMatch(/unexpected outcome/i)
    })
  })

  describe('observedOutcome labels', () => {
    it('labels alert_fired as "alert fired"', () => {
      const result = engine.validate(makeScenario('action_blocked'), makeExecution('alert_fired'))
      expect(result.observedOutcome).toBe('alert fired')
    })

    it('labels action_blocked as "action blocked"', () => {
      const result = engine.validate(makeScenario('alert_fired'), makeExecution('action_blocked'))
      expect(result.observedOutcome).toBe('action blocked')
    })

    it('labels no_alert as "no alert observed"', () => {
      const result = engine.validate(makeScenario('alert_fired'), makeExecution('no_alert'))
      expect(result.observedOutcome).toBe('no alert observed')
    })
  })
})
