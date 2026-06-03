import { describe, it, expect } from 'vitest'
import { ValidationEngine } from '../../../src/core/validation/validator.js'
import type { ScenarioDefinition } from '../../../src/types/scenario.js'
import type { ExecutionResult } from '../../../src/core/scenarios/exec/executor.js'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeScenario(expectedOutcome: 'admission_rejected' | 'admission_allowed'): ScenarioDefinition {
  return {
    id: 'test-scenario',
    version: 1,
    name: 'Test',
    description: 'A test scenario',
    category: 'preventive',
    controlObjective: 'Prevent privileged containers',
    prerequisites: [],
    manifest: {},
    expectedOutcome: { type: expectedOutcome },
    cleanup: { deleteCreatedResources: true },
    safety: { level: 'low', namespaceScoped: true },
  }
}

function makeExecution(observedOutcome: ExecutionResult['observedOutcome']): ExecutionResult {
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

describe('ValidationEngine', () => {
  const engine = new ValidationEngine()

  describe('infra-level errors', () => {
    it('maps timeout to Error status', () => {
      const result = engine.validate(makeScenario('admission_rejected'), makeExecution('timeout'))
      expect(result.status).toBe('Error')
      expect(result.observedOutcome).toBe('timeout')
      expect(result.likelyIssue).toMatch(/timed out/i)
    })

    it('maps api_error to Error status', () => {
      const result = engine.validate(makeScenario('admission_rejected'), makeExecution('api_error'))
      expect(result.status).toBe('Error')
      expect(result.observedOutcome).toBe('api_error')
      expect(result.likelyIssue).toMatch(/unexpected error/i)
    })
  })

  describe('passing scenarios', () => {
    it('returns Pass when admission_rejected was expected and observed', () => {
      const result = engine.validate(makeScenario('admission_rejected'), makeExecution('admission_rejected'))
      expect(result.status).toBe('Pass')
      expect(result.likelyIssue).toBeUndefined()
    })

    it('returns Pass when admission_allowed was expected and observed', () => {
      const result = engine.validate(makeScenario('admission_allowed'), makeExecution('admission_allowed'))
      expect(result.status).toBe('Pass')
      expect(result.likelyIssue).toBeUndefined()
    })
  })

  describe('failing scenarios', () => {
    it('returns Fail with policy-not-installed hint when rejection expected but workload was admitted', () => {
      const scenario = makeScenario('admission_rejected')
      const result = engine.validate(scenario, makeExecution('admission_allowed'))
      expect(result.status).toBe('Fail')
      expect(result.observedOutcome).toBe('workload admitted')
      expect(result.likelyIssue).toContain(scenario.controlObjective)
      expect(result.likelyIssue).toMatch(/policy may not be installed/i)
    })

    it('returns Fail with over-restrictive hint when allowance expected but workload was rejected', () => {
      const scenario = makeScenario('admission_allowed')
      const result = engine.validate(scenario, makeExecution('admission_rejected'))
      expect(result.status).toBe('Fail')
      expect(result.observedOutcome).toBe('admission rejected')
      expect(result.likelyIssue).toMatch(/more restrictive than expected/i)
      expect(result.likelyIssue).toContain(scenario.controlObjective)
    })
  })

  describe('observedOutcome labels', () => {
    it('labels admission_rejected as "admission rejected"', () => {
      const result = engine.validate(makeScenario('admission_allowed'), makeExecution('admission_rejected'))
      expect(result.observedOutcome).toBe('admission rejected')
    })

    it('labels admission_allowed as "workload admitted"', () => {
      const result = engine.validate(makeScenario('admission_rejected'), makeExecution('admission_allowed'))
      expect(result.observedOutcome).toBe('workload admitted')
    })
  })
})
