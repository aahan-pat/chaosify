import { describe, it, expect } from 'vitest'
import { EvidenceBuilder } from '../../../src/core/teardown/evidence-builder.js'
import type { ScenarioResult } from '../../../src/types/evidence.js'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeResult(status: ScenarioResult['status']): ScenarioResult {
  return {
    scenarioId: `scenario-${status.toLowerCase()}`,
    version: 1,
    status,
    expectedOutcome: 'admission rejected',
    observedOutcome: 'admission rejected',
    cleanupStatus: 'success',
    startedAt: new Date().toISOString(),
    endedAt: new Date().toISOString(),
  }
}

const BASE_OPTIONS = {
  clusterContext: 'test-cluster',
  packId: 'preventive-baseline',
  packVersion: '1',
  startedAt: '2026-01-01T00:00:00.000Z',
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('EvidenceBuilder', () => {
  describe('build()', () => {
    it('includes the cluster context and pack metadata', () => {
      const builder = new EvidenceBuilder(BASE_OPTIONS)
      const evidence = builder.build('2026-01-01T00:01:00.000Z')

      expect(evidence.clusterContext).toBe('test-cluster')
      expect(evidence.packId).toBe('preventive-baseline')
      expect(evidence.packVersion).toBe('1')
    })

    it('propagates startedAt and the provided endedAt', () => {
      const builder = new EvidenceBuilder(BASE_OPTIONS)
      const evidence = builder.build('2026-01-01T00:02:00.000Z')

      expect(evidence.startedAt).toBe('2026-01-01T00:00:00.000Z')
      expect(evidence.endedAt).toBe('2026-01-01T00:02:00.000Z')
    })

    it('generates a UUID runId per instance', () => {
      const a = new EvidenceBuilder(BASE_OPTIONS).build('2026-01-01T00:00:01.000Z')
      const b = new EvidenceBuilder(BASE_OPTIONS).build('2026-01-01T00:00:02.000Z')

      expect(a.runId).toMatch(/^[0-9a-f-]{36}$/)
      expect(b.runId).toMatch(/^[0-9a-f-]{36}$/)
      expect(a.runId).not.toBe(b.runId)
    })

    it('includes the toolVersion field', () => {
      const builder = new EvidenceBuilder(BASE_OPTIONS)
      const evidence = builder.build(new Date().toISOString())
      expect(typeof evidence.toolVersion).toBe('string')
      expect(evidence.toolVersion.length).toBeGreaterThan(0)
    })

    it('propagates all added results into the evidence', () => {
      const builder = new EvidenceBuilder(BASE_OPTIONS)
      builder.addResult(makeResult('Pass'))
      builder.addResult(makeResult('Fail'))

      const evidence = builder.build(new Date().toISOString())
      expect(evidence.results).toHaveLength(2)
    })

    it('sets scenarioId when provided instead of packId', () => {
      const builder = new EvidenceBuilder({
        clusterContext: 'ctx',
        scenarioId: 'deny-privileged',
        startedAt: new Date().toISOString(),
      })
      const evidence = builder.build(new Date().toISOString())
      expect(evidence.scenarioId).toBe('deny-privileged')
      expect(evidence.packId).toBeUndefined()
    })
  })

  describe('summary counts', () => {
    it('returns all-zero summary when no results were added', () => {
      const evidence = new EvidenceBuilder(BASE_OPTIONS).build(new Date().toISOString())
      expect(evidence.summary).toEqual({ pass: 0, fail: 0, error: 0, skipped: 0 })
    })

    it('correctly counts each outcome type', () => {
      const builder = new EvidenceBuilder(BASE_OPTIONS)
      builder.addResult(makeResult('Pass'))
      builder.addResult(makeResult('Pass'))
      builder.addResult(makeResult('Fail'))
      builder.addResult(makeResult('Error'))
      builder.addResult(makeResult('Skipped'))

      const { summary } = builder.build(new Date().toISOString())
      expect(summary.pass).toBe(2)
      expect(summary.fail).toBe(1)
      expect(summary.error).toBe(1)
      expect(summary.skipped).toBe(1)
    })
  })
})
