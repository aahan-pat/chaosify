import { describe, it, expect } from 'vitest'
import { runStep } from '../../../../src/core/utils/step.js'

describe('runStep', () => {
  describe('success', () => {
    it('returns ok with the step name when the operation resolves', async () => {
      const step = await runStep('create-namespace', () => Promise.resolve())
      expect(step.status).toBe('ok')
      expect(step.name).toBe('create-namespace')
    })

    it('returns no detail field on success', async () => {
      const step = await runStep('create-quota', () => Promise.resolve())
      expect(step.detail).toBeUndefined()
    })
  })

  describe('already-existed (409 Conflict)', () => {
    it('returns already-existed when the operation throws { statusCode: 409 }', async () => {
      const conflict = Object.assign(new Error('Conflict'), { statusCode: 409 })
      const step = await runStep('create-sa', () => Promise.reject(conflict))
      expect(step.status).toBe('already-existed')
    })

    it('returns no detail field for a conflict', async () => {
      const conflict = Object.assign(new Error('Conflict'), { statusCode: 409 })
      const step = await runStep('create-role', () => Promise.reject(conflict))
      expect(step.detail).toBeUndefined()
    })

    it('does NOT treat { code: 409 } as a conflict — only { statusCode: 409 } is recognised', async () => {
      // Some error shapes use "code" rather than "statusCode"; the guard rejects these.
      const wrongShape = Object.assign(new Error('Conflict'), { code: 409 })
      const step = await runStep('create-binding', () => Promise.reject(wrongShape))
      expect(step.status).toBe('failed')
    })

    it('does NOT treat a nested response.statusCode as a conflict', async () => {
      const nestedErr = Object.assign(new Error(), { response: { statusCode: 409 } })
      const step = await runStep('create-binding', () => Promise.reject(nestedErr))
      expect(step.status).toBe('failed')
    })
  })

  describe('failed', () => {
    it('returns failed with the error message for a generic Error', async () => {
      const step = await runStep('create-ns', () => Promise.reject(new Error('cluster unreachable')))
      expect(step.status).toBe('failed')
      expect(step.detail).toBe('cluster unreachable')
    })

    it('uses String() when a non-Error value is thrown', async () => {
      // Non-Error throws (strings, objects) are stringified so callers always get a message.
      const step = await runStep('create-ns', () => Promise.reject('connection refused'))
      expect(step.status).toBe('failed')
      expect(step.detail).toBe('connection refused')
    })

    it('handles a thrown plain object (no message property)', async () => {
      const step = await runStep('create-ns', () => Promise.reject({ reason: 'timeout' }))
      expect(step.status).toBe('failed')
      expect(typeof step.detail).toBe('string')
    })

    it('returns failed for non-409 HTTP errors (e.g. 403)', async () => {
      const forbidden = Object.assign(new Error('Forbidden'), { statusCode: 403 })
      const step = await runStep('create-ns', () => Promise.reject(forbidden))
      expect(step.status).toBe('failed')
    })
  })

  describe('name propagation', () => {
    it('preserves the step name for all outcomes', async () => {
      const ok = await runStep('my-step', () => Promise.resolve())
      const conflict = await runStep('my-step', () => Promise.reject(Object.assign(new Error(), { statusCode: 409 })))
      const failed = await runStep('my-step', () => Promise.reject(new Error('x')))
      expect(ok.name).toBe('my-step')
      expect(conflict.name).toBe('my-step')
      expect(failed.name).toBe('my-step')
    })
  })
})
