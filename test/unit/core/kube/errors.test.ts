import { describe, it, expect } from 'vitest'
import { isForbidden, isConflict, isUnauthorized, isNotFound } from '../../../../src/core/kube/errors.js'

// ---------------------------------------------------------------------------
// Shared edge cases across all guards
// ---------------------------------------------------------------------------

describe('HTTP error guards — shared rejection cases', () => {
  const guards = [isForbidden, isConflict, isUnauthorized, isNotFound]

  it('returns false for null', () => {
    guards.forEach(g => expect(g(null)).toBe(false))
  })

  it('returns false for undefined', () => {
    guards.forEach(g => expect(g(undefined)).toBe(false))
  })

  it('returns false for a plain string', () => {
    guards.forEach(g => expect(g('Forbidden')).toBe(false))
  })

  it('returns false for a number', () => {
    guards.forEach(g => expect(g(403)).toBe(false))
  })

  it('returns false for an empty object (no statusCode)', () => {
    guards.forEach(g => expect(g({})).toBe(false))
  })

  it('returns false when statusCode is a string rather than a number', () => {
    // The guard requires typeof statusCode === 'number', so "403" fails.
    guards.forEach(g => expect(g({ statusCode: '403' })).toBe(false))
  })

  it('returns false when the code is nested under response.statusCode', () => {
    // The guard only checks the top-level statusCode, not response.statusCode.
    guards.forEach(g => expect(g({ response: { statusCode: 403 } })).toBe(false))
  })

  it('returns false when the code is under the "code" key instead of statusCode', () => {
    // Some libraries use err.code — this shape is not recognised.
    guards.forEach(g => expect(g({ code: 403 })).toBe(false))
  })
})

// ---------------------------------------------------------------------------
// isForbidden
// ---------------------------------------------------------------------------

describe('isForbidden', () => {
  it('returns true for { statusCode: 403 }', () => {
    expect(isForbidden({ statusCode: 403 })).toBe(true)
  })

  it('returns true for an Error instance with statusCode 403 attached', () => {
    expect(isForbidden(Object.assign(new Error('Forbidden'), { statusCode: 403 }))).toBe(true)
  })

  it('returns false for 401 (Unauthorized, not Forbidden)', () => {
    expect(isForbidden({ statusCode: 401 })).toBe(false)
  })

  it('returns false for 404', () => {
    expect(isForbidden({ statusCode: 404 })).toBe(false)
  })

  it('returns false for 409', () => {
    expect(isForbidden({ statusCode: 409 })).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// isConflict
// ---------------------------------------------------------------------------

describe('isConflict', () => {
  it('returns true for { statusCode: 409 }', () => {
    expect(isConflict({ statusCode: 409 })).toBe(true)
  })

  it('returns true for an Error instance with statusCode 409 attached', () => {
    expect(isConflict(Object.assign(new Error('Conflict'), { statusCode: 409 }))).toBe(true)
  })

  it('returns false for 403', () => {
    expect(isConflict({ statusCode: 403 })).toBe(false)
  })

  it('returns false for 422 (Unprocessable Entity is not a conflict)', () => {
    expect(isConflict({ statusCode: 422 })).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// isUnauthorized
// ---------------------------------------------------------------------------

describe('isUnauthorized', () => {
  it('returns true for { statusCode: 401 }', () => {
    expect(isUnauthorized({ statusCode: 401 })).toBe(true)
  })

  it('returns false for 403 (Forbidden is not Unauthorized)', () => {
    expect(isUnauthorized({ statusCode: 403 })).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// isNotFound
// ---------------------------------------------------------------------------

describe('isNotFound', () => {
  it('returns true for { statusCode: 404 }', () => {
    expect(isNotFound({ statusCode: 404 })).toBe(true)
  })

  it('returns false for 410 (Gone is not Not Found)', () => {
    expect(isNotFound({ statusCode: 410 })).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// cross-guard isolation
// ---------------------------------------------------------------------------

describe('cross-guard isolation', () => {
  it('each guard is true only for its own status code', () => {
    // Verify no guard accidentally fires on another guard's code.
    expect(isForbidden({ statusCode: 409 })).toBe(false)
    expect(isConflict({ statusCode: 403 })).toBe(false)
    expect(isUnauthorized({ statusCode: 404 })).toBe(false)
    expect(isNotFound({ statusCode: 401 })).toBe(false)
  })
})
