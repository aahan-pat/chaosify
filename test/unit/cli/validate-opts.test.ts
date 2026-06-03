import { describe, it, expect, vi, afterEach } from 'vitest'
import { validateOpts } from '../../../src/cli/commands/verify/run/validate-opts.js'
import type { RunOpts } from '../../../src/cli/commands/verify/run/validate-opts.js'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Base options with all required fields set; tests override only what they care about.
function opts(overrides: Partial<RunOpts> = {}): RunOpts {
  return {
    namespace: 'chaosclaw',
    alertSource: 'none',
    format: 'table',
    cleanup: 'always',
    ...overrides,
  }
}

afterEach(() => {
  vi.restoreAllMocks()
})

// Spy on process.exit and prevent it from terminating the test process.
function spyExit() {
  return vi.spyOn(process, 'exit').mockImplementation((() => {}) as () => never)
}

// ---------------------------------------------------------------------------
// Valid target combinations (no exit)
// ---------------------------------------------------------------------------

describe('validateOpts — valid inputs', () => {
  it('accepts --pack alone without calling process.exit', () => {
    const exit = spyExit()
    validateOpts(opts({ pack: 'preventive-baseline' }))
    expect(exit).not.toHaveBeenCalled()
  })

  it('accepts --scenario alone', () => {
    const exit = spyExit()
    validateOpts(opts({ scenario: 'deny-hostpath' }))
    expect(exit).not.toHaveBeenCalled()
  })

  it('accepts --manifest with --expect "rejected"', () => {
    const exit = spyExit()
    validateOpts(opts({ manifest: './my-pod.yaml', expect: 'rejected' }))
    expect(exit).not.toHaveBeenCalled()
  })

  it('accepts --manifest with --expect "allowed"', () => {
    const exit = spyExit()
    validateOpts(opts({ manifest: './pod.yaml', expect: 'allowed' }))
    expect(exit).not.toHaveBeenCalled()
  })
})

// ---------------------------------------------------------------------------
// Missing target — no target at all
// ---------------------------------------------------------------------------

describe('validateOpts — missing target', () => {
  it('exits 4 when none of --pack, --scenario, or --manifest is provided', () => {
    const exit = spyExit()
    validateOpts(opts())
    expect(exit).toHaveBeenCalledWith(4)
  })

  it('exits 4 when all three target fields are explicitly undefined', () => {
    const exit = spyExit()
    validateOpts(opts({ pack: undefined, scenario: undefined, manifest: undefined }))
    expect(exit).toHaveBeenCalledWith(4)
  })
})

// ---------------------------------------------------------------------------
// Mutually exclusive targets
// ---------------------------------------------------------------------------

describe('validateOpts — mutually exclusive targets', () => {
  it('exits 4 when --pack and --scenario are both provided', () => {
    const exit = spyExit()
    validateOpts(opts({ pack: 'preventive-baseline', scenario: 'deny-hostpath' }))
    expect(exit).toHaveBeenCalledWith(4)
  })

  it('exits 4 when --pack and --manifest are both provided', () => {
    const exit = spyExit()
    validateOpts(opts({ pack: 'preventive-baseline', manifest: './pod.yaml', expect: 'rejected' }))
    expect(exit).toHaveBeenCalledWith(4)
  })

  it('exits 4 when --scenario and --manifest are both provided', () => {
    const exit = spyExit()
    validateOpts(opts({ scenario: 'deny-hostpath', manifest: './pod.yaml', expect: 'rejected' }))
    expect(exit).toHaveBeenCalledWith(4)
  })

  it('exits 4 when all three targets are provided simultaneously', () => {
    const exit = spyExit()
    validateOpts(opts({ pack: 'p', scenario: 's', manifest: './m.yaml', expect: 'rejected' }))
    expect(exit).toHaveBeenCalledWith(4)
  })
})

// ---------------------------------------------------------------------------
// --manifest requires --expect
// ---------------------------------------------------------------------------

describe('validateOpts — --manifest requires --expect', () => {
  it('exits 4 when --manifest is given without --expect', () => {
    const exit = spyExit()
    validateOpts(opts({ manifest: './pod.yaml' }))
    expect(exit).toHaveBeenCalledWith(4)
  })

  it('exits 4 when --expect is an empty string', () => {
    const exit = spyExit()
    validateOpts(opts({ manifest: './pod.yaml', expect: '' }))
    expect(exit).toHaveBeenCalledWith(4)
  })

  it('exits 4 when --expect is "blocked" (not a valid admission outcome)', () => {
    const exit = spyExit()
    validateOpts(opts({ manifest: './pod.yaml', expect: 'blocked' }))
    expect(exit).toHaveBeenCalledWith(4)
  })

  it('exits 4 when --expect is "REJECTED" (case-sensitive — must be lowercase)', () => {
    const exit = spyExit()
    validateOpts(opts({ manifest: './pod.yaml', expect: 'REJECTED' }))
    expect(exit).toHaveBeenCalledWith(4)
  })

  it('exits 4 when --expect is "denied" (not a valid value)', () => {
    const exit = spyExit()
    validateOpts(opts({ manifest: './pod.yaml', expect: 'denied' }))
    expect(exit).toHaveBeenCalledWith(4)
  })
})

// ---------------------------------------------------------------------------
// --pack and --scenario do not require --expect
// ---------------------------------------------------------------------------

describe('validateOpts — --expect not required for pack/scenario', () => {
  it('accepts --pack without --expect', () => {
    const exit = spyExit()
    validateOpts(opts({ pack: 'preventive-baseline' }))
    expect(exit).not.toHaveBeenCalled()
  })

  it('accepts --scenario without --expect', () => {
    const exit = spyExit()
    validateOpts(opts({ scenario: 'deny-privileged' }))
    expect(exit).not.toHaveBeenCalled()
  })
})
