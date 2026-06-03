import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { Command } from 'commander'

// ---------------------------------------------------------------------------
// Module mocks
// ---------------------------------------------------------------------------

vi.mock('../../../../src/core/recon/rbac.js', () => ({
  surveyRbac: vi.fn(),
}))

vi.mock('../../../../src/cli/commands/recon/utils/shared.js', () => ({
  buildKubeConfig: vi.fn().mockReturnValue({ kc: {}, clusterContext: 'test-cluster' }),
  DEFAULT_RECON_NAMESPACE: 'chaosclaw',
  writeJsonToFile: vi.fn().mockResolvedValue(undefined),
}))

import { rbac } from '../../../../src/cli/commands/recon/rbac.js'
import { surveyRbac } from '../../../../src/core/recon/rbac.js'
import { writeJsonToFile } from '../../../../src/cli/commands/recon/utils/shared.js'

// ---------------------------------------------------------------------------
// Helpers — zero-argument factories so mock args don't pollute the result.
// ---------------------------------------------------------------------------

const surveyMock = surveyRbac as ReturnType<typeof vi.fn>
const writeMock = writeJsonToFile as ReturnType<typeof vi.fn>

const OK_RESULT = {
  tool: 'rbac',
  status: 'ok' as const,
  findings: [],
  data: { clusterRoleCount: 5, clusterRoleBindingCount: 3, partial: false },
}

const SKIP_RESULT = {
  tool: 'rbac',
  status: 'skip' as const,
  findings: [{ severity: 'SKIP' as const, title: 'ClusterRole list skipped', detail: 'No permission' }],
  data: {},
}

const HIGH_RESULT = {
  tool: 'rbac',
  status: 'ok' as const,
  findings: [{ severity: 'HIGH' as const, title: 'cluster-admin bound', detail: 'developer@example.com — via binding dev-admin' }],
  data: { clusterRoleCount: 1, clusterRoleBindingCount: 1, partial: false },
}

function makeProgram() {
  const recon = new Command('recon')
  rbac(recon)
  return recon
}

async function run(args: string[]) {
  await makeProgram().parseAsync(args).catch(() => {})
}

// ---------------------------------------------------------------------------
// Test setup
// ---------------------------------------------------------------------------

let exitCode: number | undefined
let logSpy: ReturnType<typeof vi.spyOn>

beforeEach(() => {
  exitCode = undefined
  vi.spyOn(process, 'exit').mockImplementation((code?: number) => {
    exitCode = code
    throw new Error(`EXIT:${code}`)
  })
  logSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

afterEach(() => {
  vi.restoreAllMocks()
  surveyMock.mockReset()
  writeMock.mockReset()
})

// ---------------------------------------------------------------------------
// Core function delegation
// ---------------------------------------------------------------------------

describe('recon rbac — delegation', () => {
  it('calls surveyRbac with the correct namespace', async () => {
    surveyMock.mockResolvedValue(OK_RESULT)
    await run(['node', 'recon', 'rbac', '--namespace', 'my-ns'])
    expect(surveyMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ namespace: 'my-ns' }))
  })

  it('uses the default namespace "chaosclaw" when --namespace is omitted', async () => {
    surveyMock.mockResolvedValue(OK_RESULT)
    await run(['node', 'recon', 'rbac'])
    expect(surveyMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ namespace: 'chaosclaw' }))
  })

  it('passes includeSystem: true when --include-system is set', async () => {
    surveyMock.mockResolvedValue(OK_RESULT)
    await run(['node', 'recon', 'rbac', '--include-system'])
    expect(surveyMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ includeSystem: true }))
  })

  it('passes includeSystem as falsy when --include-system is omitted', async () => {
    surveyMock.mockResolvedValue(OK_RESULT)
    await run(['node', 'recon', 'rbac'])
    expect(surveyMock).toHaveBeenCalledWith(
      expect.anything(),
      expect.not.objectContaining({ includeSystem: true }),
    )
  })

  it('forwards --context to surveyRbac', async () => {
    surveyMock.mockResolvedValue(OK_RESULT)
    await run(['node', 'recon', 'rbac', '--context', 'staging'])
    expect(surveyMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ context: 'staging' }))
  })
})

// ---------------------------------------------------------------------------
// Exit codes
// ---------------------------------------------------------------------------

describe('recon rbac — exit codes', () => {
  it('exits 0 on a successful survey with no findings', async () => {
    surveyMock.mockResolvedValue(OK_RESULT)
    await run(['node', 'recon', 'rbac'])
    expect(exitCode).toBe(0)
  })

  it('exits 0 even when HIGH findings are present (informational only)', async () => {
    // recon rbac reports findings but always exits 0 — no --fail-on-findings flag.
    surveyMock.mockResolvedValue(HIGH_RESULT)
    await run(['node', 'recon', 'rbac'])
    expect(exitCode).toBe(0)
  })

  it('exits 0 when the survey returns skip status', async () => {
    surveyMock.mockResolvedValue(SKIP_RESULT)
    await run(['node', 'recon', 'rbac'])
    expect(exitCode).toBe(0)
  })

  it('exits 2 when surveyRbac throws an unexpected error', async () => {
    surveyMock.mockRejectedValue(new Error('network failure'))
    await run(['node', 'recon', 'rbac'])
    expect(exitCode).toBe(2)
  })

  it('exits 2 when surveyRbac throws a non-Error value', async () => {
    surveyMock.mockRejectedValue('dial timeout')
    await run(['node', 'recon', 'rbac'])
    expect(exitCode).toBe(2)
  })
})

// ---------------------------------------------------------------------------
// JSON format
// ---------------------------------------------------------------------------

describe('recon rbac — --format json', () => {
  it('prints parseable JSON to stdout', async () => {
    surveyMock.mockResolvedValue(HIGH_RESULT)
    await run(['node', 'recon', 'rbac', '--format', 'json'])
    const jsonCall = logSpy.mock.calls.find(call => {
      try { JSON.parse(String(call[0])); return true } catch { return false }
    })
    expect(jsonCall).toBeDefined()
    expect(JSON.parse(String(jsonCall![0])).tool).toBe('rbac')
  })

  it('includes findings in the JSON output', async () => {
    surveyMock.mockResolvedValue(HIGH_RESULT)
    await run(['node', 'recon', 'rbac', '--format', 'json'])
    const jsonCall = logSpy.mock.calls.find(call => {
      try { JSON.parse(String(call[0])); return true } catch { return false }
    })
    const parsed = JSON.parse(String(jsonCall![0]))
    expect(parsed.findings).toHaveLength(1)
  })

  it('exits 0 in JSON mode regardless of finding severity', async () => {
    surveyMock.mockResolvedValue(HIGH_RESULT)
    await run(['node', 'recon', 'rbac', '--format', 'json'])
    expect(exitCode).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// --output file writing
// ---------------------------------------------------------------------------

describe('recon rbac — --output', () => {
  it('calls writeJsonToFile with the given path and full survey result', async () => {
    surveyMock.mockResolvedValue(OK_RESULT)
    await run(['node', 'recon', 'rbac', '--output', './report.json'])
    expect(writeMock).toHaveBeenCalledWith('./report.json', expect.objectContaining({ tool: 'rbac' }))
  })

  it('writes the file even for skip results', async () => {
    surveyMock.mockResolvedValue(SKIP_RESULT)
    await run(['node', 'recon', 'rbac', '--output', './skip.json'])
    expect(writeMock).toHaveBeenCalledWith('./skip.json', expect.objectContaining({ status: 'skip' }))
  })

  it('writes the file when combined with --format json', async () => {
    surveyMock.mockResolvedValue(OK_RESULT)
    await run(['node', 'recon', 'rbac', '--output', './out.json', '--format', 'json'])
    expect(writeMock).toHaveBeenCalledTimes(1)
  })

  it('does not call writeJsonToFile when --output is omitted', async () => {
    surveyMock.mockResolvedValue(OK_RESULT)
    await run(['node', 'recon', 'rbac'])
    expect(writeMock).not.toHaveBeenCalled()
  })
})
