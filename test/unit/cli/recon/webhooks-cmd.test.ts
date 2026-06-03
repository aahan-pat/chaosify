import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { Command } from 'commander'

// ---------------------------------------------------------------------------
// Module mocks
// ---------------------------------------------------------------------------

vi.mock('../../../../src/core/recon/webhooks.js', () => ({
  surveyWebhooks: vi.fn(),
}))

vi.mock('../../../../src/cli/commands/recon/utils/shared.js', () => ({
  buildKubeConfig: vi.fn().mockReturnValue({ kc: {}, clusterContext: 'test-cluster' }),
  DEFAULT_RECON_NAMESPACE: 'chaosclaw',
  writeJsonToFile: vi.fn().mockResolvedValue(undefined),
}))

import { webhooks } from '../../../../src/cli/commands/recon/webhooks.js'
import { surveyWebhooks } from '../../../../src/core/recon/webhooks.js'
import { writeJsonToFile } from '../../../../src/cli/commands/recon/utils/shared.js'

// ---------------------------------------------------------------------------
// Helpers — zero-argument result objects so mock args don't pollute results.
// ---------------------------------------------------------------------------

const surveyMock = surveyWebhooks as ReturnType<typeof vi.fn>
const writeMock = writeJsonToFile as ReturnType<typeof vi.fn>

const OK_EMPTY = {
  tool: 'webhooks',
  status: 'ok' as const,
  findings: [{ severity: 'HIGH' as const, title: 'No admission webhooks detected', detail: 'No webhooks found' }],
  data: { webhooks: [] },
}

const OK_WITH_WEBHOOKS = {
  tool: 'webhooks',
  status: 'ok' as const,
  findings: [{ severity: 'INFO' as const, title: 'All admission webhooks use failurePolicy: Fail', detail: '' }],
  data: {
    webhooks: [
      { name: 'kyverno.io', type: 'validating', ruleCount: 5, failurePolicy: 'Fail', scope: 'cluster-wide' },
      { name: 'inject.istio.io', type: 'mutating', ruleCount: 1, failurePolicy: 'Fail', scope: 'namespace-scoped' },
    ],
  },
}

const SKIP_RESULT = {
  tool: 'webhooks',
  status: 'skip' as const,
  findings: [{ severity: 'SKIP' as const, title: 'Webhook recon skipped', detail: 'No permission' }],
  data: {},
}

const FAIL_OPEN_RESULT = {
  tool: 'webhooks',
  status: 'ok' as const,
  findings: [{ severity: 'HIGH' as const, title: 'policy.example.com — failurePolicy: Ignore', detail: '' }],
  data: {
    webhooks: [
      { name: 'policy.example.com', type: 'validating', ruleCount: 3, failurePolicy: 'Ignore', scope: 'cluster-wide' },
    ],
  },
}

function makeProgram() {
  const recon = new Command('recon')
  webhooks(recon)
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

describe('recon webhooks — delegation', () => {
  it('calls surveyWebhooks with the correct namespace', async () => {
    surveyMock.mockResolvedValue(OK_WITH_WEBHOOKS)
    await run(['node', 'recon', 'webhooks', '--namespace', 'my-ns'])
    expect(surveyMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ namespace: 'my-ns' }))
  })

  it('uses the default namespace "chaosclaw" when --namespace is omitted', async () => {
    surveyMock.mockResolvedValue(OK_WITH_WEBHOOKS)
    await run(['node', 'recon', 'webhooks'])
    expect(surveyMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ namespace: 'chaosclaw' }))
  })

  it('forwards --context to surveyWebhooks', async () => {
    surveyMock.mockResolvedValue(OK_WITH_WEBHOOKS)
    await run(['node', 'recon', 'webhooks', '--context', 'staging'])
    expect(surveyMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ context: 'staging' }))
  })
})

// ---------------------------------------------------------------------------
// Exit codes
// ---------------------------------------------------------------------------

describe('recon webhooks — exit codes', () => {
  it('exits 0 when webhooks exist and are all fail-closed', async () => {
    surveyMock.mockResolvedValue(OK_WITH_WEBHOOKS)
    await run(['node', 'recon', 'webhooks'])
    expect(exitCode).toBe(0)
  })

  it('exits 0 even with HIGH findings (fail-open webhook) — recon is informational', async () => {
    surveyMock.mockResolvedValue(FAIL_OPEN_RESULT)
    await run(['node', 'recon', 'webhooks'])
    expect(exitCode).toBe(0)
  })

  it('exits 0 when no webhooks exist (HIGH finding)', async () => {
    surveyMock.mockResolvedValue(OK_EMPTY)
    await run(['node', 'recon', 'webhooks'])
    expect(exitCode).toBe(0)
  })

  it('exits 0 when the survey returns skip status', async () => {
    surveyMock.mockResolvedValue(SKIP_RESULT)
    await run(['node', 'recon', 'webhooks'])
    expect(exitCode).toBe(0)
  })

  it('exits 2 when surveyWebhooks throws an unexpected error', async () => {
    surveyMock.mockRejectedValue(new Error('network failure'))
    await run(['node', 'recon', 'webhooks'])
    expect(exitCode).toBe(2)
  })

  it('exits 2 when surveyWebhooks throws a non-Error value', async () => {
    surveyMock.mockRejectedValue('dial tcp: connection refused')
    await run(['node', 'recon', 'webhooks'])
    expect(exitCode).toBe(2)
  })
})

// ---------------------------------------------------------------------------
// JSON format
// ---------------------------------------------------------------------------

describe('recon webhooks — --format json', () => {
  it('prints parseable JSON to stdout', async () => {
    surveyMock.mockResolvedValue(OK_WITH_WEBHOOKS)
    await run(['node', 'recon', 'webhooks', '--format', 'json'])
    const jsonCall = logSpy.mock.calls.find(call => {
      try { JSON.parse(String(call[0])); return true } catch { return false }
    })
    expect(jsonCall).toBeDefined()
    expect(JSON.parse(String(jsonCall![0])).tool).toBe('webhooks')
  })

  it('includes the webhook list in the JSON output', async () => {
    surveyMock.mockResolvedValue(OK_WITH_WEBHOOKS)
    await run(['node', 'recon', 'webhooks', '--format', 'json'])
    const jsonCall = logSpy.mock.calls.find(call => {
      try { JSON.parse(String(call[0])); return true } catch { return false }
    })
    const parsed = JSON.parse(String(jsonCall![0]))
    expect(Array.isArray(parsed.data.webhooks)).toBe(true)
    expect(parsed.data.webhooks).toHaveLength(2)
  })

  it('exits 0 in JSON mode', async () => {
    surveyMock.mockResolvedValue(OK_WITH_WEBHOOKS)
    await run(['node', 'recon', 'webhooks', '--format', 'json'])
    expect(exitCode).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// --output file writing
// ---------------------------------------------------------------------------

describe('recon webhooks — --output', () => {
  it('calls writeJsonToFile with the given path and full survey result', async () => {
    surveyMock.mockResolvedValue(OK_WITH_WEBHOOKS)
    await run(['node', 'recon', 'webhooks', '--output', './wh-report.json'])
    expect(writeMock).toHaveBeenCalledWith('./wh-report.json', expect.objectContaining({ tool: 'webhooks' }))
  })

  it('writes the file for skip results too', async () => {
    surveyMock.mockResolvedValue(SKIP_RESULT)
    await run(['node', 'recon', 'webhooks', '--output', './out.json'])
    expect(writeMock).toHaveBeenCalledWith('./out.json', expect.objectContaining({ status: 'skip' }))
  })

  it('writes the file when combined with --format json', async () => {
    surveyMock.mockResolvedValue(OK_WITH_WEBHOOKS)
    await run(['node', 'recon', 'webhooks', '--output', './out.json', '--format', 'json'])
    expect(writeMock).toHaveBeenCalledTimes(1)
  })

  it('does not call writeJsonToFile when --output is omitted', async () => {
    surveyMock.mockResolvedValue(OK_WITH_WEBHOOKS)
    await run(['node', 'recon', 'webhooks'])
    expect(writeMock).not.toHaveBeenCalled()
  })
})
