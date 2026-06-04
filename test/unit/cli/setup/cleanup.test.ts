import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { Command } from 'commander'

// ---------------------------------------------------------------------------
// Module mocks
// ---------------------------------------------------------------------------

vi.mock('../../../../src/core/setup/cleanup.js', () => ({
  teardownNamespace: vi.fn(),
}))

vi.mock('../../../../src/cli/commands/recon/utils/shared.js', () => ({
  buildKubeConfig: vi.fn().mockReturnValue({ kc: {}, clusterContext: 'test-cluster' }),
  DEFAULT_RECON_NAMESPACE: 'chaosify',
}))

import { cleanup } from '../../../../src/cli/commands/setup/cleanup.js'
import { teardownNamespace } from '../../../../src/core/setup/cleanup.js'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const teardownMock = teardownNamespace as ReturnType<typeof vi.fn>

function successResult() {
  return Promise.resolve({
    clusterContext: 'test-cluster',
    namespace: 'chaosify',
    steps: [
      { name: 'RoleBinding chaosify-runner', status: 'ok' },
      { name: 'Role chaosify-runner', status: 'ok' },
      { name: 'ServiceAccount chaosify-runner', status: 'ok' },
      { name: 'ResourceQuota chaosify-quota', status: 'ok' },
      { name: 'Namespace chaosify', status: 'ok' },
    ],
  })
}

function failedStepResult() {
  return Promise.resolve({
    clusterContext: 'test-cluster',
    namespace: 'chaosify',
    steps: [
      { name: 'RoleBinding chaosify-runner', status: 'failed', detail: 'permission denied' },
    ],
  })
}

function makeProgram() {
  const setup = new Command('setup')
  cleanup(setup)
  return setup
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
  teardownMock.mockReset()
})

// ---------------------------------------------------------------------------
// Success path
// ---------------------------------------------------------------------------

describe('setup cleanup — success', () => {
  it('exits 0 when all teardown steps succeed', async () => {
    teardownMock.mockImplementation(successResult)
    await run(['node', 'setup', 'cleanup'])
    expect(exitCode).toBe(0)
  })

  it('calls teardownNamespace with the provided namespace', async () => {
    teardownMock.mockImplementation(successResult)
    await run(['node', 'setup', 'cleanup', '--namespace', 'my-ns'])
    expect(teardownMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ namespace: 'my-ns' }))
  })

  it('uses the default namespace "chaosify" when --namespace is omitted', async () => {
    teardownMock.mockImplementation(successResult)
    await run(['node', 'setup', 'cleanup'])
    expect(teardownMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ namespace: 'chaosify' }))
  })

  it('forwards --context to teardownNamespace', async () => {
    teardownMock.mockImplementation(successResult)
    await run(['node', 'setup', 'cleanup', '--context', 'prod'])
    expect(teardownMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ context: 'prod' }))
  })
})

// ---------------------------------------------------------------------------
// JSON format
// ---------------------------------------------------------------------------

describe('setup cleanup — --format json', () => {
  it('prints a JSON result to stdout', async () => {
    teardownMock.mockImplementation(successResult)
    await run(['node', 'setup', 'cleanup', '--format', 'json'])
    const jsonCall = logSpy.mock.calls.find(call => {
      try { JSON.parse(String(call[0])); return true } catch { return false }
    })
    expect(jsonCall).toBeDefined()
  })

  it('exits 0 in JSON mode when all steps succeed', async () => {
    teardownMock.mockImplementation(successResult)
    await run(['node', 'setup', 'cleanup', '--format', 'json'])
    expect(exitCode).toBe(0)
  })

  it('exits 2 in JSON mode when a step failed', async () => {
    teardownMock.mockImplementation(failedStepResult)
    await run(['node', 'setup', 'cleanup', '--format', 'json'])
    expect(exitCode).toBe(2)
  })
})

// ---------------------------------------------------------------------------
// Failure path
// ---------------------------------------------------------------------------

describe('setup cleanup — failures', () => {
  it('exits 2 when a teardown step fails', async () => {
    teardownMock.mockImplementation(failedStepResult)
    await run(['node', 'setup', 'cleanup'])
    expect(exitCode).toBe(2)
  })

  it('exits 2 when teardownNamespace throws an unexpected error', async () => {
    teardownMock.mockRejectedValue(new Error('cluster unreachable'))
    await run(['node', 'setup', 'cleanup'])
    expect(exitCode).toBe(2)
  })

  it('exits 2 when teardownNamespace throws a non-Error value', async () => {
    teardownMock.mockRejectedValue('socket hang up')
    await run(['node', 'setup', 'cleanup'])
    expect(exitCode).toBe(2)
  })
})

// ---------------------------------------------------------------------------
// Idempotency — resources already deleted
// ---------------------------------------------------------------------------

describe('setup cleanup — already removed', () => {
  it('exits 0 when all resources were already deleted (already-existed steps)', async () => {
    teardownMock.mockResolvedValue({
      clusterContext: 'test-cluster',
      namespace: 'chaosify',
      steps: [
        { name: 'RoleBinding chaosify-runner', status: 'already-existed' },
        { name: 'Namespace chaosify', status: 'already-existed' },
      ],
    })
    await run(['node', 'setup', 'cleanup'])
    expect(exitCode).toBe(0)
  })
})
