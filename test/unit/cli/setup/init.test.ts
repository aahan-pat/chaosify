import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { Command } from 'commander'

// ---------------------------------------------------------------------------
// Module mocks
// ---------------------------------------------------------------------------

vi.mock('../../../../src/core/setup/init.js', () => ({
  initNamespace: vi.fn(),
}))

vi.mock('../../../../src/cli/commands/recon/utils/shared.js', () => ({
  buildKubeConfig: vi.fn().mockReturnValue({ kc: {}, clusterContext: 'test-cluster' }),
  DEFAULT_RECON_NAMESPACE: 'chaosify',
}))

import { init } from '../../../../src/cli/commands/setup/init.js'
import { initNamespace } from '../../../../src/core/setup/init.js'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const initMock = initNamespace as ReturnType<typeof vi.fn>

function successResult() {
  return Promise.resolve({
    clusterContext: 'test-cluster',
    namespace: 'chaosify',
    alreadyExisted: false,
    steps: [
      { name: 'Namespace chaosify', status: 'ok' },
      { name: 'ResourceQuota', status: 'ok' },
      { name: 'ServiceAccount chaosify-runner', status: 'ok' },
      { name: 'Role chaosify-runner', status: 'ok' },
      { name: 'RoleBinding chaosify-runner', status: 'ok' },
    ],
  })
}

function failedStepResult() {
  return Promise.resolve({
    clusterContext: 'test-cluster',
    namespace: 'chaosify',
    alreadyExisted: false,
    steps: [{ name: 'ResourceQuota', status: 'failed', detail: 'permission denied' }],
  })
}

function makeProgram() {
  const setup = new Command('setup')
  init(setup)
  return setup
}

// Parse args and always resolve — process.exit throws internally to stop execution,
// Commander re-throws it as a rejected promise which we always swallow here.
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
  // Throw after capturing the code so execution halts at the process.exit() call site.
  vi.spyOn(process, 'exit').mockImplementation((code?: number) => {
    exitCode = code
    throw new Error(`EXIT:${code}`)
  })
  logSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

afterEach(() => {
  vi.restoreAllMocks()
  initMock.mockReset()
})

// ---------------------------------------------------------------------------
// Success path
// ---------------------------------------------------------------------------

describe('setup init — success', () => {
  it('exits 0 when all steps succeed', async () => {
    initMock.mockImplementation(successResult)
    await run(['node', 'setup', 'init'])
    expect(exitCode).toBe(0)
  })

  it('calls initNamespace with the provided namespace', async () => {
    initMock.mockImplementation(successResult)
    await run(['node', 'setup', 'init', '--namespace', 'my-ns'])
    expect(initMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ namespace: 'my-ns' }))
  })

  it('uses the default namespace "chaosify" when --namespace is omitted', async () => {
    initMock.mockImplementation(successResult)
    await run(['node', 'setup', 'init'])
    expect(initMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ namespace: 'chaosify' }))
  })

  it('forwards --context to initNamespace', async () => {
    initMock.mockImplementation(successResult)
    await run(['node', 'setup', 'init', '--context', 'prod'])
    expect(initMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ context: 'prod' }))
  })
})

// ---------------------------------------------------------------------------
// JSON format
// ---------------------------------------------------------------------------

describe('setup init — --format json', () => {
  it('prints a JSON result to stdout', async () => {
    initMock.mockImplementation(successResult)
    await run(['node', 'setup', 'init', '--format', 'json'])
    const jsonCall = logSpy.mock.calls.find(call => {
      try { JSON.parse(String(call[0])); return true } catch { return false }
    })
    expect(jsonCall).toBeDefined()
  })

  it('exits 0 when all steps succeed in JSON mode', async () => {
    initMock.mockImplementation(successResult)
    await run(['node', 'setup', 'init', '--format', 'json'])
    expect(exitCode).toBe(0)
  })

  it('exits 2 when a step failed in JSON mode', async () => {
    initMock.mockImplementation(failedStepResult)
    await run(['node', 'setup', 'init', '--format', 'json'])
    expect(exitCode).toBe(2)
  })
})

// ---------------------------------------------------------------------------
// Failure path
// ---------------------------------------------------------------------------

describe('setup init — failures', () => {
  it('exits 2 when a setup step fails', async () => {
    initMock.mockImplementation(failedStepResult)
    await run(['node', 'setup', 'init'])
    expect(exitCode).toBe(2)
  })

  it('exits 2 when initNamespace throws an unexpected error', async () => {
    initMock.mockRejectedValue(new Error('cluster unreachable'))
    await run(['node', 'setup', 'init'])
    expect(exitCode).toBe(2)
  })

  it('exits 2 when initNamespace throws a non-Error value', async () => {
    initMock.mockRejectedValue('connection refused')
    await run(['node', 'setup', 'init'])
    expect(exitCode).toBe(2)
  })
})

// ---------------------------------------------------------------------------
// alreadyExisted
// ---------------------------------------------------------------------------

describe('setup init — namespace already existed', () => {
  it('still exits 0 when the namespace already existed and all steps complete', async () => {
    initMock.mockResolvedValue({
      clusterContext: 'test-cluster',
      namespace: 'chaosify',
      alreadyExisted: true,
      steps: [{ name: 'Namespace chaosify', status: 'already-existed' }],
    })
    await run(['node', 'setup', 'init'])
    expect(exitCode).toBe(0)
  })
})
