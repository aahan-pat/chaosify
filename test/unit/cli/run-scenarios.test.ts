import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { runScenarios } from '../../../src/cli/commands/verify/run/run-scenarios.js'
import type { RunContext } from '../../../src/cli/commands/verify/run/run-context.js'
import type { ScenarioDefinition } from '../../../src/types/scenario.js'
import type { RuntimeScenarioDefinition } from '../../../src/types/runtime-scenario.js'
import type { ExecutionResult } from '../../../src/core/scenarios/exec/executor.js'
import type { RuntimeExecutionResult } from '../../../src/core/scenarios/exec/runtime-executor.js'
import type { ValidationResult } from '../../../src/core/validation/validator.js'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeScenario(id: string): ScenarioDefinition {
  return {
    id,
    version: 1,
    name: `Scenario ${id}`,
    description: 'Test',
    category: 'preventive',
    controlObjective: 'Test objective',
    prerequisites: [],
    manifest: { kind: 'Pod', apiVersion: 'v1', metadata: {} },
    expectedOutcome: { type: 'admission_rejected' },
    cleanup: { deleteCreatedResources: true },
    safety: { level: 'low', namespaceScoped: true },
  }
}

function makeRuntimeScenario(id: string): RuntimeScenarioDefinition {
  return {
    id,
    version: 1,
    name: `Runtime ${id}`,
    description: 'Test',
    category: 'detective',
    controlObjective: 'Detect exec',
    prerequisites: [],
    manifest: { kind: 'Pod', apiVersion: 'v1', metadata: {} },
    execStep: { container: 'c', command: ['cat', '/etc/shadow'] },
    expectedOutcome: { type: 'alert_fired' },
    cleanup: { deleteCreatedResources: true },
    safety: { level: 'low', namespaceScoped: true },
  }
}

function makeExecution(overrides: Partial<ExecutionResult> = {}): ExecutionResult {
  return {
    observedOutcome: 'admission_rejected',
    rawResponse: '{}',
    manifestSnapshot: '{}',
    startedAt: new Date().toISOString(),
    endedAt: new Date().toISOString(),
    ...overrides,
  }
}

function makeRuntimeExecution(overrides: Partial<RuntimeExecutionResult> = {}): RuntimeExecutionResult {
  return {
    observedOutcome: 'alert_fired',
    rawResponse: '{}',
    manifestSnapshot: '{}',
    startedAt: new Date().toISOString(),
    endedAt: new Date().toISOString(),
    ...overrides,
  }
}

function makeValidation(status: ValidationResult['status'], overrides: Partial<ValidationResult> = {}): ValidationResult {
  return { status, observedOutcome: 'admission rejected', ...overrides }
}

// Build a fully-mocked RunContext with controllable per-call behaviour.
function makeCtx(overrides: {
  executeResult?: ExecutionResult | ExecutionResult[]
  validateResult?: ValidationResult | ValidationResult[]
  runtimeExecuteResult?: RuntimeExecutionResult
  runtimeValidateResult?: ValidationResult
  cleanupStatus?: 'success' | 'failed' | 'partial' | 'skipped'
} = {}): RunContext {
  const execResults = Array.isArray(overrides.executeResult)
    ? overrides.executeResult
    : [overrides.executeResult ?? makeExecution()]
  let execIdx = 0

  const validateResults = Array.isArray(overrides.validateResult)
    ? overrides.validateResult
    : [overrides.validateResult ?? makeValidation('Pass')]
  let validateIdx = 0

  return {
    kc: {} as never,
    clusterContext: 'test-cluster',
    executor: { execute: vi.fn(() => Promise.resolve(execResults[execIdx++] ?? execResults.at(-1)!)) },
    validator: { validate: vi.fn(() => validateResults[validateIdx++] ?? validateResults.at(-1)!) },
    runtimeExecutor: {
      execute: vi.fn().mockResolvedValue(overrides.runtimeExecuteResult ?? makeRuntimeExecution()),
    },
    runtimeValidator: {
      validate: vi.fn().mockReturnValue(overrides.runtimeValidateResult ?? makeValidation('Pass')),
    },
    cleanup: {
      cleanup: vi.fn().mockResolvedValue({
        status: overrides.cleanupStatus ?? 'success',
        remainingResources: [],
      }),
    },
    builder: { addResult: vi.fn() },
  } as unknown as RunContext
}

const BASE_OPTS = { namespace: 'chaosclaw-test', cleanup: 'always', format: 'table' }

// ---------------------------------------------------------------------------
// Test setup
// ---------------------------------------------------------------------------

beforeEach(() => {
  // Suppress all console output produced by indent() and printCleanupWarning().
  vi.spyOn(console, 'log').mockImplementation(() => {})
})

afterEach(() => {
  vi.restoreAllMocks()
})

// ---------------------------------------------------------------------------
// Exit codes
// ---------------------------------------------------------------------------

describe('runScenarios — exit codes', () => {
  it('returns exitCode 0 when all scenarios pass', async () => {
    const ctx = makeCtx({ validateResult: makeValidation('Pass') })
    const { exitCode } = await runScenarios([makeScenario('s1'), makeScenario('s2')], ctx, BASE_OPTS)
    expect(exitCode).toBe(0)
  })

  it('returns exitCode 1 when any scenario fails', async () => {
    const ctx = makeCtx({ validateResult: makeValidation('Fail') })
    const { exitCode } = await runScenarios([makeScenario('s1')], ctx, BASE_OPTS)
    expect(exitCode).toBe(1)
  })

  it('returns exitCode 1 when any scenario errors', async () => {
    const ctx = makeCtx({ validateResult: makeValidation('Error') })
    const { exitCode } = await runScenarios([makeScenario('s1')], ctx, BASE_OPTS)
    expect(exitCode).toBe(1)
  })

  it('returns exitCode 0 with no scenarios', async () => {
    const ctx = makeCtx()
    const { exitCode } = await runScenarios([], ctx, BASE_OPTS)
    expect(exitCode).toBe(0)
  })

  it('returns exitCode 1 when the last scenario fails after earlier passes', async () => {
    const ctx = makeCtx({
      validateResult: [makeValidation('Pass'), makeValidation('Pass'), makeValidation('Fail')],
    })
    const { exitCode } = await runScenarios(
      [makeScenario('s1'), makeScenario('s2'), makeScenario('s3')],
      ctx,
      BASE_OPTS,
    )
    expect(exitCode).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// fail-fast
// ---------------------------------------------------------------------------

describe('runScenarios — fail-fast', () => {
  it('stops after the first failure and reports notRun count', async () => {
    const ctx = makeCtx({ validateResult: makeValidation('Fail') })
    const scenarios = [makeScenario('s1'), makeScenario('s2'), makeScenario('s3')]
    const result = await runScenarios(scenarios, ctx, { ...BASE_OPTS, failFast: true })
    expect(result.exitCode).toBe(1)
    // s1 ran (and failed), s2 and s3 were not run.
    expect(result.notRun).toBe(2)
  })

  it('does not stop when failFast is false and all scenarios run', async () => {
    const ctx = makeCtx({
      validateResult: [makeValidation('Fail'), makeValidation('Pass'), makeValidation('Fail')],
    })
    const scenarios = [makeScenario('s1'), makeScenario('s2'), makeScenario('s3')]
    const result = await runScenarios(scenarios, ctx, { ...BASE_OPTS, failFast: false })
    expect(result.notRun).toBe(0)
    // Executor is called for all three scenarios despite failures.
    expect((ctx.executor as { execute: ReturnType<typeof vi.fn> }).execute).toHaveBeenCalledTimes(3)
  })

  it('reports notRun: 0 when the failure is the last scenario', async () => {
    const ctx = makeCtx({
      validateResult: [makeValidation('Pass'), makeValidation('Fail')],
    })
    const result = await runScenarios(
      [makeScenario('s1'), makeScenario('s2')],
      ctx,
      { ...BASE_OPTS, failFast: true },
    )
    expect(result.notRun).toBe(0)
  })

  it('reports notRun: 0 when no failures occur even with failFast enabled', async () => {
    const ctx = makeCtx({ validateResult: makeValidation('Pass') })
    const result = await runScenarios(
      [makeScenario('s1'), makeScenario('s2')],
      ctx,
      { ...BASE_OPTS, failFast: true },
    )
    expect(result.exitCode).toBe(0)
    expect(result.notRun).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// cleanup modes
// ---------------------------------------------------------------------------

describe('runScenarios — cleanup modes', () => {
  it('calls cleanup for every scenario when mode is "always" (pass or fail)', async () => {
    const ctx = makeCtx({
      executeResult: makeExecution({ createdResourceName: 'chaosclaw-test-abc' }),
      validateResult: makeValidation('Fail'),
    })
    await runScenarios([makeScenario('s1')], ctx, { ...BASE_OPTS, cleanup: 'always' })
    expect((ctx.cleanup as { cleanup: ReturnType<typeof vi.fn> }).cleanup).toHaveBeenCalledTimes(1)
  })

  it('calls cleanup only on passing scenarios when mode is "on-success"', async () => {
    const ctx = makeCtx({
      executeResult: makeExecution({ createdResourceName: 'chaosclaw-test-abc' }),
      validateResult: makeValidation('Fail'),
    })
    await runScenarios([makeScenario('s1')], ctx, { ...BASE_OPTS, cleanup: 'on-success' })
    // Fail result → on-success skips cleanup.
    expect((ctx.cleanup as { cleanup: ReturnType<typeof vi.fn> }).cleanup).not.toHaveBeenCalled()
  })

  it('calls cleanup on a passing scenario when mode is "on-success"', async () => {
    const ctx = makeCtx({
      executeResult: makeExecution({ createdResourceName: 'chaosclaw-test-abc' }),
      validateResult: makeValidation('Pass'),
    })
    await runScenarios([makeScenario('s1')], ctx, { ...BASE_OPTS, cleanup: 'on-success' })
    expect((ctx.cleanup as { cleanup: ReturnType<typeof vi.fn> }).cleanup).toHaveBeenCalledTimes(1)
  })

  it('never calls cleanup when mode is "never"', async () => {
    const ctx = makeCtx({
      executeResult: makeExecution({ createdResourceName: 'chaosclaw-test-abc' }),
      validateResult: makeValidation('Pass'),
    })
    await runScenarios([makeScenario('s1'), makeScenario('s2')], ctx, { ...BASE_OPTS, cleanup: 'never' })
    expect((ctx.cleanup as { cleanup: ReturnType<typeof vi.fn> }).cleanup).not.toHaveBeenCalled()
  })
})

// ---------------------------------------------------------------------------
// Evidence builder
// ---------------------------------------------------------------------------

describe('runScenarios — evidence builder', () => {
  it('calls addResult once per executed scenario', async () => {
    const ctx = makeCtx()
    await runScenarios([makeScenario('s1'), makeScenario('s2'), makeScenario('s3')], ctx, BASE_OPTS)
    expect((ctx.builder as { addResult: ReturnType<typeof vi.fn> }).addResult).toHaveBeenCalledTimes(3)
  })

  it('does not call addResult for scenarios skipped by fail-fast', async () => {
    const ctx = makeCtx({ validateResult: makeValidation('Fail') })
    await runScenarios(
      [makeScenario('s1'), makeScenario('s2'), makeScenario('s3')],
      ctx,
      { ...BASE_OPTS, failFast: true },
    )
    // Only s1 ran before fail-fast triggered.
    expect((ctx.builder as { addResult: ReturnType<typeof vi.fn> }).addResult).toHaveBeenCalledTimes(1)
  })
})

// ---------------------------------------------------------------------------
// Preventive vs runtime dispatch
// ---------------------------------------------------------------------------

describe('runScenarios — executor dispatch', () => {
  it('uses the preventive executor for non-runtime scenarios', async () => {
    const ctx = makeCtx()
    await runScenarios([makeScenario('s1')], ctx, BASE_OPTS)
    expect((ctx.executor as { execute: ReturnType<typeof vi.fn> }).execute).toHaveBeenCalledTimes(1)
    expect((ctx.runtimeExecutor as { execute: ReturnType<typeof vi.fn> }).execute).not.toHaveBeenCalled()
  })

  it('uses the runtime executor for scenarios that have an execStep', async () => {
    const ctx = makeCtx()
    await runScenarios([makeRuntimeScenario('r1')], ctx, BASE_OPTS)
    expect((ctx.runtimeExecutor as { execute: ReturnType<typeof vi.fn> }).execute).toHaveBeenCalledTimes(1)
    expect((ctx.executor as { execute: ReturnType<typeof vi.fn> }).execute).not.toHaveBeenCalled()
  })

  it('dispatches to the correct executor for each scenario in a mixed list', async () => {
    const ctx = makeCtx()
    await runScenarios(
      [makeScenario('preventive'), makeRuntimeScenario('runtime'), makeScenario('preventive-2')],
      ctx,
      BASE_OPTS,
    )
    expect((ctx.executor as { execute: ReturnType<typeof vi.fn> }).execute).toHaveBeenCalledTimes(2)
    expect((ctx.runtimeExecutor as { execute: ReturnType<typeof vi.fn> }).execute).toHaveBeenCalledTimes(1)
  })

  it('passes the correct namespace and timeout to the preventive executor', async () => {
    const ctx = makeCtx()
    await runScenarios([makeScenario('s1')], ctx, { ...BASE_OPTS, namespace: 'my-ns', timeout: '5000' })
    const call = (ctx.executor as { execute: ReturnType<typeof vi.fn> }).execute.mock.calls[0]
    expect(call?.[1]).toMatchObject({ namespace: 'my-ns', timeoutMs: 5000 })
  })
})
