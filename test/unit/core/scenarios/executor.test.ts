import { describe, it, expect, vi } from 'vitest'
import * as k8s from '@kubernetes/client-node'
import { ScenarioExecutor } from '../../../../src/core/scenarios/exec/executor.js'
import type { ScenarioDefinition } from '../../../../src/types/scenario.js'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeScenario(overrides: Partial<ScenarioDefinition> = {}): ScenarioDefinition {
  return {
    id: 'deny-privileged',
    version: 1,
    name: 'Deny privileged containers',
    description: 'Test',
    category: 'preventive',
    controlObjective: 'Prevent privileged containers',
    prerequisites: [],
    manifest: {
      kind: 'Pod',
      apiVersion: 'v1',
      metadata: { name: 'test-pod', namespace: 'wrong-ns' },
      spec: { containers: [{ name: 'c', image: 'busybox:1.36' }] },
    },
    expectedOutcome: { type: 'admission_rejected' },
    cleanup: { deleteCreatedResources: true },
    safety: { level: 'low', namespaceScoped: true },
    ...overrides,
  }
}

// Build a mock KubeConfig whose CoreV1Api is fully controllable.
function makeKc(
  createImpl: () => Promise<k8s.V1Pod> = () => Promise.resolve({ metadata: { name: 'chaosclaw-test-abc1' } }),
): { kc: k8s.KubeConfig; createNamespacedPod: ReturnType<typeof vi.fn> } {
  const createNamespacedPod = vi.fn(createImpl)
  const kc = {
    makeApiClient: vi.fn().mockReturnValue({ createNamespacedPod }),
  } as unknown as k8s.KubeConfig
  return { kc, createNamespacedPod }
}

// ScenarioExecutor checks response?.statusCode for admission rejections, not statusCode at top level.
function admissionError(statusCode: number): Error {
  return Object.assign(new Error(`HTTP ${statusCode}`), { response: { statusCode } })
}

const OPTS = { namespace: 'chaosclaw-test', timeoutMs: 2_000 }

// ---------------------------------------------------------------------------
// Admission outcomes
// ---------------------------------------------------------------------------

describe('ScenarioExecutor.execute() — admission outcomes', () => {
  it('returns admission_allowed when the pod is created successfully', async () => {
    const { kc } = makeKc(() => Promise.resolve({ metadata: { name: 'chaosclaw-test-abc1' } }))
    const result = await new ScenarioExecutor(kc).execute(makeScenario(), OPTS)
    expect(result.observedOutcome).toBe('admission_allowed')
  })

  it('captures the server-assigned pod name in createdResourceName for cleanup', async () => {
    const { kc } = makeKc(() => Promise.resolve({ metadata: { name: 'chaosclaw-test-xyz9' } }))
    const result = await new ScenarioExecutor(kc).execute(makeScenario(), OPTS)
    expect(result.createdResourceName).toBe('chaosclaw-test-xyz9')
  })

  it('returns admission_rejected when the API returns 403 (RBAC or webhook denial)', async () => {
    const { kc } = makeKc(() => Promise.reject(admissionError(403)))
    const result = await new ScenarioExecutor(kc).execute(makeScenario(), OPTS)
    expect(result.observedOutcome).toBe('admission_rejected')
  })

  it('returns admission_rejected when the API returns 400 (webhook validation failure)', async () => {
    const { kc } = makeKc(() => Promise.reject(admissionError(400)))
    const result = await new ScenarioExecutor(kc).execute(makeScenario(), OPTS)
    expect(result.observedOutcome).toBe('admission_rejected')
  })

  it('returns api_error for 422 (some webhook rejections return Unprocessable Entity)', async () => {
    // 422 is NOT recognised as an admission rejection — only 400 and 403 are.
    const { kc } = makeKc(() => Promise.reject(admissionError(422)))
    const result = await new ScenarioExecutor(kc).execute(makeScenario(), OPTS)
    expect(result.observedOutcome).toBe('api_error')
  })

  it('returns api_error for a 500 server error', async () => {
    const { kc } = makeKc(() => Promise.reject(admissionError(500)))
    const result = await new ScenarioExecutor(kc).execute(makeScenario(), OPTS)
    expect(result.observedOutcome).toBe('api_error')
  })

  it('returns api_error for a plain Error with no statusCode (network failure, etc.)', async () => {
    const { kc } = makeKc(() => Promise.reject(new Error('connection refused')))
    const result = await new ScenarioExecutor(kc).execute(makeScenario(), OPTS)
    expect(result.observedOutcome).toBe('api_error')
    expect(result.rawResponse).toContain('connection refused')
  })

  it('does NOT treat top-level statusCode 403 as an admission rejection — only response.statusCode is checked', async () => {
    // isForbidden() in errors.ts uses statusCode at the top level, but ScenarioExecutor uses
    // response?.statusCode — these are different error shapes and must not be confused.
    const topLevelErr = Object.assign(new Error('Forbidden'), { statusCode: 403 })
    const { kc } = makeKc(() => Promise.reject(topLevelErr))
    const result = await new ScenarioExecutor(kc).execute(makeScenario(), OPTS)
    expect(result.observedOutcome).toBe('api_error')
  })
})

// ---------------------------------------------------------------------------
// Unsupported manifest kinds
// ---------------------------------------------------------------------------

describe('ScenarioExecutor.execute() — unsupported manifest kind', () => {
  it('returns api_error for a Deployment manifest (only Pod is supported)', async () => {
    const { kc } = makeKc()
    const scenario = makeScenario({ manifest: { kind: 'Deployment', apiVersion: 'apps/v1', metadata: { name: 'test' } } })
    const result = await new ScenarioExecutor(kc).execute(scenario, OPTS)
    expect(result.observedOutcome).toBe('api_error')
    expect(result.rawResponse).toMatch(/unsupported manifest kind/i)
  })

  it('returns api_error when manifest has no kind field', async () => {
    const { kc } = makeKc()
    const scenario = makeScenario({ manifest: { apiVersion: 'v1', metadata: { name: 'test' } } })
    const result = await new ScenarioExecutor(kc).execute(scenario, OPTS)
    expect(result.observedOutcome).toBe('api_error')
  })
})

// ---------------------------------------------------------------------------
// Timeout
// ---------------------------------------------------------------------------

describe('ScenarioExecutor.execute() — timeout', () => {
  it('returns api_error (not timeout) when the API call never resolves', async () => {
    // Unlike RuntimeScenarioExecutor, ScenarioExecutor does not distinguish timeout from api_error.
    const { kc } = makeKc(() => new Promise(() => {}))
    const result = await new ScenarioExecutor(kc).execute(makeScenario(), { ...OPTS, timeoutMs: 80 })
    expect(result.observedOutcome).toBe('api_error')
  }, 1_000)
})

// ---------------------------------------------------------------------------
// Namespace injection
// ---------------------------------------------------------------------------

describe('ScenarioExecutor.execute() — namespace injection', () => {
  it('injects the target namespace and sets generateName before submission', async () => {
    const { kc, createNamespacedPod } = makeKc(() =>
      Promise.resolve({ metadata: { name: 'chaosclaw-test-inj1' } }),
    )
    await new ScenarioExecutor(kc).execute(makeScenario(), OPTS)
    const submitted = createNamespacedPod.mock.calls[0]?.[0]?.body as k8s.V1Pod
    expect(submitted.metadata?.namespace).toBe('chaosclaw-test')
    expect(submitted.metadata?.generateName).toBe('chaosclaw-test-')
    // The original name is cleared so generateName takes over.
    expect(submitted.metadata?.name).toBeUndefined()
  })

  it('preserves other metadata fields when injecting namespace', async () => {
    const { kc, createNamespacedPod } = makeKc(() =>
      Promise.resolve({ metadata: { name: 'chaosclaw-test-inj2' } }),
    )
    const scenario = makeScenario({
      manifest: {
        kind: 'Pod',
        apiVersion: 'v1',
        metadata: { name: 'test', labels: { app: 'test-app' } },
        spec: { containers: [{ name: 'c', image: 'busybox' }] },
      },
    })
    await new ScenarioExecutor(kc).execute(scenario, OPTS)
    const submitted = createNamespacedPod.mock.calls[0]?.[0]?.body as k8s.V1Pod
    expect(submitted.metadata?.labels).toEqual({ app: 'test-app' })
  })

  it('handles manifests with no metadata by creating one', async () => {
    const { kc, createNamespacedPod } = makeKc(() =>
      Promise.resolve({ metadata: { name: 'chaosclaw-test-inj3' } }),
    )
    const scenario = makeScenario({ manifest: { kind: 'Pod', apiVersion: 'v1' } })
    await new ScenarioExecutor(kc).execute(scenario, OPTS)
    const submitted = createNamespacedPod.mock.calls[0]?.[0]?.body as k8s.V1Pod
    expect(submitted.metadata?.namespace).toBe('chaosclaw-test')
  })
})

// ---------------------------------------------------------------------------
// Timing and evidence fields
// ---------------------------------------------------------------------------

describe('ScenarioExecutor.execute() — evidence fields', () => {
  it('records valid ISO timestamps for startedAt and endedAt', async () => {
    const { kc } = makeKc(() => Promise.resolve({ metadata: { name: 'chaosclaw-test-t1' } }))
    const result = await new ScenarioExecutor(kc).execute(makeScenario(), OPTS)
    expect(() => new Date(result.startedAt)).not.toThrow()
    expect(() => new Date(result.endedAt)).not.toThrow()
    expect(new Date(result.endedAt).getTime()).toBeGreaterThanOrEqual(new Date(result.startedAt).getTime())
  })

  it('stores the post-injection manifest in manifestSnapshot, not the original', async () => {
    const { kc } = makeKc(() => Promise.resolve({ metadata: { name: 'chaosclaw-test-t2' } }))
    const result = await new ScenarioExecutor(kc).execute(makeScenario(), OPTS)
    const snapshot = JSON.parse(result.manifestSnapshot) as k8s.V1Pod
    // Snapshot must reflect the injected namespace, not the "wrong-ns" in the original fixture.
    expect(snapshot.metadata?.namespace).toBe('chaosclaw-test')
  })

  it('does not set createdResourceName on admission_rejected', async () => {
    const { kc } = makeKc(() => Promise.reject(admissionError(403)))
    const result = await new ScenarioExecutor(kc).execute(makeScenario(), OPTS)
    expect(result.createdResourceName).toBeUndefined()
  })
})
