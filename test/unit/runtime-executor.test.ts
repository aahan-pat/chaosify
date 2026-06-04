import { describe, it, expect, vi } from 'vitest'
import * as k8s from '@kubernetes/client-node'
import { RuntimeScenarioExecutor } from '../../src/core/scenarios/exec/runtime-executor.js'
import type { RuntimeAlertSource, RuntimeAlert } from '../../src/core/scenarios/exec/runtime-executor.js'
import type { RuntimeScenarioDefinition } from '../../src/types/runtime-scenario.js'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const SCENARIO: RuntimeScenarioDefinition = {
  id: 'test-runtime',
  version: 1,
  name: 'Test runtime scenario',
  description: 'Test',
  category: 'detective',
  controlObjective: 'Detect privileged exec',
  prerequisites: [],
  manifest: {
    apiVersion: 'v1',
    kind: 'Pod',
    metadata: { name: 'original-name', namespace: 'wrong-ns' },
    spec: { containers: [{ name: 'test', image: 'busybox:1.36' }] },
  },
  execStep: { container: 'test', command: ['cat', '/etc/shadow'] },
  expectedOutcome: { type: 'alert_fired' },
  cleanup: { deleteCreatedResources: true },
  safety: { level: 'low', namespaceScoped: true },
}

// ---------------------------------------------------------------------------
// Testable subclass — overrides createExec so tests never need a real websocket
// ---------------------------------------------------------------------------

class TestableRuntimeExecutor extends RuntimeScenarioExecutor {
  protected override createExec(): k8s.Exec {
    return {
      exec: (
        _ns: string,
        _pod: string,
        _container: string,
        _command: string[],
        _stdout: unknown,
        _stderr: unknown,
        _stdin: unknown,
        _tty: boolean,
        statusCallback: (status: k8s.V1Status) => void,
      ) => {
        // Fire the status callback on the next tick so the promise resolves
        Promise.resolve().then(() => statusCallback({} as k8s.V1Status))
        return Promise.resolve(null as unknown as WebSocket)
      },
    } as unknown as k8s.Exec
  }
}

const ALERT: RuntimeAlert = {
  source: 'falco',
  ruleName: 'Terminal shell in container',
  namespace: 'chaosify-test',
  podName: 'chaosify-test-x4f7b',
  triggeredAt: new Date().toISOString(),
  raw: '{"rule":"Terminal shell in container"}',
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a mock KubeConfig whose CoreV1Api methods are controllable */
function makeKc(
  createPod: () => Promise<k8s.V1Pod>,
  readPod: () => Promise<k8s.V1Pod> = () =>
    Promise.resolve({
      status: { phase: 'Running', containerStatuses: [{ ready: true, name: 'test' }] },
    }),
): { kc: k8s.KubeConfig; createNamespacedPod: ReturnType<typeof vi.fn> } {
  const createNamespacedPod = vi.fn(createPod)
  const readNamespacedPod = vi.fn(readPod)
  const kc = {
    makeApiClient: vi.fn().mockReturnValue({ createNamespacedPod, readNamespacedPod }),
  } as unknown as k8s.KubeConfig
  return { kc, createNamespacedPod }
}

/** Build a mock alert source with controllable pollForAlert behaviour */
function makeAlertSource(
  poll: () => Promise<RuntimeAlert | null> = () => Promise.resolve(null),
): RuntimeAlertSource {
  return {
    name: 'mock',
    isAvailable: vi.fn().mockResolvedValue(true),
    pollForAlert: vi.fn(poll),
  }
}

const BASE_OPTIONS = { namespace: 'chaosify-test', observationWindowMs: 500, timeoutMs: 2_000 }

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('RuntimeScenarioExecutor', () => {
  describe('execute()', () => {
    it('returns alert_fired when the alert source fires within the window', async () => {
      const { kc } = makeKc(() =>
        Promise.resolve({ metadata: { name: 'chaosify-test-abc1' } }),
      )
      const alertSource = makeAlertSource(() => Promise.resolve(ALERT))
      const executor = new TestableRuntimeExecutor(kc, alertSource)

      const result = await executor.execute(SCENARIO, BASE_OPTIONS)

      expect(result.observedOutcome).toBe('alert_fired')
      expect(result.alertDetail).toEqual(ALERT)
      expect(result.createdResourceName).toBe('chaosify-test-abc1')
    })

    it('returns no_alert when the observation window closes without an alert', async () => {
      const { kc } = makeKc(() =>
        Promise.resolve({ metadata: { name: 'chaosify-test-abc2' } }),
      )
      const alertSource = makeAlertSource(() => Promise.resolve(null))
      const executor = new TestableRuntimeExecutor(kc, alertSource)

      const result = await executor.execute(SCENARIO, BASE_OPTIONS)

      expect(result.observedOutcome).toBe('no_alert')
      expect(result.alertDetail).toBeUndefined()
      expect(result.createdResourceName).toBe('chaosify-test-abc2')
    })

    it('returns api_error when the Kubernetes API rejects the pod', async () => {
      const apiError = Object.assign(new Error('forbidden'), { response: { statusCode: 403 } })
      const { kc } = makeKc(() => Promise.reject(apiError))
      const executor = new TestableRuntimeExecutor(kc, makeAlertSource())

      const result = await executor.execute(SCENARIO, BASE_OPTIONS)

      expect(result.observedOutcome).toBe('api_error')
      expect(result.rawResponse).toContain('forbidden')
      expect(result.createdResourceName).toBeUndefined()
    })

    it('returns api_error when the server creates the pod without assigning a name', async () => {
      const { kc } = makeKc(() => Promise.resolve({ metadata: {} }))
      const executor = new TestableRuntimeExecutor(kc, makeAlertSource())

      const result = await executor.execute(SCENARIO, BASE_OPTIONS)

      expect(result.observedOutcome).toBe('api_error')
      expect(result.rawResponse).toMatch(/no name/i)
    })

    it('returns timeout when the submit step exceeds timeoutMs', async () => {
      // Promise that never resolves — relies on the executor's internal timeout
      const { kc } = makeKc(() => new Promise(() => {}))
      const executor = new TestableRuntimeExecutor(kc, makeAlertSource())

      const result = await executor.execute(SCENARIO, { ...BASE_OPTIONS, timeoutMs: 80 })

      expect(result.observedOutcome).toBe('timeout')
      expect(result.createdResourceName).toBeUndefined()
    }, 1_000)

    it('returns api_error with createdResourceName when the alert source throws', async () => {
      const { kc } = makeKc(() =>
        Promise.resolve({ metadata: { name: 'chaosify-test-abc3' } }),
      )
      const alertSource = makeAlertSource(() => Promise.reject(new Error('falco unavailable')))
      const executor = new TestableRuntimeExecutor(kc, alertSource)

      const result = await executor.execute(SCENARIO, BASE_OPTIONS)

      expect(result.observedOutcome).toBe('api_error')
      expect(result.rawResponse).toContain('falco unavailable')
      // Pod was created before the observe phase failed — name must be preserved for cleanup
      expect(result.createdResourceName).toBe('chaosify-test-abc3')
    })

    it('injects namespace and generateName into the submitted manifest', async () => {
      const { kc, createNamespacedPod } = makeKc(() =>
        Promise.resolve({ metadata: { name: 'chaosify-test-abc4' } }),
      )
      const executor = new TestableRuntimeExecutor(kc, makeAlertSource())

      await executor.execute(SCENARIO, BASE_OPTIONS)

      const submittedPod = createNamespacedPod.mock.calls[0]?.[0]?.body as k8s.V1Pod
      expect(submittedPod.metadata?.namespace).toBe('chaosify-test')
      expect(submittedPod.metadata?.generateName).toBe('chaosify-test-')
      // Original name should be cleared so generateName takes over
      expect(submittedPod.metadata?.name).toBeUndefined()
    })

    it('uses chaosify-test- as the pod name prefix when polling for alerts', async () => {
      const { kc } = makeKc(() =>
        Promise.resolve({ metadata: { name: 'chaosify-test-abc5' } }),
      )
      const alertSource = makeAlertSource(() => Promise.resolve(ALERT))
      const executor = new TestableRuntimeExecutor(kc, alertSource)

      await executor.execute(SCENARIO, BASE_OPTIONS)

      const pollCall = (alertSource.pollForAlert as ReturnType<typeof vi.fn>).mock.calls[0]
      expect(pollCall?.[1]).toBe('chaosify-test-')
    })

    it('passes the correct namespace to pollForAlert', async () => {
      const { kc } = makeKc(() =>
        Promise.resolve({ metadata: { name: 'chaosify-test-abc6' } }),
      )
      const alertSource = makeAlertSource(() => Promise.resolve(null))
      const executor = new TestableRuntimeExecutor(kc, alertSource)

      await executor.execute(SCENARIO, { ...BASE_OPTIONS, namespace: 'my-custom-ns' })

      const pollCall = (alertSource.pollForAlert as ReturnType<typeof vi.fn>).mock.calls[0]
      expect(pollCall?.[0]).toBe('my-custom-ns')
    })

    it('records startedAt and endedAt as ISO timestamps', async () => {
      const { kc } = makeKc(() =>
        Promise.resolve({ metadata: { name: 'chaosify-test-abc7' } }),
      )
      const executor = new TestableRuntimeExecutor(kc, makeAlertSource())

      const result = await executor.execute(SCENARIO, BASE_OPTIONS)

      expect(() => new Date(result.startedAt)).not.toThrow()
      expect(() => new Date(result.endedAt)).not.toThrow()
      expect(new Date(result.endedAt).getTime()).toBeGreaterThanOrEqual(
        new Date(result.startedAt).getTime(),
      )
    })

    it('preserves manifestSnapshot as the injected manifest JSON', async () => {
      const { kc } = makeKc(() =>
        Promise.resolve({ metadata: { name: 'chaosify-test-abc8' } }),
      )
      const executor = new TestableRuntimeExecutor(kc, makeAlertSource())

      const result = await executor.execute(SCENARIO, BASE_OPTIONS)

      const snapshot = JSON.parse(result.manifestSnapshot) as Record<string, unknown>
      const meta = snapshot['metadata'] as Record<string, unknown>
      // Snapshot should reflect the injected namespace, not the original
      expect(meta['namespace']).toBe('chaosify-test')
    })
  })
})
