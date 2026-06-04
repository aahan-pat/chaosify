import { describe, it, expect, vi } from 'vitest'
import * as k8s from '@kubernetes/client-node'
import { CleanupManager } from '../../../src/core/teardown/cleanup.js'
import type { CleanupTarget } from '../../../src/core/teardown/cleanup.js'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeKc(deleteImpl: () => Promise<unknown> = () => Promise.resolve()): k8s.KubeConfig {
  const deleteNamespacedPod = vi.fn(deleteImpl)
  return {
    makeApiClient: vi.fn().mockReturnValue({ deleteNamespacedPod }),
  } as unknown as k8s.KubeConfig
}

const POD: CleanupTarget = { kind: 'Pod', name: 'chaosify-test-abc', namespace: 'chaosify' }
const POD2: CleanupTarget = { kind: 'Pod', name: 'chaosify-test-def', namespace: 'chaosify' }
const POD3: CleanupTarget = { kind: 'Pod', name: 'chaosify-test-ghi', namespace: 'chaosify' }

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('CleanupManager', () => {
  describe('empty target list', () => {
    it('returns skipped immediately without calling the API', () => {
      const kc = makeKc()
      const manager = new CleanupManager(kc)
      return manager.cleanup([]).then(result => {
        expect(result.status).toBe('skipped')
        expect(result.remainingResources).toEqual([])
        expect((kc.makeApiClient as ReturnType<typeof vi.fn>).mock.calls).toHaveLength(0)
      })
    })
  })

  describe('single target', () => {
    it('returns success when the pod is deleted successfully', async () => {
      const kc = makeKc(() => Promise.resolve())
      const manager = new CleanupManager(kc)

      const result = await manager.cleanup([POD])

      expect(result.status).toBe('success')
      expect(result.remainingResources).toEqual([])
    })

    it('returns failed when the API call throws', async () => {
      const kc = makeKc(() => Promise.reject(new Error('not found')))
      const manager = new CleanupManager(kc)

      const result = await manager.cleanup([POD])

      expect(result.status).toBe('failed')
      expect(result.remainingResources).toEqual([POD])
    })
  })

  describe('multiple targets', () => {
    it('returns success when all pods are deleted', async () => {
      const kc = makeKc(() => Promise.resolve())
      const manager = new CleanupManager(kc)

      const result = await manager.cleanup([POD, POD2])

      expect(result.status).toBe('success')
      expect(result.remainingResources).toEqual([])
    })

    it('returns partial when some but not all deletions fail', async () => {
      let callCount = 0
      const kc = makeKc(() => {
        callCount++
        // Fail only the second call
        return callCount === 2 ? Promise.reject(new Error('api error')) : Promise.resolve()
      })
      const manager = new CleanupManager(kc)

      const result = await manager.cleanup([POD, POD2, POD3])

      expect(result.status).toBe('partial')
      expect(result.remainingResources).toHaveLength(1)
      expect(result.remainingResources[0]).toEqual(POD2)
    })

    it('returns failed when all deletions fail', async () => {
      const kc = makeKc(() => Promise.reject(new Error('cluster unreachable')))
      const manager = new CleanupManager(kc)

      const result = await manager.cleanup([POD, POD2])

      expect(result.status).toBe('failed')
      expect(result.remainingResources).toEqual([POD, POD2])
    })

    it('includes a detail message for partial failures', async () => {
      let callCount = 0
      const kc = makeKc(() => {
        callCount++
        return callCount === 1 ? Promise.reject(new Error('err')) : Promise.resolve()
      })
      const manager = new CleanupManager(kc)

      const result = await manager.cleanup([POD, POD2])

      expect(result.status).toBe('partial')
      expect(result.detail).toMatch(/could not be deleted/i)
    })
  })

  describe('API call arguments', () => {
    it('passes the correct name and namespace to deleteNamespacedPod', async () => {
      const deleteNamespacedPod = vi.fn(() => Promise.resolve())
      const kc = {
        makeApiClient: vi.fn().mockReturnValue({ deleteNamespacedPod }),
      } as unknown as k8s.KubeConfig
      const manager = new CleanupManager(kc)

      await manager.cleanup([POD])

      expect(deleteNamespacedPod).toHaveBeenCalledWith({
        name: 'chaosify-test-abc',
        namespace: 'chaosify',
      })
    })
  })
})
