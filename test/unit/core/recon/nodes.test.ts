import { describe, it, expect, vi } from 'vitest'
import * as k8s from '@kubernetes/client-node'

vi.mock('../../../../src/core/kube/client.js', () => ({ coreV1Api: vi.fn() }))

import { surveyNodes } from '../../../../src/core/recon/nodes.js'
import { coreV1Api } from '../../../../src/core/kube/client.js'
import type { NodeInfo } from '../../../../src/types/recon.js'

const coreMock = coreV1Api as ReturnType<typeof vi.fn>
const OPTS = { namespace: 'chaosify' }
const KC = {} as k8s.KubeConfig

function node(name: string, kernel: string) {
  return { metadata: { name }, status: { nodeInfo: { osImage: 'Ubuntu', kernelVersion: kernel, containerRuntimeVersion: 'containerd://1.7' } } }
}

function setup(nodes: unknown[]) {
  coreMock.mockReturnValue({ listNode: vi.fn().mockResolvedValue({ items: nodes }) })
}

describe('surveyNodes — seccomp honesty', () => {
  it('reports seccompDefault as unknown rather than fabricating runtime/default', async () => {
    setup([node('node-1', '6.0.0')])
    const result = await surveyNodes(KC, OPTS)
    const nodes = (result.data as { nodes: NodeInfo[] }).nodes
    expect(nodes[0]!.seccompDefault).toBe('unknown')
    expect(nodes[0]!.seccompDefault).not.toBe('runtime/default')
  })
})

describe('surveyNodes — kernel outliers', () => {
  it('flags nodes running a non-dominant kernel version', async () => {
    setup([node('a', '6.0.0'), node('b', '6.0.0'), node('c', '5.15.0')])
    const result = await surveyNodes(KC, OPTS)
    const info = result.findings.filter(f => f.severity === 'INFO')
    expect(info).toHaveLength(1)
    expect(info[0]!.detail).toContain('c')
  })
})
