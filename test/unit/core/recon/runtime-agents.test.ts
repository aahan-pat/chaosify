import { describe, it, expect, vi } from 'vitest'
import * as k8s from '@kubernetes/client-node'

vi.mock('../../../../src/core/kube/client.js', () => ({ appsV1Api: vi.fn() }))

import { surveyRuntimeAgents } from '../../../../src/core/recon/runtime-agents.js'
import { appsV1Api } from '../../../../src/core/kube/client.js'
import type { RuntimeThreatGraph } from '../../../../src/types/recon.js'

const appsMock = appsV1Api as ReturnType<typeof vi.fn>
const OPTS = { namespace: 'chaosify' }
const KC = {} as k8s.KubeConfig

// A DaemonSet for a named agent with given readiness/desired counts.
function ds(name: string, ready: number, desired: number, namespace = 'falco') {
  return { metadata: { name, namespace }, status: { numberReady: ready, desiredNumberScheduled: desired } }
}

function setup(daemonsets: unknown[]) {
  appsMock.mockReturnValue({ listDaemonSetForAllNamespaces: vi.fn().mockResolvedValue({ items: daemonsets }) })
}

function graphOf(result: Awaited<ReturnType<typeof surveyRuntimeAgents>>): RuntimeThreatGraph {
  return result.data as RuntimeThreatGraph
}

describe('surveyRuntimeAgents — no agents', () => {
  it('emits a HIGH finding when no known agent DaemonSet exists', async () => {
    setup([ds('some-other-ds', 3, 3)])
    const result = await surveyRuntimeAgents(KC, OPTS)
    expect(graphOf(result).agentsDetected).toBe(0)
    expect(result.findings.filter(f => f.severity === 'HIGH')).toHaveLength(1)
    expect(result.findings[0]!.title).toMatch(/no runtime detection agents/i)
  })
})

describe('surveyRuntimeAgents — partial coverage', () => {
  it('flags a detection_gap when an agent is ready on fewer nodes than desired', async () => {
    setup([ds('falco', 2, 3)])
    const graph = graphOf(await surveyRuntimeAgents(KC, OPTS))
    const gap = graph.findings.find(f => f.exploitClasses.includes('detection_gap'))
    expect(gap).toBeDefined()
    expect(gap!.severity).toBe('high')
    expect(gap!.suggestedProbe).toContain('probe detect')
    expect(gap!.suggestedProbe).toContain('falco')
  })

  it('does not flag a detection_gap at full coverage', async () => {
    setup([ds('falco', 3, 3), ds('kubearmor', 3, 3, 'kubearmor')])
    const graph = graphOf(await surveyRuntimeAgents(KC, OPTS))
    expect(graph.findings.some(f => f.exploitClasses.includes('detection_gap'))).toBe(false)
  })
})

describe('surveyRuntimeAgents — detect-only posture', () => {
  it('flags no_enforcement when Falco is present without an LSM enforcer', async () => {
    setup([ds('falco', 3, 3)])
    const graph = graphOf(await surveyRuntimeAgents(KC, OPTS))
    const noEnf = graph.findings.find(f => f.exploitClasses.includes('no_enforcement'))
    expect(noEnf).toBeDefined()
    expect(noEnf!.severity).toBe('medium')
  })

  it('does not flag no_enforcement when an LSM enforcer (Tetragon) is present alongside Falco', async () => {
    setup([ds('falco', 3, 3), ds('tetragon', 3, 3, 'tetragon')])
    const graph = graphOf(await surveyRuntimeAgents(KC, OPTS))
    expect(graph.findings.some(f => f.exploitClasses.includes('no_enforcement'))).toBe(false)
  })
})

describe('surveyRuntimeAgents — blind spots', () => {
  it('always reports presence-vs-detection and rule-coverage blind spots', async () => {
    setup([])
    const graph = graphOf(await surveyRuntimeAgents(KC, OPTS))
    expect(graph.blindSpots.some(b => /probe detect|fires/i.test(b))).toBe(true)
    expect(graph.blindSpots.some(b => /rule/i.test(b))).toBe(true)
  })
})
