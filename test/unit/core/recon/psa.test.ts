import { describe, it, expect, vi, beforeEach } from 'vitest'
import type * as k8s from '@kubernetes/client-node'

// ---------------------------------------------------------------------------
// Module mocks — surveyPsa is pod-first: it lists pods and namespaces cluster-wide,
// evaluates the PSA enforce label on each pod's namespace, and emits exploit chains.
// We mock coreV1Api to drive both listPodForAllNamespaces and listNamespace.
// ---------------------------------------------------------------------------

vi.mock('../../../../src/core/kube/client.js', () => ({
  coreV1Api: vi.fn(),
}))

import { surveyPsa } from '../../../../src/core/recon/psa.js'
import { coreV1Api } from '../../../../src/core/kube/client.js'
import type { PsaThreatGraph } from '../../../../src/types/recon.js'

const coreMock = coreV1Api as ReturnType<typeof vi.fn>

const OPTS = { namespace: 'chaosify' }
const KC = {} as k8s.KubeConfig

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

function pod(name: string, namespace: string, opts: { phase?: string } = {}): k8s.V1Pod {
  return {
    metadata: { name, namespace },
    status: { phase: opts.phase ?? 'Running' },
  } as k8s.V1Pod
}

function namespace(name: string, opts: { enforce?: string; audit?: string; warn?: string } = {}): k8s.V1Namespace {
  const labels: Record<string, string> = {}
  if (opts.enforce) labels['pod-security.kubernetes.io/enforce'] = opts.enforce
  if (opts.audit) labels['pod-security.kubernetes.io/audit'] = opts.audit
  if (opts.warn) labels['pod-security.kubernetes.io/warn'] = opts.warn
  return { metadata: { name, labels } } as k8s.V1Namespace
}

function forbiddenErr(): Error {
  return Object.assign(new Error('Forbidden'), { statusCode: 403 })
}

function setup(opts: { pods?: k8s.V1Pod[]; namespaces?: k8s.V1Namespace[]; listError?: unknown }) {
  const listPodForAllNamespaces = opts.listError
    ? vi.fn().mockRejectedValue(opts.listError)
    : vi.fn().mockResolvedValue({ items: opts.pods ?? [] })
  const listNamespace = opts.listError
    ? vi.fn().mockRejectedValue(opts.listError)
    : vi.fn().mockResolvedValue({ items: opts.namespaces ?? [] })
  coreMock.mockReturnValue({ listPodForAllNamespaces, listNamespace })
}

function graphOf(result: Awaited<ReturnType<typeof surveyPsa>>): PsaThreatGraph {
  return result.data as PsaThreatGraph
}

beforeEach(() => {
  coreMock.mockReset()
})

// ---------------------------------------------------------------------------
// Permission unreachable → skip
// ---------------------------------------------------------------------------

describe('surveyPsa — permissions', () => {
  it('returns skip on 403', async () => {
    setup({ listError: forbiddenErr() })
    const result = await surveyPsa(KC, OPTS)
    expect(result.status).toBe('skip')
  })
})

// ---------------------------------------------------------------------------
// node_escape findings — no enforce or enforce=privileged
// ---------------------------------------------------------------------------

describe('surveyPsa — node_escape findings', () => {
  it('flags a pod in a namespace with no PSA labels as node_escape HIGH', async () => {
    setup({ pods: [pod('app', 'default')], namespaces: [namespace('default')] })
    const graph = graphOf(await surveyPsa(KC, OPTS))

    expect(graph.findings).toHaveLength(1)
    const f = graph.findings[0]!
    expect(f.namespace).toBe('default')
    expect(f.enforceLevel).toBe('none')
    expect(f.auditOnly).toBe(false)
    expect(f.exploitClasses).toEqual(['node_escape'])
    expect(f.severity).toBe('high')
    expect(f.suggestedProbe).toContain('preventive-baseline')
    expect(f.suggestedProbe).toContain('default')
  })

  it('flags a pod in a namespace with enforce=privileged as node_escape HIGH', async () => {
    setup({ pods: [pod('app', 'prod')], namespaces: [namespace('prod', { enforce: 'privileged' })] })
    const graph = graphOf(await surveyPsa(KC, OPTS))

    const f = graph.findings[0]!
    expect(f.enforceLevel).toBe('privileged')
    expect(f.exploitClasses).toEqual(['node_escape'])
    expect(f.severity).toBe('high')
    expect(f.impact).toContain('explicitly disabled')
  })

  it('flags an audit-only namespace as node_escape HIGH with auditOnly=true', async () => {
    setup({
      pods: [pod('app', 'staging')],
      namespaces: [namespace('staging', { audit: 'restricted', warn: 'restricted' })],
    })
    const graph = graphOf(await surveyPsa(KC, OPTS))

    const f = graph.findings[0]!
    expect(f.enforceLevel).toBe('none')
    expect(f.auditOnly).toBe(true)
    expect(f.exploitClasses).toEqual(['node_escape'])
    expect(f.severity).toBe('high')
    expect(f.impact).toContain('audit/warn mode only')
  })
})

// ---------------------------------------------------------------------------
// container_escape findings — enforce=baseline
// ---------------------------------------------------------------------------

describe('surveyPsa — container_escape findings', () => {
  it('flags a pod in a baseline namespace as container_escape MEDIUM', async () => {
    setup({ pods: [pod('app', 'prod')], namespaces: [namespace('prod', { enforce: 'baseline' })] })
    const graph = graphOf(await surveyPsa(KC, OPTS))

    expect(graph.findings).toHaveLength(1)
    const f = graph.findings[0]!
    expect(f.enforceLevel).toBe('baseline')
    expect(f.exploitClasses).toEqual(['container_escape'])
    expect(f.severity).toBe('medium')
    expect(f.suggestedProbe).toContain('deny-privilege-escalation')
    expect(f.suggestedProbe).toContain('prod')
  })
})

// ---------------------------------------------------------------------------
// No findings — enforce=restricted or no pods
// ---------------------------------------------------------------------------

describe('surveyPsa — no findings', () => {
  it('emits no findings for a pod in a restricted namespace', async () => {
    setup({ pods: [pod('app', 'prod')], namespaces: [namespace('prod', { enforce: 'restricted' })] })
    const graph = graphOf(await surveyPsa(KC, OPTS))

    expect(graph.findings).toHaveLength(0)
    expect(graph.podsScanned).toBe(1)
  })

  it('emits no findings and podsScanned=0 when there are no running pods', async () => {
    setup({ pods: [], namespaces: [namespace('default')] })
    const graph = graphOf(await surveyPsa(KC, OPTS))

    expect(graph.findings).toHaveLength(0)
    expect(graph.podsScanned).toBe(0)
  })

  it('excludes non-running pods (Pending, Succeeded)', async () => {
    setup({
      pods: [pod('pending', 'default', { phase: 'Pending' }), pod('done', 'default', { phase: 'Succeeded' })],
      namespaces: [namespace('default')],
    })
    const graph = graphOf(await surveyPsa(KC, OPTS))

    expect(graph.podsScanned).toBe(0)
    expect(graph.findings).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// Severity ordering — high before medium in the findings list
// ---------------------------------------------------------------------------

describe('surveyPsa — severity ordering', () => {
  it('surfaces high-severity findings before medium ones', async () => {
    setup({
      pods: [pod('app-a', 'ns-a'), pod('app-b', 'ns-b')],
      namespaces: [namespace('ns-a', { enforce: 'baseline' }), namespace('ns-b')],
    })
    const graph = graphOf(await surveyPsa(KC, OPTS))

    expect(graph.findings).toHaveLength(2)
    expect(graph.findings[0]!.severity).toBe('high')
    expect(graph.findings[1]!.severity).toBe('medium')
  })
})

// ---------------------------------------------------------------------------
// Noise control — replica pods collapsed into one finding
// ---------------------------------------------------------------------------

describe('surveyPsa — noise control', () => {
  it('collapses replicas sharing an exposure profile into one finding', async () => {
    setup({
      pods: [pod('app-1', 'default'), pod('app-2', 'default'), pod('app-3', 'default')],
      namespaces: [namespace('default')],
    })
    const graph = graphOf(await surveyPsa(KC, OPTS))

    expect(graph.findings).toHaveLength(1)
    expect(graph.findings[0]!.podCount).toBe(3)
  })

  it('excludes system namespaces by default and includes them with includeSystem', async () => {
    setup({ pods: [pod('kproxy', 'kube-system')], namespaces: [namespace('kube-system')] })

    expect(graphOf(await surveyPsa(KC, OPTS)).findings).toHaveLength(0)
    expect(graphOf(await surveyPsa(KC, { ...OPTS, includeSystem: true })).findings).toHaveLength(1)
  })

  it('keeps two findings when two namespaces have different exposure profiles', async () => {
    setup({
      pods: [pod('a', 'ns-a'), pod('b', 'ns-b')],
      namespaces: [namespace('ns-a'), namespace('ns-b', { enforce: 'baseline' })],
    })
    const graph = graphOf(await surveyPsa(KC, OPTS))

    expect(graph.findings).toHaveLength(2)
  })
})

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

describe('surveyPsa — counters', () => {
  it('reports podsScanned and namespacesScanned accurately', async () => {
    setup({
      pods: [pod('a', 'ns-a'), pod('b', 'ns-a'), pod('c', 'ns-b')],
      namespaces: [namespace('ns-a'), namespace('ns-b', { enforce: 'restricted' })],
    })
    const graph = graphOf(await surveyPsa(KC, OPTS))

    // All three running pods are scanned; both namespaces are listed.
    expect(graph.podsScanned).toBe(3)
    expect(graph.namespacesScanned).toBe(2)
  })
})

// ---------------------------------------------------------------------------
// Blind spots — always reported
// ---------------------------------------------------------------------------

describe('surveyPsa — blind spots', () => {
  it('always reports admission-controller, baseline, and retroactive blind spots', async () => {
    setup({ pods: [], namespaces: [] })
    const graph = graphOf(await surveyPsa(KC, OPTS))

    expect(graph.blindSpots.some(b => /Gatekeeper|Kyverno/i.test(b))).toBe(true)
    expect(graph.blindSpots.some(b => /baseline/i.test(b))).toBe(true)
    expect(graph.blindSpots.some(b => /retroactively|admission time/i.test(b))).toBe(true)
  })
})
