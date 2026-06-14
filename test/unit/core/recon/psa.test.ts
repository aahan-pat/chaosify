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

// A running pod whose spec actually exercises dangerous traits, for correlation tests.
function dangerousPod(
  name: string,
  namespace: string,
  spec: {
    privileged?: boolean
    allowPrivilegeEscalation?: boolean
    addCaps?: string[]
    hostNetwork?: boolean
    hostPID?: boolean
    hostPath?: boolean
  },
): k8s.V1Pod {
  return {
    metadata: { name, namespace },
    status: { phase: 'Running' },
    spec: {
      hostNetwork: spec.hostNetwork,
      hostPID: spec.hostPID,
      volumes: spec.hostPath ? [{ name: 'h', hostPath: { path: '/etc' } }] : undefined,
      containers: [{
        name: 'c',
        securityContext: {
          privileged: spec.privileged,
          allowPrivilegeEscalation: spec.allowPrivilegeEscalation,
          capabilities: spec.addCaps ? { add: spec.addCaps } : undefined,
        },
      }],
    },
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
// Confirmed chains — pod spec actually exercises an admitted dangerous trait
// ---------------------------------------------------------------------------

describe('surveyPsa — confirmed chains outrank permissive namespaces', () => {
  it('escalates a privileged pod in a no-enforce namespace from HIGH to CRITICAL', async () => {
    setup({
      pods: [dangerousPod('priv', 'default', { privileged: true })],
      namespaces: [namespace('default')],
    })
    const f = graphOf(await surveyPsa(KC, OPTS)).findings[0]!

    expect(f.severity).toBe('critical')
    expect(f.confirmed).toBe(true)
    expect(f.observedTraits).toContain('privileged')
    expect(f.exploitClasses).toEqual(['node_escape'])
    expect(f.impact).toContain('confirmed node breakout')
  })

  it('keeps a benign pod in a no-enforce namespace at HIGH and marks it unconfirmed', async () => {
    setup({ pods: [pod('app', 'default')], namespaces: [namespace('default')] })
    const f = graphOf(await surveyPsa(KC, OPTS)).findings[0]!

    expect(f.severity).toBe('high')
    expect(f.confirmed).toBe(false)
    expect(f.observedTraits).toEqual([])
    expect(f.impact).toContain('no running pod currently exercises this')
  })

  it('treats hostNetwork, hostPath, and dangerous capabilities as node-escape traits', async () => {
    for (const spec of [{ hostNetwork: true }, { hostPath: true }, { addCaps: ['NET_ADMIN'] }]) {
      setup({ pods: [dangerousPod('x', 'default', spec)], namespaces: [namespace('default')] })
      const f = graphOf(await surveyPsa(KC, OPTS)).findings[0]!
      expect(f.severity).toBe('critical')
      expect(f.confirmed).toBe(true)
    }
  })

  it('does not treat NET_BIND_SERVICE as a dangerous capability', async () => {
    setup({
      pods: [dangerousPod('x', 'default', { addCaps: ['NET_BIND_SERVICE'] })],
      namespaces: [namespace('default')],
    })
    const f = graphOf(await surveyPsa(KC, OPTS)).findings[0]!
    expect(f.severity).toBe('high')
    expect(f.observedTraits).not.toContain('dangerous_capabilities')
  })

  it('escalation-only in a no-enforce namespace stays HIGH but is confirmed', async () => {
    setup({
      pods: [dangerousPod('esc', 'default', { allowPrivilegeEscalation: true })],
      namespaces: [namespace('default')],
    })
    const f = graphOf(await surveyPsa(KC, OPTS)).findings[0]!

    expect(f.severity).toBe('high')
    expect(f.confirmed).toBe(true)
    expect(f.observedTraits).toEqual(['privilege_escalation'])
    expect(f.impact).toContain('confirmed privilege escalation')
  })

  it('escalates a confirmed escalating pod in a baseline namespace from MEDIUM to HIGH', async () => {
    setup({
      pods: [dangerousPod('esc', 'prod', { allowPrivilegeEscalation: true })],
      namespaces: [namespace('prod', { enforce: 'baseline' })],
    })
    const f = graphOf(await surveyPsa(KC, OPTS)).findings[0]!

    expect(f.enforceLevel).toBe('baseline')
    expect(f.severity).toBe('high')
    expect(f.confirmed).toBe(true)
    expect(f.exploitClasses).toEqual(['container_escape'])
  })

  it('does not confirm a node-escape trait that baseline would have blocked at admission', async () => {
    // A privileged pod cannot be admitted under baseline; if seen, it predates the label and is
    // not counted as a reachable chain — the finding stays a potential MEDIUM container_escape.
    setup({
      pods: [dangerousPod('priv', 'prod', { privileged: true })],
      namespaces: [namespace('prod', { enforce: 'baseline' })],
    })
    const f = graphOf(await surveyPsa(KC, OPTS)).findings[0]!

    expect(f.severity).toBe('medium')
    expect(f.confirmed).toBe(false)
    expect(f.observedTraits).toEqual([])
  })

  it('prefers a confirming pod as the example entry point over a benign replica', async () => {
    setup({
      pods: [pod('benign', 'default'), dangerousPod('priv', 'default', { privileged: true })],
      namespaces: [namespace('default')],
    })
    const graph = graphOf(await surveyPsa(KC, OPTS))

    // Both pods collapse into one namespace finding; the example pod is the smoking gun.
    expect(graph.findings).toHaveLength(1)
    const f = graph.findings[0]!
    expect(f.examplePod).toBe('priv')
    expect(f.podCount).toBe(2)
    expect(f.severity).toBe('critical')
  })

  it('ranks a confirmed-critical namespace ahead of a permissive-high namespace', async () => {
    setup({
      pods: [pod('benign', 'ns-a'), dangerousPod('priv', 'ns-b', { privileged: true })],
      namespaces: [namespace('ns-a'), namespace('ns-b')],
    })
    const findings = graphOf(await surveyPsa(KC, OPTS)).findings

    expect(findings[0]!.severity).toBe('critical')
    expect(findings[0]!.namespace).toBe('ns-b')
    expect(findings[1]!.severity).toBe('high')
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
