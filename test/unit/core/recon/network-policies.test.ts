import { describe, it, expect, vi, beforeEach } from 'vitest'
import type * as k8s from '@kubernetes/client-node'

// ---------------------------------------------------------------------------
// Module mocks — surveyNetworkPolicies is pod-first: it lists pods and
// NetworkPolicies cluster-wide, then evaluates the egress/ingress coverage that
// actually selects each pod. We mock the two kube client factories to drive it.
// ---------------------------------------------------------------------------

vi.mock('../../../../src/core/kube/client.js', () => ({
  coreV1Api: vi.fn(),
  networkingV1Api: vi.fn(),
}))

import { surveyNetworkPolicies } from '../../../../src/core/recon/network-policies.js'
import { coreV1Api, networkingV1Api } from '../../../../src/core/kube/client.js'
import type { NetpolThreatGraph } from '../../../../src/types/recon.js'

const coreMock = coreV1Api as ReturnType<typeof vi.fn>
const netMock = networkingV1Api as ReturnType<typeof vi.fn>

const OPTS = { namespace: 'chaosify' }
const KC = {} as k8s.KubeConfig

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

function pod(name: string, namespace: string, opts: { labels?: Record<string, string>; phase?: string } = {}): k8s.V1Pod {
  return {
    metadata: { name, namespace, labels: opts.labels ?? {} },
    status: { phase: opts.phase ?? 'Running' },
  } as k8s.V1Pod
}

function policy(namespace: string, opts: {
  selector?: k8s.V1LabelSelector
  types?: string[]
  ingress?: k8s.V1NetworkPolicyIngressRule[]
  egress?: k8s.V1NetworkPolicyEgressRule[]
} = {}): k8s.V1NetworkPolicy {
  return {
    metadata: { namespace, name: 'np' },
    spec: {
      podSelector: opts.selector ?? {},
      policyTypes: opts.types ?? ['Ingress', 'Egress'],
      ingress: opts.ingress,
      egress: opts.egress,
    },
  } as k8s.V1NetworkPolicy
}

function forbiddenErr(): Error {
  return Object.assign(new Error('Forbidden'), { statusCode: 403 })
}

function setup(opts: { pods?: k8s.V1Pod[]; policies?: k8s.V1NetworkPolicy[]; listError?: unknown }) {
  const listPodForAllNamespaces = opts.listError
    ? vi.fn().mockRejectedValue(opts.listError)
    : vi.fn().mockResolvedValue({ items: opts.pods ?? [] })
  const listNetworkPolicyForAllNamespaces = opts.listError
    ? vi.fn().mockRejectedValue(opts.listError)
    : vi.fn().mockResolvedValue({ items: opts.policies ?? [] })
  coreMock.mockReturnValue({ listPodForAllNamespaces })
  netMock.mockReturnValue({ listNetworkPolicyForAllNamespaces })
}

function graphOf(result: Awaited<ReturnType<typeof surveyNetworkPolicies>>): NetpolThreatGraph {
  return result.data as NetpolThreatGraph
}

beforeEach(() => {
  coreMock.mockReset()
  netMock.mockReset()
})

// ---------------------------------------------------------------------------
// Permission unreachable → skip
// ---------------------------------------------------------------------------

describe('surveyNetworkPolicies — permissions', () => {
  it('returns skip on 403', async () => {
    setup({ listError: forbiddenErr() })
    const result = await surveyNetworkPolicies(KC, OPTS)
    expect(result.status).toBe('skip')
  })
})

// ---------------------------------------------------------------------------
// Open paths
// ---------------------------------------------------------------------------

describe('surveyNetworkPolicies — open paths', () => {
  it('flags a pod with no policies as both egress- and ingress-open', async () => {
    setup({ pods: [pod('app', 'default')], policies: [] })
    const graph = graphOf(await surveyNetworkPolicies(KC, OPTS))

    expect(graph.findings).toHaveLength(1)
    const f = graph.findings[0]!
    expect(f.egressOpen).toBe(true)
    expect(f.ingressOpen).toBe(true)
    expect(f.exploitClasses).toEqual(expect.arrayContaining(['metadata_exposure', 'egress_exfiltration', 'lateral_movement']))
    expect(f.severity).toBe('high')
    expect(f.suggestedProbe).toContain('169.254.169.254')
  })

  it('treats an Ingress-only policy as leaving egress open (metadata path)', async () => {
    setup({ pods: [pod('app', 'default')], policies: [policy('default', { types: ['Ingress'] })] })
    const graph = graphOf(await surveyNetworkPolicies(KC, OPTS))

    const f = graph.findings[0]!
    expect(f.egressOpen).toBe(true)
    expect(f.ingressOpen).toBe(false)
    expect(f.exploitClasses).toContain('metadata_exposure')
  })

  it('reports no open paths when a default-deny-all policy (empty rules) covers the pod', async () => {
    setup({ pods: [pod('app', 'default')], policies: [policy('default', { types: ['Ingress', 'Egress'] })] })
    const graph = graphOf(await surveyNetworkPolicies(KC, OPTS))

    expect(graph.findings).toHaveLength(0)
  })

  // Regression: a policy named/typed for both directions but with allow-all rule
  // bodies (`ingress:[{}]`, `egress:[{}]`) is open, not coverage. This is the
  // exact false negative seen on the minikube pentest-lab cluster.
  it('treats an allow-all policy (empty rule bodies) as fully open, not covered', async () => {
    setup({
      pods: [pod('app', 'default')],
      policies: [policy('default', { types: ['Ingress', 'Egress'], ingress: [{}], egress: [{}] })],
    })
    const graph = graphOf(await surveyNetworkPolicies(KC, OPTS))

    expect(graph.findings).toHaveLength(1)
    expect(graph.findings[0]!.egressOpen).toBe(true)
    expect(graph.findings[0]!.ingressOpen).toBe(true)
  })

  it('treats an egress rule permitting 0.0.0.0/0 as egress-open (metadata reachable)', async () => {
    setup({
      pods: [pod('app', 'default')],
      policies: [policy('default', { types: ['Egress'], egress: [{ to: [{ ipBlock: { cidr: '0.0.0.0/0' } }] }] })],
    })
    const graph = graphOf(await surveyNetworkPolicies(KC, OPTS))

    expect(graph.findings[0]!.egressOpen).toBe(true)
    expect(graph.findings[0]!.exploitClasses).toContain('metadata_exposure')
  })

  it('treats an ingress rule from any namespace as ingress-open', async () => {
    setup({
      pods: [pod('app', 'default')],
      policies: [policy('default', { types: ['Ingress'], ingress: [{ _from: [{ namespaceSelector: {} }] }] })],
    })
    const graph = graphOf(await surveyNetworkPolicies(KC, OPTS))

    expect(graph.findings[0]!.ingressOpen).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Selector matching — a policy that does not select the pod is not coverage
// ---------------------------------------------------------------------------

describe('surveyNetworkPolicies — selector matching', () => {
  it('does not count a policy whose matchLabels selector misses the pod', async () => {
    setup({
      pods: [pod('app', 'default', { labels: { app: 'web' } })],
      policies: [policy('default', { selector: { matchLabels: { app: 'db' } } })],
    })
    const graph = graphOf(await surveyNetworkPolicies(KC, OPTS))
    // The egress/Ingress policy targets app=db, so app=web is still fully open.
    expect(graph.findings[0]!.egressOpen).toBe(true)
    expect(graph.findings[0]!.ingressOpen).toBe(true)
  })

  it('counts a policy whose matchLabels selector hits the pod', async () => {
    setup({
      pods: [pod('app', 'default', { labels: { app: 'web' } })],
      policies: [policy('default', { selector: { matchLabels: { app: 'web' } }, types: ['Egress'] })],
    })
    const graph = graphOf(await surveyNetworkPolicies(KC, OPTS))
    // Egress is now covered; only ingress remains open → lateral movement only.
    const f = graph.findings[0]!
    expect(f.egressOpen).toBe(false)
    expect(f.ingressOpen).toBe(true)
    expect(f.exploitClasses).toEqual(['lateral_movement'])
    expect(f.severity).toBe('medium')
  })
})

// ---------------------------------------------------------------------------
// Noise control and honesty
// ---------------------------------------------------------------------------

describe('surveyNetworkPolicies — noise and blind spots', () => {
  it('collapses replicas sharing an exposure profile into one finding', async () => {
    setup({ pods: [pod('app-1', 'default'), pod('app-2', 'default')], policies: [] })
    const graph = graphOf(await surveyNetworkPolicies(KC, OPTS))

    expect(graph.findings).toHaveLength(1)
    expect(graph.findings[0]!.podCount).toBe(2)
  })

  it('excludes system namespaces by default and includes them with includeSystem', async () => {
    setup({ pods: [pod('kproxy', 'kube-system')], policies: [] })

    expect(graphOf(await surveyNetworkPolicies(KC, OPTS)).findings).toHaveLength(0)
    expect(graphOf(await surveyNetworkPolicies(KC, { ...OPTS, includeSystem: true })).findings).toHaveLength(1)
  })

  it('always reports CNI-enforcement and hostNetwork blind spots', async () => {
    setup({ pods: [], policies: [] })
    const graph = graphOf(await surveyNetworkPolicies(KC, OPTS))

    expect(graph.blindSpots.some(b => /CNI/i.test(b))).toBe(true)
    expect(graph.blindSpots.some(b => /hostNetwork/i.test(b))).toBe(true)
  })
})
