import { describe, it, expect, vi, beforeEach } from 'vitest'
import type * as k8s from '@kubernetes/client-node'

// ---------------------------------------------------------------------------
// Module mocks — surveyRbac is pod-first: it lists pods, execs to harvest each
// mounted SA token, then fingerprints permissions via SelfSubjectRulesReview.
// We mock the kube client factories and execInPod to drive those three steps.
// ---------------------------------------------------------------------------

vi.mock('../../../../src/core/kube/client.js', () => ({
  coreV1Api: vi.fn(),
  authorizationV1Api: vi.fn(),
  // Returns a token-tagged sentinel so the authorization mock can resolve rules per identity.
  kubeConfigWithToken: vi.fn((_base: unknown, token: string) => ({ token })),
}))

vi.mock('../../../../src/core/kube/pod.js', () => ({
  execInPod: vi.fn(),
}))

import { surveyRbac } from '../../../../src/core/recon/rbac.js'
import { coreV1Api, authorizationV1Api } from '../../../../src/core/kube/client.js'
import { execInPod } from '../../../../src/core/kube/pod.js'
import type { RbacThreatGraph } from '../../../../src/types/recon.js'

const coreMock = coreV1Api as ReturnType<typeof vi.fn>
const authzMock = authorizationV1Api as ReturnType<typeof vi.fn>
const execMock = execInPod as ReturnType<typeof vi.fn>

const OPTS = { namespace: 'chaosify' }
const KC = {} as k8s.KubeConfig

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

function pod(name: string, namespace: string, opts: {
  sa?: string
  automount?: boolean
  phase?: string
  container?: string
} = {}): k8s.V1Pod {
  return {
    metadata: { name, namespace },
    spec: {
      serviceAccountName: opts.sa ?? 'default',
      automountServiceAccountToken: opts.automount,
      containers: [{ name: opts.container ?? 'main' }],
    },
    status: { phase: opts.phase ?? 'Running' },
  } as k8s.V1Pod
}

function rule(resources: string[], verbs: string[]): k8s.V1ResourceRule {
  return { apiGroups: [''], resources, verbs }
}

function forbiddenErr(): Error {
  return Object.assign(new Error('Forbidden'), { statusCode: 403 })
}

// Configure the mocked client/exec layer for a single run.
function setup(opts: {
  pods?: k8s.V1Pod[]
  listError?: unknown
  // Rules returned by SelfSubjectRulesReview, keyed by harvested token (default key 'TOKEN').
  rulesByToken?: Record<string, k8s.V1ResourceRule[]>
  // Override execInPod behaviour per call; defaults to a successful harvest of 'TOKEN'.
  exec?: ReturnType<typeof vi.fn>
}) {
  const listPodForAllNamespaces = opts.listError
    ? vi.fn().mockRejectedValue(opts.listError)
    : vi.fn().mockResolvedValue({ items: opts.pods ?? [] })
  coreMock.mockReturnValue({ listPodForAllNamespaces })

  execMock.mockImplementation(opts.exec ?? (() => Promise.resolve({ stdout: 'TOKEN', stderr: '', exitCode: 0 })))

  const rulesByToken = opts.rulesByToken ?? {}
  authzMock.mockImplementation((kc: { token: string }) => ({
    createSelfSubjectRulesReview: vi.fn().mockResolvedValue({
      status: { resourceRules: rulesByToken[kc.token] ?? [], nonResourceRules: [], incomplete: false },
    }),
  }))

  return { listPodForAllNamespaces }
}

function graphOf(result: Awaited<ReturnType<typeof surveyRbac>>): RbacThreatGraph {
  return result.data as RbacThreatGraph
}

beforeEach(() => {
  coreMock.mockReset()
  authzMock.mockReset()
  execMock.mockReset()
})

// ---------------------------------------------------------------------------
// Permission unreachable → skip
// ---------------------------------------------------------------------------

describe('surveyRbac — preflight', () => {
  it('returns skip status when listing pods is forbidden', async () => {
    setup({ listError: forbiddenErr() })
    const result = await surveyRbac(KC, OPTS)
    expect(result.status).toBe('skip')
    expect(result.findings[0]?.severity).toBe('SKIP')
  })

  it('returns error status when pod listing throws a non-403 error', async () => {
    setup({ listError: new Error('connection refused') })
    const result = await surveyRbac(KC, OPTS)
    expect(result.status).toBe('error')
  })
})

// ---------------------------------------------------------------------------
// Exploit-class detection
// ---------------------------------------------------------------------------

describe('surveyRbac — exploit classes', () => {
  it('flags secret read as a HIGH secret_access finding', async () => {
    setup({
      pods: [pod('app-1', 'default')],
      rulesByToken: { TOKEN: [rule(['secrets'], ['get', 'list'])] },
    })
    const graph = graphOf(await surveyRbac(KC, OPTS))
    expect(graph.findings).toHaveLength(1)
    expect(graph.findings[0]?.exploitClasses).toContain('secret_access')
    expect(graph.findings[0]?.severity).toBe('high')
  })

  it('collapses identical permission blocks into one dangerousPermissions entry', async () => {
    setup({
      pods: [pod('app-1', 'default')],
      // Same effective rule surfaced twice — without dedup it would repeat verbatim.
      rulesByToken: { TOKEN: [rule(['secrets'], ['get', 'list']), rule(['secrets'], ['get', 'list'])] },
    })
    const graph = graphOf(await surveyRbac(KC, OPTS))
    expect(graph.findings[0]?.dangerousPermissions).toHaveLength(1)
  })

  it('flags create clusterrolebindings as a critical privilege_escalation finding', async () => {
    setup({
      pods: [pod('app-1', 'default')],
      rulesByToken: { TOKEN: [{ apiGroups: ['rbac.authorization.k8s.io'], resources: ['clusterrolebindings'], verbs: ['create'] }] },
    })
    const graph = graphOf(await surveyRbac(KC, OPTS))
    expect(graph.findings[0]?.exploitClasses).toContain('privilege_escalation')
    expect(graph.findings[0]?.severity).toBe('critical')
    expect(graph.findings[0]?.attackChain).toMatch(/cluster-admin/)
  })

  it('flags create pods as privilege_escalation (node breakout path)', async () => {
    setup({
      pods: [pod('app-1', 'default')],
      rulesByToken: { TOKEN: [rule(['pods'], ['create'])] },
    })
    const graph = graphOf(await surveyRbac(KC, OPTS))
    expect(graph.findings[0]?.exploitClasses).toContain('privilege_escalation')
  })

  it('flags pods/exec as lateral_movement', async () => {
    setup({
      pods: [pod('app-1', 'default')],
      rulesByToken: { TOKEN: [rule(['pods/exec'], ['create'])] },
    })
    const graph = graphOf(await surveyRbac(KC, OPTS))
    expect(graph.findings[0]?.exploitClasses).toContain('lateral_movement')
  })

  it('treats wildcard verbs and resources as cluster-admin-equivalent', async () => {
    setup({
      pods: [pod('app-1', 'default')],
      rulesByToken: { TOKEN: [{ apiGroups: ['*'], resources: ['*'], verbs: ['*'] }] },
    })
    const graph = graphOf(await surveyRbac(KC, OPTS))
    expect(graph.findings[0]?.severity).toBe('critical')
    expect(graph.findings[0]?.exploitClasses).toEqual(
      expect.arrayContaining(['privilege_escalation', 'secret_access', 'lateral_movement']),
    )
  })

  it('produces no findings (and an INFO summary) when the token holds nothing dangerous', async () => {
    setup({
      pods: [pod('app-1', 'default')],
      rulesByToken: { TOKEN: [rule(['pods'], ['get', 'list'])] },
    })
    const result = await surveyRbac(KC, OPTS)
    const graph = graphOf(result)
    expect(graph.findings).toHaveLength(0)
    expect(result.findings[0]?.severity).toBe('INFO')
    expect(result.findings[0]?.title).toMatch(/no exploitable privilege chains/i)
  })
})

// ---------------------------------------------------------------------------
// Token harvesting and scope
// ---------------------------------------------------------------------------

describe('surveyRbac — harvesting', () => {
  it('skips pods with automount disabled and records a blind spot', async () => {
    setup({ pods: [pod('app-1', 'default', { automount: false })] })
    const graph = graphOf(await surveyRbac(KC, OPTS))
    expect(execMock).not.toHaveBeenCalled()
    expect(graph.tokensHarvested).toBe(0)
    expect(graph.blindSpots.some(b => /automount/i.test(b))).toBe(true)
  })

  it('records a blind spot but does not abort when exec fails on a pod', async () => {
    setup({
      pods: [pod('app-1', 'default'), pod('app-2', 'default', { sa: 'reader' })],
      exec: vi.fn()
        .mockResolvedValueOnce({ stdout: '', stderr: 'no token', exitCode: 1 })
        .mockResolvedValueOnce({ stdout: 'TOKEN', stderr: '', exitCode: 0 }),
      rulesByToken: { TOKEN: [rule(['secrets'], ['get'])] },
    })
    const graph = graphOf(await surveyRbac(KC, OPTS))
    expect(graph.blindSpots.some(b => b.includes('app-1'))).toBe(true)
    expect(graph.findings).toHaveLength(1)
    expect(graph.tokensHarvested).toBe(1)
  })

  it('only considers running pods', async () => {
    setup({ pods: [pod('pending-1', 'default', { phase: 'Pending' })] })
    const graph = graphOf(await surveyRbac(KC, OPTS))
    expect(graph.podsScanned).toBe(0)
    expect(execMock).not.toHaveBeenCalled()
  })

  it('dedupes identities — one finding per (namespace, ServiceAccount)', async () => {
    setup({
      pods: [pod('replica-1', 'default', { sa: 'app' }), pod('replica-2', 'default', { sa: 'app' })],
      rulesByToken: { TOKEN: [rule(['secrets'], ['get'])] },
    })
    const graph = graphOf(await surveyRbac(KC, OPTS))
    expect(execMock).toHaveBeenCalledTimes(1)
    expect(graph.findings).toHaveLength(1)
  })
})

// ---------------------------------------------------------------------------
// System-namespace scoping
// ---------------------------------------------------------------------------

describe('surveyRbac — system namespaces', () => {
  it('excludes system-namespace pods by default', async () => {
    setup({
      pods: [pod('kube-proxy', 'kube-system'), pod('app-1', 'default')],
      rulesByToken: { TOKEN: [rule(['secrets'], ['get'])] },
    })
    const graph = graphOf(await surveyRbac(KC, OPTS))
    expect(graph.podsScanned).toBe(1)
    expect(graph.findings.every(f => f.namespace !== 'kube-system')).toBe(true)
  })

  it('includes system-namespace pods when includeSystem is set', async () => {
    setup({
      pods: [pod('kube-proxy', 'kube-system')],
      rulesByToken: { TOKEN: [rule(['secrets'], ['get'])] },
    })
    const graph = graphOf(await surveyRbac(KC, { ...OPTS, includeSystem: true }))
    expect(graph.podsScanned).toBe(1)
    expect(graph.findings[0]?.namespace).toBe('kube-system')
  })
})

// ---------------------------------------------------------------------------
// Blind spots are always honest about pod-first limits
// ---------------------------------------------------------------------------

describe('surveyRbac — blind spots', () => {
  it('always reports the structural blind spots of pod-first recon', async () => {
    setup({ pods: [] })
    const graph = graphOf(await surveyRbac(KC, OPTS))
    expect(graph.blindSpots.some(b => /not bound to any running pod/i.test(b))).toBe(true)
  })
})
