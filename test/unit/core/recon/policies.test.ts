import { describe, it, expect, vi } from 'vitest'
import * as k8s from '@kubernetes/client-node'
import { surveyPolicies } from '../../../../src/core/recon/policies.js'
import type { PolicyThreatGraph } from '../../../../src/types/recon.js'

// ---------------------------------------------------------------------------
// surveyPolicies probes Kyverno (kyverno.io/clusterpolicies) first, then Gatekeeper
// (constraints.gatekeeper.sh/constrainttemplates) only if Kyverno is absent. Both go
// through kc.makeApiClient(CustomObjectsApi).listClusterCustomObject. We mock that one call.
// ---------------------------------------------------------------------------

function notFoundErr(): Error {
  return Object.assign(new Error('Not Found'), { statusCode: 404 })
}
function forbiddenErr(): Error {
  return Object.assign(new Error('Forbidden'), { statusCode: 403 })
}

// Drives listClusterCustomObject by api group: kyverno.io vs constraints.gatekeeper.sh.
function makeKc(handlers: { kyverno?: () => unknown; gatekeeper?: () => unknown }): k8s.KubeConfig {
  const listClusterCustomObject = vi.fn(async (params: { group: string }) => {
    const h = params.group === 'kyverno.io' ? handlers.kyverno : handlers.gatekeeper
    if (!h) throw notFoundErr()
    return h()
  })
  return { makeApiClient: vi.fn().mockReturnValue({ listClusterCustomObject }) } as unknown as k8s.KubeConfig
}

function kyvernoPolicy(name: string, action?: string) {
  return { metadata: { name }, spec: action ? { validationFailureAction: action } : {} }
}

const OPTS = { namespace: 'chaosify' }

function graphOf(result: Awaited<ReturnType<typeof surveyPolicies>>): PolicyThreatGraph {
  return result.data as PolicyThreatGraph
}

// ---------------------------------------------------------------------------
// no engine
// ---------------------------------------------------------------------------

describe('surveyPolicies — no engine', () => {
  it('emits a CRITICAL finding and engine=none when neither engine is installed', async () => {
    const result = await surveyPolicies(makeKc({}), OPTS)
    expect(result.status).toBe('ok')
    expect(graphOf(result).engine).toBe('none')
    expect(result.findings.filter(f => f.severity === 'CRITICAL')).toHaveLength(1)
    expect(result.findings[0]!.title).toMatch(/no policy engine/i)
  })
})

// ---------------------------------------------------------------------------
// audit-mode bypass paths
// ---------------------------------------------------------------------------

describe('surveyPolicies — audit-mode bypass', () => {
  it('scores each Audit-mode Kyverno policy as a high-severity admission_bypass', async () => {
    const kc = makeKc({
      kyverno: () => ({ items: [kyvernoPolicy('require-non-root', 'Audit'), kyvernoPolicy('disallow-privileged', 'Enforce')] }),
    })
    const graph = graphOf(await surveyPolicies(kc, OPTS))

    expect(graph.engine).toBe('kyverno')
    expect(graph.policiesScanned).toBe(2)
    expect(graph.findings).toHaveLength(1)
    expect(graph.findings[0]!.policy).toBe('require-non-root')
    expect(graph.findings[0]!.severity).toBe('high')
    expect(graph.findings[0]!.exploitClasses).toEqual(['admission_bypass'])
  })

  it('emits a positive INFO when all policies are in Enforce mode', async () => {
    const kc = makeKc({ kyverno: () => ({ items: [kyvernoPolicy('disallow-privileged', 'Enforce')] }) })
    const result = await surveyPolicies(kc, OPTS)
    expect(graphOf(result).findings).toHaveLength(0)
    expect(result.findings.filter(f => f.severity === 'INFO')).toHaveLength(1)
    expect(result.findings[0]!.title).toMatch(/enforce mode/i)
  })
})

// ---------------------------------------------------------------------------
// gatekeeper fallback
// ---------------------------------------------------------------------------

describe('surveyPolicies — gatekeeper', () => {
  it('falls back to Gatekeeper when Kyverno is absent', async () => {
    const kc = makeKc({ gatekeeper: () => ({ items: [{ metadata: { name: 'k8srequiredlabels' } }] }) })
    const graph = graphOf(await surveyPolicies(kc, OPTS))
    expect(graph.engine).toBe('gatekeeper')
    expect(graph.policiesScanned).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// permission denial → skip
// ---------------------------------------------------------------------------

describe('surveyPolicies — permission denial', () => {
  it('returns skip with a SKIP finding when the engine is installed but unreadable', async () => {
    const kc = makeKc({ kyverno: () => { throw forbiddenErr() } })
    const result = await surveyPolicies(kc, OPTS)
    expect(result.status).toBe('skip')
    expect(result.findings.some(f => f.severity === 'SKIP')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// blind spots
// ---------------------------------------------------------------------------

describe('surveyPolicies — blind spots', () => {
  it('always reports rule-scope, background-scan, and overlap blind spots', async () => {
    const graph = graphOf(await surveyPolicies(makeKc({}), OPTS))
    expect(graph.blindSpots.some(b => /scope|matches/i.test(b))).toBe(true)
    expect(graph.blindSpots.some(b => /background scan/i.test(b))).toBe(true)
    expect(graph.blindSpots.some(b => /psa|webhooks/i.test(b))).toBe(true)
  })
})
