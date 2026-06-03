import { describe, it, expect } from 'vitest'
import { reconWrapper, SYSTEM_NAMESPACES } from '../../../../src/core/utils/recon.js'
import type { ReconFinding } from '../../../../src/types/recon.js'

// ---------------------------------------------------------------------------
// SYSTEM_NAMESPACES
// ---------------------------------------------------------------------------

describe('SYSTEM_NAMESPACES', () => {
  it('contains the three standard Kubernetes system namespaces', () => {
    expect(SYSTEM_NAMESPACES.has('kube-system')).toBe(true)
    expect(SYSTEM_NAMESPACES.has('kube-public')).toBe(true)
    expect(SYSTEM_NAMESPACES.has('kube-node-lease')).toBe(true)
  })

  it('does not contain application namespaces', () => {
    expect(SYSTEM_NAMESPACES.has('default')).toBe(false)
    expect(SYSTEM_NAMESPACES.has('chaosclaw')).toBe(false)
    expect(SYSTEM_NAMESPACES.has('production')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// reconWrapper — success path
// ---------------------------------------------------------------------------

describe('reconWrapper — success', () => {
  it('returns ok status with findings and data from the fn', async () => {
    const findings: ReconFinding[] = [{ severity: 'HIGH', title: 'Bad actor' }]
    const result = await reconWrapper('rbac', { title: 'skip' }, async () => ({
      findings,
      data: { count: 3 },
    }))
    expect(result.status).toBe('ok')
    expect(result.findings).toEqual(findings)
    expect(result.data).toEqual({ count: 3 })
  })

  it('preserves the tool name in the result', async () => {
    const result = await reconWrapper('webhooks', { title: 'skip' }, async () => ({ findings: [], data: {} }))
    expect(result.tool).toBe('webhooks')
  })

  it('returns empty findings when fn returns an empty array', async () => {
    const result = await reconWrapper('psa', { title: 'skip' }, async () => ({ findings: [], data: {} }))
    expect(result.status).toBe('ok')
    expect(result.findings).toEqual([])
  })
})

// ---------------------------------------------------------------------------
// reconWrapper — 403 skip path
// ---------------------------------------------------------------------------

describe('reconWrapper — 403 skip', () => {
  it('returns skip status when fn throws { statusCode: 403 }', async () => {
    const err = Object.assign(new Error('Forbidden'), { statusCode: 403 })
    const result = await reconWrapper('rbac', { title: 'Recon skipped' }, () => Promise.reject(err))
    expect(result.status).toBe('skip')
  })

  it('injects SKIP severity into the skip finding', async () => {
    const err = Object.assign(new Error(), { statusCode: 403 })
    const result = await reconWrapper('rbac', { title: 'Skipped' }, () => Promise.reject(err))
    expect(result.findings[0]?.severity).toBe('SKIP')
  })

  it('propagates all provided skip fields into the finding', async () => {
    const err = Object.assign(new Error(), { statusCode: 403 })
    const skipFields = {
      title: 'Skipped title',
      detail: 'Why it was skipped',
      missingPermission: 'list clusterroles',
      coverageImpact: 'Cannot enumerate roles',
    }
    const result = await reconWrapper('rbac', skipFields, () => Promise.reject(err))
    const finding = result.findings[0]!
    expect(finding.title).toBe('Skipped title')
    expect(finding.detail).toBe('Why it was skipped')
    expect(finding.missingPermission).toBe('list clusterroles')
    expect(finding.coverageImpact).toBe('Cannot enumerate roles')
  })

  it('returns empty data ({}) on 403', async () => {
    const err = Object.assign(new Error(), { statusCode: 403 })
    const result = await reconWrapper('rbac', { title: 'skip' }, () => Promise.reject(err))
    expect(result.data).toEqual({})
  })

  it('does NOT treat { code: 403 } as forbidden — only { statusCode: 403 } is caught', async () => {
    // The guard checks err.statusCode; using err.code is the wrong shape.
    const wrongShape = Object.assign(new Error('Forbidden'), { code: 403 })
    const result = await reconWrapper('rbac', { title: 'skip' }, () => Promise.reject(wrongShape))
    expect(result.status).toBe('error')
  })

  it('does NOT treat nested response.statusCode as forbidden', async () => {
    // k8s client sometimes throws { response: { statusCode: 403 } }; reconWrapper won't catch it as a skip.
    const nestedErr = Object.assign(new Error('Forbidden'), { response: { statusCode: 403 } })
    const result = await reconWrapper('rbac', { title: 'skip' }, () => Promise.reject(nestedErr))
    expect(result.status).toBe('error')
  })
})

// ---------------------------------------------------------------------------
// reconWrapper — generic error path
// ---------------------------------------------------------------------------

describe('reconWrapper — generic error', () => {
  it('returns error status for a non-403 HTTP error (e.g. 500)', async () => {
    const err = Object.assign(new Error('Internal Server Error'), { statusCode: 500 })
    const result = await reconWrapper('nodes', { title: 'skip' }, () => Promise.reject(err))
    expect(result.status).toBe('error')
  })

  it('returns empty findings for generic errors', async () => {
    const result = await reconWrapper('nodes', { title: 'skip' }, () => Promise.reject(new Error('timeout')))
    expect(result.findings).toEqual([])
  })

  it('captures the error message in result.data.error', async () => {
    const result = await reconWrapper('nodes', { title: 'skip' }, () => Promise.reject(new Error('connection refused')))
    const data = result.data as { error: string }
    expect(data.error).toBe('connection refused')
  })

  it('stringifies non-Error thrown values', async () => {
    // Thrown strings are not Error instances; String() is used to capture the message.
    const result = await reconWrapper('psa', { title: 'skip' }, () => Promise.reject('dial tcp: connection refused'))
    const data = result.data as { error: string }
    expect(data.error).toBe('dial tcp: connection refused')
  })

  it('preserves the tool name in error results', async () => {
    const result = await reconWrapper('runtime-agents', { title: 'skip' }, () => Promise.reject(new Error('x')))
    expect(result.tool).toBe('runtime-agents')
  })
})
