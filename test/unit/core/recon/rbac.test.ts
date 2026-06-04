import { describe, it, expect, vi } from 'vitest'
import * as k8s from '@kubernetes/client-node'
import { surveyRbac } from '../../../../src/core/recon/rbac.js'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Build a mock KubeConfig whose RbacAuthorizationV1Api methods are controllable.
function makeKc(
  listClusterRole: ReturnType<typeof vi.fn> = vi.fn().mockResolvedValue({ items: [] }),
  listClusterRoleBinding: ReturnType<typeof vi.fn> = vi.fn().mockResolvedValue({ items: [] }),
): k8s.KubeConfig {
  return {
    makeApiClient: vi.fn().mockReturnValue({ listClusterRole, listClusterRoleBinding }),
  } as unknown as k8s.KubeConfig
}

// k8s errors use top-level statusCode — not response.statusCode or code.
function forbiddenErr(): Error {
  return Object.assign(new Error('Forbidden'), { statusCode: 403 })
}

function makeAdminBinding(name: string, subjects: k8s.V1Subject[]): k8s.V1ClusterRoleBinding {
  return {
    metadata: { name },
    roleRef: { apiGroup: 'rbac.authorization.k8s.io', kind: 'ClusterRole', name: 'cluster-admin' },
    subjects,
  }
}

function makeRole(name: string, rules: k8s.V1PolicyRule[]): k8s.V1ClusterRole {
  return { metadata: { name }, rules }
}

// A ClusterRole granting broad (no resourceNames) secret read access.
function secretReadRole(name: string): k8s.V1ClusterRole {
  return makeRole(name, [{ apiGroups: [''], resources: ['secrets'], verbs: ['get', 'list', 'watch'] }])
}

// A ClusterRole whose secret access is scoped to specific resource names.
function scopedSecretReadRole(name: string): k8s.V1ClusterRole {
  return makeRole(name, [{ apiGroups: [''], resources: ['secrets'], verbs: ['get'], resourceNames: ['specific-secret'] }])
}

// A ClusterRole using wildcard resources that still covers secret read.
function wildcardResourceRole(name: string): k8s.V1ClusterRole {
  return makeRole(name, [{ apiGroups: [''], resources: ['*'], verbs: ['get', 'list'] }])
}

// A ClusterRole using wildcard verbs that still covers secret read.
function wildcardVerbRole(name: string): k8s.V1ClusterRole {
  return makeRole(name, [{ apiGroups: [''], resources: ['secrets'], verbs: ['*'] }])
}

function bindingFor(roleName: string, subjects: k8s.V1Subject[]): k8s.V1ClusterRoleBinding {
  return {
    metadata: { name: `${roleName}-binding` },
    roleRef: { apiGroup: 'rbac.authorization.k8s.io', kind: 'ClusterRole', name: roleName },
    subjects,
  }
}

function saPrincipal(name: string, namespace: string): k8s.V1Subject {
  return { kind: 'ServiceAccount', name, namespace, apiGroup: '' }
}

const OPTS = { namespace: 'chaosify' }

// ---------------------------------------------------------------------------
// cluster-admin bindings
// ---------------------------------------------------------------------------

describe('surveyRbac — cluster-admin bindings', () => {
  it('emits a WARN finding for a non-system cluster-admin binding', async () => {
    const kc = makeKc(
      vi.fn().mockResolvedValue({ items: [] }),
      vi.fn().mockResolvedValue({
        items: [makeAdminBinding('dev-admin', [{ kind: 'User', name: 'developer@example.com', apiGroup: '' }])],
      }),
    )
    const result = await surveyRbac(kc, OPTS)
    const warn = result.findings.filter(f => f.severity === 'WARN')
    expect(warn).toHaveLength(1)
    expect(warn[0]?.title).toMatch(/cluster-admin/i)
    expect(warn[0]?.detail).toContain('developer@example.com')
  })

  it('omits system-namespace subjects when includeSystem is false', async () => {
    const kc = makeKc(
      vi.fn().mockResolvedValue({ items: [] }),
      vi.fn().mockResolvedValue({
        items: [makeAdminBinding('system-binding', [{ kind: 'ServiceAccount', name: 'default', namespace: 'kube-system', apiGroup: '' }])],
      }),
    )
    const result = await surveyRbac(kc, { ...OPTS, includeSystem: false })
    expect(result.findings.filter(f => f.severity === 'WARN')).toHaveLength(0)
  })

  it('includes system-namespace subjects when includeSystem is true', async () => {
    const kc = makeKc(
      vi.fn().mockResolvedValue({ items: [] }),
      vi.fn().mockResolvedValue({
        items: [makeAdminBinding('system-binding', [{ kind: 'ServiceAccount', name: 'default', namespace: 'kube-system', apiGroup: '' }])],
      }),
    )
    const result = await surveyRbac(kc, { ...OPTS, includeSystem: true })
    expect(result.findings.filter(f => f.severity === 'WARN')).toHaveLength(1)
  })

  it('skips the built-in cluster-admin binding by name', async () => {
    // The binding Kubernetes ships with is named "cluster-admin" and must be excluded.
    const kc = makeKc(
      vi.fn().mockResolvedValue({ items: [] }),
      vi.fn().mockResolvedValue({
        items: [makeAdminBinding('cluster-admin', [{ kind: 'Group', name: 'system:masters', apiGroup: '' }])],
      }),
    )
    const result = await surveyRbac(kc, OPTS)
    expect(result.findings.filter(f => f.severity === 'WARN')).toHaveLength(0)
  })

  it('emits one WARN per binding, not per subject', async () => {
    const kc = makeKc(
      vi.fn().mockResolvedValue({ items: [] }),
      vi.fn().mockResolvedValue({
        items: [
          makeAdminBinding('binding-a', [
            { kind: 'User', name: 'alice@example.com', apiGroup: '' },
            { kind: 'User', name: 'bob@example.com', apiGroup: '' },
          ]),
        ],
      }),
    )
    const result = await surveyRbac(kc, OPTS)
    // Both subjects appear in a single finding's detail, not as two separate findings.
    expect(result.findings.filter(f => f.severity === 'WARN')).toHaveLength(1)
    expect(result.findings[0]?.detail).toContain('alice@example.com')
    expect(result.findings[0]?.detail).toContain('bob@example.com')
  })

  it('emits no WARN when a binding has no subjects', async () => {
    const kc = makeKc(
      vi.fn().mockResolvedValue({ items: [] }),
      vi.fn().mockResolvedValue({
        items: [makeAdminBinding('empty-binding', [])],
      }),
    )
    const result = await surveyRbac(kc, OPTS)
    expect(result.findings.filter(f => f.severity === 'WARN')).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// cluster-wide secret read access
// ---------------------------------------------------------------------------

describe('surveyRbac — cluster-wide secret read', () => {
  it('emits a HIGH finding when a ServiceAccount has broad secret read via a ClusterRole', async () => {
    const role = secretReadRole('secret-reader')
    const binding = bindingFor('secret-reader', [saPrincipal('app-sa', 'production')])
    const kc = makeKc(
      vi.fn().mockResolvedValue({ items: [role] }),
      vi.fn().mockResolvedValue({ items: [binding] }),
    )
    const result = await surveyRbac(kc, OPTS)
    const high = result.findings.filter(f => f.severity === 'HIGH')
    expect(high).toHaveLength(1)
    expect(high[0]?.title).toContain('app-sa')
    expect(high[0]?.title).toContain('production')
  })

  it('does not emit HIGH when secret access is scoped to specific resourceNames', async () => {
    const role = scopedSecretReadRole('scoped-reader')
    const binding = bindingFor('scoped-reader', [saPrincipal('app-sa', 'production')])
    const kc = makeKc(
      vi.fn().mockResolvedValue({ items: [role] }),
      vi.fn().mockResolvedValue({ items: [binding] }),
    )
    const result = await surveyRbac(kc, OPTS)
    expect(result.findings.filter(f => f.severity === 'HIGH')).toHaveLength(0)
  })

  it('emits HIGH when the role uses wildcard resources covering secrets', async () => {
    const role = wildcardResourceRole('wildcard-reader')
    const binding = bindingFor('wildcard-reader', [saPrincipal('bad-sa', 'default')])
    const kc = makeKc(
      vi.fn().mockResolvedValue({ items: [role] }),
      vi.fn().mockResolvedValue({ items: [binding] }),
    )
    const result = await surveyRbac(kc, OPTS)
    expect(result.findings.filter(f => f.severity === 'HIGH')).toHaveLength(1)
  })

  it('emits HIGH when the role uses wildcard verbs on secrets', async () => {
    const role = wildcardVerbRole('wildcard-verb-reader')
    const binding = bindingFor('wildcard-verb-reader', [saPrincipal('bad-sa', 'default')])
    const kc = makeKc(
      vi.fn().mockResolvedValue({ items: [role] }),
      vi.fn().mockResolvedValue({ items: [binding] }),
    )
    const result = await surveyRbac(kc, OPTS)
    expect(result.findings.filter(f => f.severity === 'HIGH')).toHaveLength(1)
  })

  it('emits one HIGH per service account, not per binding', async () => {
    const role = secretReadRole('reader')
    const binding = bindingFor('reader', [saPrincipal('sa1', 'ns-a'), saPrincipal('sa2', 'ns-b')])
    const kc = makeKc(
      vi.fn().mockResolvedValue({ items: [role] }),
      vi.fn().mockResolvedValue({ items: [binding] }),
    )
    const result = await surveyRbac(kc, OPTS)
    expect(result.findings.filter(f => f.severity === 'HIGH')).toHaveLength(2)
  })

  it('does not emit HIGH for system SAs when includeSystem is false', async () => {
    const role = secretReadRole('reader')
    const binding = bindingFor('reader', [saPrincipal('controller', 'kube-system')])
    const kc = makeKc(
      vi.fn().mockResolvedValue({ items: [role] }),
      vi.fn().mockResolvedValue({ items: [binding] }),
    )
    const result = await surveyRbac(kc, { ...OPTS, includeSystem: false })
    expect(result.findings.filter(f => f.severity === 'HIGH')).toHaveLength(0)
  })

  it('emits no HIGH for User/Group subjects — only ServiceAccounts are tracked', async () => {
    const role = secretReadRole('reader')
    const binding = bindingFor('reader', [{ kind: 'User', name: 'admin@example.com', apiGroup: '' }])
    const kc = makeKc(
      vi.fn().mockResolvedValue({ items: [role] }),
      vi.fn().mockResolvedValue({ items: [binding] }),
    )
    const result = await surveyRbac(kc, OPTS)
    expect(result.findings.filter(f => f.severity === 'HIGH')).toHaveLength(0)
  })

  it('skips secret-read analysis when the referenced role is not in the role list', async () => {
    // Binding references "missing-role" which does not exist in the role list.
    const binding = bindingFor('missing-role', [saPrincipal('app-sa', 'production')])
    const kc = makeKc(
      vi.fn().mockResolvedValue({ items: [] }),
      vi.fn().mockResolvedValue({ items: [binding] }),
    )
    const result = await surveyRbac(kc, OPTS)
    expect(result.findings.filter(f => f.severity === 'HIGH')).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// 403 partial and full skips
// ---------------------------------------------------------------------------

describe('surveyRbac — 403 handling', () => {
  it('returns skip status when both calls fail with 403', async () => {
    const kc = makeKc(
      vi.fn().mockRejectedValue(forbiddenErr()),
      vi.fn().mockRejectedValue(forbiddenErr()),
    )
    const result = await surveyRbac(kc, OPTS)
    expect(result.status).toBe('skip')
    expect(result.findings.every(f => f.severity === 'SKIP')).toBe(true)
  })

  it('returns ok when bindings produce analysis findings even if roles return 403', async () => {
    // A cluster-admin binding from a non-system user still produces a WARN finding.
    const kc = makeKc(
      vi.fn().mockRejectedValue(forbiddenErr()),
      vi.fn().mockResolvedValue({
        items: [makeAdminBinding('dev-admin', [{ kind: 'User', name: 'dev@example.com', apiGroup: '' }])],
      }),
    )
    const result = await surveyRbac(kc, OPTS)
    expect(result.status).toBe('ok')
    expect(result.findings.some(f => f.severity === 'WARN')).toBe(true)
    // A SKIP finding for roles is still included alongside the analysis findings.
    expect(result.findings.some(f => f.severity === 'SKIP')).toBe(true)
  })

  it('does NOT treat { code: 403 } as a permission error — only { statusCode: 403 } is recognised', async () => {
    // Wrong error shape: the guard checks err.statusCode, not err.code.
    const wrongShape = Object.assign(new Error('Forbidden'), { code: 403 })
    const kc = makeKc(
      vi.fn().mockRejectedValue(wrongShape),
      vi.fn().mockResolvedValue({ items: [] }),
    )
    // isForbidden({ code: 403 }) === false, so the error is swallowed silently.
    const result = await surveyRbac(kc, OPTS)
    expect(result.findings.filter(f => f.severity === 'SKIP')).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// result data
// ---------------------------------------------------------------------------

describe('surveyRbac — result data', () => {
  it('reports role and binding counts in result.data', async () => {
    const kc = makeKc(
      vi.fn().mockResolvedValue({ items: [secretReadRole('r1'), secretReadRole('r2')] }),
      vi.fn().mockResolvedValue({ items: [] }),
    )
    const result = await surveyRbac(kc, OPTS)
    const data = result.data as { clusterRoleCount: number; clusterRoleBindingCount: number }
    expect(data.clusterRoleCount).toBe(2)
    expect(data.clusterRoleBindingCount).toBe(0)
  })

  it('reports partial: true when at least one list call was skipped', async () => {
    const kc = makeKc(
      vi.fn().mockRejectedValue(forbiddenErr()),
      vi.fn().mockResolvedValue({ items: [] }),
    )
    const result = await surveyRbac(kc, OPTS)
    const data = result.data as { partial: boolean }
    expect(data.partial).toBe(true)
  })
})
