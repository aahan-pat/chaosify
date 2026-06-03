import { describe, it, expect, vi } from 'vitest'
import * as k8s from '@kubernetes/client-node'
import { surveyWebhooks } from '../../../../src/core/recon/webhooks.js'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeKc(
  listValidating: ReturnType<typeof vi.fn> = vi.fn().mockResolvedValue({ items: [] }),
  listMutating: ReturnType<typeof vi.fn> = vi.fn().mockResolvedValue({ items: [] }),
): k8s.KubeConfig {
  return {
    makeApiClient: vi.fn().mockReturnValue({ listValidatingWebhookConfiguration: listValidating, listMutatingWebhookConfiguration: listMutating }),
  } as unknown as k8s.KubeConfig
}

// k8s errors use top-level statusCode — not response.statusCode or code.
function forbiddenErr(): Error {
  return Object.assign(new Error('Forbidden'), { statusCode: 403 })
}

function validatingConfig(webhooks: Partial<k8s.V1ValidatingWebhook>[]): k8s.V1ValidatingWebhookConfiguration {
  return {
    metadata: { name: 'test-config' },
    webhooks: webhooks.map(wh => ({
      name: wh.name ?? 'wh.example.com',
      admissionReviewVersions: ['v1'],
      clientConfig: {},
      sideEffects: 'None',
      failurePolicy: wh.failurePolicy ?? 'Fail',
      ...wh,
    })),
  }
}

function mutatingConfig(webhooks: Partial<k8s.V1MutatingWebhook>[]): k8s.V1MutatingWebhookConfiguration {
  return {
    metadata: { name: 'mutating-config' },
    webhooks: webhooks.map(wh => ({
      name: wh.name ?? 'mutating.example.com',
      admissionReviewVersions: ['v1'],
      clientConfig: {},
      sideEffects: 'None',
      failurePolicy: wh.failurePolicy ?? 'Fail',
      ...wh,
    })),
  }
}

const OPTS = { namespace: 'chaosclaw' }

// ---------------------------------------------------------------------------
// no webhooks
// ---------------------------------------------------------------------------

describe('surveyWebhooks — no webhooks', () => {
  it('returns a HIGH finding when no admission webhooks exist at all', async () => {
    const result = await surveyWebhooks(makeKc(), OPTS)
    expect(result.status).toBe('ok')
    const high = result.findings.filter(f => f.severity === 'HIGH')
    expect(high).toHaveLength(1)
    expect(high[0]?.title).toMatch(/no admission webhooks/i)
  })

  it('returns HIGH even when the configs exist but have no webhooks inside them', async () => {
    // A WebhookConfiguration object with an empty webhooks array contributes nothing.
    const kc = makeKc(
      vi.fn().mockResolvedValue({ items: [{ metadata: { name: 'empty-config' }, webhooks: [] }] }),
    )
    const result = await surveyWebhooks(kc, OPTS)
    expect(result.findings.filter(f => f.severity === 'HIGH')[0]?.title).toMatch(/no admission webhooks/i)
  })
})

// ---------------------------------------------------------------------------
// fail-open webhooks
// ---------------------------------------------------------------------------

describe('surveyWebhooks — fail-open webhooks', () => {
  it('emits a HIGH per webhook with failurePolicy: Ignore', async () => {
    const kc = makeKc(
      vi.fn().mockResolvedValue({
        items: [validatingConfig([
          { name: 'policy.example.com', failurePolicy: 'Ignore' },
          { name: 'strict.example.com', failurePolicy: 'Fail' },
        ])],
      }),
    )
    const result = await surveyWebhooks(kc, OPTS)
    const high = result.findings.filter(f => f.severity === 'HIGH')
    expect(high).toHaveLength(1)
    expect(high[0]?.title).toContain('policy.example.com')
  })

  it('emits one HIGH per fail-open webhook across both validating and mutating', async () => {
    const kc = makeKc(
      vi.fn().mockResolvedValue({ items: [validatingConfig([{ name: 'v.example.com', failurePolicy: 'Ignore' }])] }),
      vi.fn().mockResolvedValue({ items: [mutatingConfig([{ name: 'm.example.com', failurePolicy: 'Ignore' }])] }),
    )
    const result = await surveyWebhooks(kc, OPTS)
    expect(result.findings.filter(f => f.severity === 'HIGH')).toHaveLength(2)
  })

  it('treats a missing failurePolicy as Fail — the k8s API default', async () => {
    // A webhook with no failurePolicy set defaults to Fail, which is fail-closed.
    const kc = makeKc(
      vi.fn().mockResolvedValue({
        items: [{ metadata: { name: 'cfg' }, webhooks: [{ name: 'wh.example.com', admissionReviewVersions: ['v1'], clientConfig: {}, sideEffects: 'None' }] }],
      }),
    )
    const result = await surveyWebhooks(kc, OPTS)
    // No HIGH for fail-open; one INFO for all-fail-closed.
    expect(result.findings.filter(f => f.severity === 'HIGH')).toHaveLength(0)
    expect(result.findings.filter(f => f.severity === 'INFO')).toHaveLength(1)
  })
})

// ---------------------------------------------------------------------------
// all fail-closed
// ---------------------------------------------------------------------------

describe('surveyWebhooks — all fail-closed', () => {
  it('returns an INFO finding when all webhooks use failurePolicy: Fail', async () => {
    const kc = makeKc(
      vi.fn().mockResolvedValue({
        items: [validatingConfig([{ name: 'strict.example.com', failurePolicy: 'Fail' }])],
      }),
    )
    const result = await surveyWebhooks(kc, OPTS)
    const info = result.findings.filter(f => f.severity === 'INFO')
    expect(info).toHaveLength(1)
    expect(info[0]?.title).toMatch(/failurePolicy: Fail/i)
  })

  it('emits INFO even with a mix of validating and mutating webhooks — as long as all are fail-closed', async () => {
    const kc = makeKc(
      vi.fn().mockResolvedValue({ items: [validatingConfig([{ name: 'v.example.com', failurePolicy: 'Fail' }])] }),
      vi.fn().mockResolvedValue({ items: [mutatingConfig([{ name: 'm.example.com', failurePolicy: 'Fail' }])] }),
    )
    const result = await surveyWebhooks(kc, OPTS)
    expect(result.findings.filter(f => f.severity === 'INFO')).toHaveLength(1)
    expect(result.findings.filter(f => f.severity === 'HIGH')).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// 403 skip
// ---------------------------------------------------------------------------

describe('surveyWebhooks — 403 handling', () => {
  it('returns skip with a SKIP finding when the API returns 403', async () => {
    // surveyWebhooks uses Promise.all — if either call fails the whole fn rejects.
    const kc = makeKc(
      vi.fn().mockRejectedValue(forbiddenErr()),
      vi.fn().mockRejectedValue(forbiddenErr()),
    )
    const result = await surveyWebhooks(kc, OPTS)
    expect(result.status).toBe('skip')
    expect(result.findings[0]?.severity).toBe('SKIP')
    expect(result.findings[0]?.missingPermission).toBeDefined()
  })

  it('returns skip when only the validating call fails with 403 (Promise.all rejects)', async () => {
    const kc = makeKc(
      vi.fn().mockRejectedValue(forbiddenErr()),
      vi.fn().mockResolvedValue({ items: [] }),
    )
    const result = await surveyWebhooks(kc, OPTS)
    expect(result.status).toBe('skip')
  })

  it('returns error (not skip) for non-403 HTTP failures', async () => {
    const serverErr = Object.assign(new Error('Internal Server Error'), { statusCode: 500 })
    const kc = makeKc(vi.fn().mockRejectedValue(serverErr))
    const result = await surveyWebhooks(kc, OPTS)
    expect(result.status).toBe('error')
  })

  it('does NOT treat { code: 403 } as a permission error — only { statusCode: 403 } is recognised', async () => {
    const wrongShape = Object.assign(new Error('Forbidden'), { code: 403 })
    const kc = makeKc(vi.fn().mockRejectedValue(wrongShape))
    const result = await surveyWebhooks(kc, OPTS)
    expect(result.status).toBe('error')
  })
})

// ---------------------------------------------------------------------------
// result data
// ---------------------------------------------------------------------------

describe('surveyWebhooks — result data', () => {
  it('includes all webhook entries in result.data', async () => {
    const kc = makeKc(
      vi.fn().mockResolvedValue({
        items: [validatingConfig([{ name: 'wh1.example.com' }, { name: 'wh2.example.com' }])],
      }),
    )
    const result = await surveyWebhooks(kc, OPTS)
    const data = result.data as { webhooks: unknown[] }
    expect(data.webhooks).toHaveLength(2)
  })

  it('includes mutating webhooks in the webhook list', async () => {
    const kc = makeKc(
      vi.fn().mockResolvedValue({ items: [] }),
      vi.fn().mockResolvedValue({ items: [mutatingConfig([{ name: 'inject.example.com' }])] }),
    )
    const result = await surveyWebhooks(kc, OPTS)
    const data = result.data as { webhooks: Array<{ type: string; name: string }> }
    expect(data.webhooks).toHaveLength(1)
    expect(data.webhooks[0]?.type).toBe('mutating')
  })
})
