import { describe, it, expect } from 'vitest'
import { injectNamespace, resolveFirstContainer } from '../../../../src/core/scenarios/exec/pod-runner.js'

// ---------------------------------------------------------------------------
// injectNamespace
// ---------------------------------------------------------------------------

describe('injectNamespace', () => {
  it('sets namespace on the metadata', () => {
    const result = injectNamespace({ kind: 'Pod', metadata: { name: 'test' } }, 'chaosclaw-test')
    const meta = result['metadata'] as Record<string, unknown>
    expect(meta['namespace']).toBe('chaosclaw-test')
  })

  it('sets generateName to chaosclaw-test-', () => {
    const result = injectNamespace({ kind: 'Pod', metadata: {} }, 'chaosclaw-test')
    const meta = result['metadata'] as Record<string, unknown>
    expect(meta['generateName']).toBe('chaosclaw-test-')
  })

  it('clears the name so generateName takes control of naming', () => {
    const result = injectNamespace({ kind: 'Pod', metadata: { name: 'my-pod' } }, 'chaosclaw-test')
    const meta = result['metadata'] as Record<string, unknown>
    expect(meta['name']).toBeUndefined()
  })

  it('creates a metadata object when the manifest has none', () => {
    const result = injectNamespace({ kind: 'Pod', apiVersion: 'v1' }, 'chaosclaw-test')
    const meta = result['metadata'] as Record<string, unknown>
    expect(meta['namespace']).toBe('chaosclaw-test')
  })

  it('preserves other metadata fields alongside the injected ones', () => {
    const result = injectNamespace(
      { kind: 'Pod', metadata: { labels: { app: 'test' }, annotations: { 'note': 'yes' } } },
      'chaosclaw-test',
    )
    const meta = result['metadata'] as Record<string, unknown>
    expect(meta['labels']).toEqual({ app: 'test' })
    expect(meta['annotations']).toEqual({ note: 'yes' })
  })

  it('preserves other top-level manifest fields', () => {
    const result = injectNamespace({ kind: 'Pod', apiVersion: 'v1', spec: { containers: [] } }, 'ns')
    expect(result['kind']).toBe('Pod')
    expect(result['apiVersion']).toBe('v1')
    expect(result['spec']).toEqual({ containers: [] })
  })

  it('does not mutate the original manifest', () => {
    const original = { kind: 'Pod', metadata: { name: 'test' } }
    injectNamespace(original, 'chaosclaw-test')
    // Original must remain unchanged.
    expect((original.metadata as Record<string, unknown>)['namespace']).toBeUndefined()
  })

  it('overwrites an existing namespace in the manifest', () => {
    const result = injectNamespace({ kind: 'Pod', metadata: { namespace: 'original-ns' } }, 'new-ns')
    const meta = result['metadata'] as Record<string, unknown>
    expect(meta['namespace']).toBe('new-ns')
  })
})

// ---------------------------------------------------------------------------
// resolveFirstContainer
// ---------------------------------------------------------------------------

describe('resolveFirstContainer', () => {
  it('returns the name of the first container', () => {
    const manifest = { spec: { containers: [{ name: 'main' }, { name: 'sidecar' }] } }
    expect(resolveFirstContainer(manifest)).toBe('main')
  })

  it('returns undefined when spec is missing', () => {
    expect(resolveFirstContainer({})).toBeUndefined()
  })

  it('returns undefined when containers array is empty', () => {
    expect(resolveFirstContainer({ spec: { containers: [] } })).toBeUndefined()
  })

  it('returns undefined when the first container has no name', () => {
    expect(resolveFirstContainer({ spec: { containers: [{ image: 'busybox' }] } })).toBeUndefined()
  })

  it('returns undefined when spec.containers is missing entirely', () => {
    expect(resolveFirstContainer({ spec: {} })).toBeUndefined()
  })

  it('ignores subsequent containers — only the first matters', () => {
    const manifest = { spec: { containers: [{ name: 'first' }, { name: 'second' }] } }
    expect(resolveFirstContainer(manifest)).toBe('first')
  })
})
