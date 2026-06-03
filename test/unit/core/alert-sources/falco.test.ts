import { describe, it, expect } from 'vitest'
import * as k8s from '@kubernetes/client-node'
import { FalcoAlertSource } from '../../../../src/core/alert-sources/adapters/falco.js'

// ---------------------------------------------------------------------------
// Testable subclass — exposes protected parseLine for unit testing
// ---------------------------------------------------------------------------

class TestableFalco extends FalcoAlertSource {
  parse(line: string, ns: string, prefix: string) {
    return this.parseLine(line, ns, prefix)
  }
}

// parseLine does not use the KubeConfig; pass a minimal stub.
const source = new TestableFalco({} as k8s.KubeConfig)

// Build a valid Falco JSON event for the given namespace and pod name.
function falcoEvent(ns: string, podName: string, rule = 'Read sensitive file'): string {
  return JSON.stringify({
    rule,
    time: '2026-01-01T00:00:00.000Z',
    priority: 'WARNING',
    output_fields: { 'k8s.ns.name': ns, 'k8s.pod.name': podName },
  })
}

const NS = 'chaosclaw-test'
const PREFIX = 'chaosclaw-test-'
const POD = 'chaosclaw-test-abc1'

// ---------------------------------------------------------------------------
// Valid events
// ---------------------------------------------------------------------------

describe('FalcoAlertSource.parseLine — valid events', () => {
  it('returns an alert for a matching namespace and pod', () => {
    const alert = source.parse(falcoEvent(NS, POD), NS, PREFIX)
    expect(alert).not.toBeNull()
    expect(alert?.source).toBe('falco')
    expect(alert?.ruleName).toBe('Read sensitive file')
    expect(alert?.namespace).toBe(NS)
    expect(alert?.podName).toBe(POD)
  })

  it('action is always "detected" — Falco never blocks syscalls', () => {
    const alert = source.parse(falcoEvent(NS, POD), NS, PREFIX)
    expect(alert?.action).toBe('detected')
  })

  it('captures triggeredAt from the event time field', () => {
    const alert = source.parse(falcoEvent(NS, POD), NS, PREFIX)
    expect(alert?.triggeredAt).toBe('2026-01-01T00:00:00.000Z')
  })

  it('preserves the raw line in the alert', () => {
    const line = falcoEvent(NS, POD)
    const alert = source.parse(line, NS, PREFIX)
    expect(alert?.raw).toBe(line)
  })

  it('matches a pod whose name starts with the prefix (not just exact match)', () => {
    // Any pod in the test run shares the prefix; only exact match would miss some.
    const alert = source.parse(falcoEvent(NS, 'chaosclaw-test-xyz99'), NS, PREFIX)
    expect(alert).not.toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Filtering — wrong namespace or pod
// ---------------------------------------------------------------------------

describe('FalcoAlertSource.parseLine — namespace and pod filtering', () => {
  it('returns null when the event namespace does not match', () => {
    const alert = source.parse(falcoEvent('other-namespace', POD), NS, PREFIX)
    expect(alert).toBeNull()
  })

  it('returns null when the pod name does not start with the prefix', () => {
    // A pod from a different test run or the agent pod itself must not match.
    const alert = source.parse(falcoEvent(NS, 'foreign-pod-abc'), NS, PREFIX)
    expect(alert).toBeNull()
  })

  it('returns null when output_fields is absent (namespace and pod default to empty string)', () => {
    const line = JSON.stringify({ rule: 'Some Rule', time: '2026-01-01T00:00:00.000Z' })
    const alert = source.parse(line, NS, PREFIX)
    expect(alert).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Malformed lines
// ---------------------------------------------------------------------------

describe('FalcoAlertSource.parseLine — malformed lines', () => {
  it('returns null for a non-JSON line (startup messages, etc.)', () => {
    expect(source.parse('Falco version: 0.39.0 starting up', NS, PREFIX)).toBeNull()
  })

  it('returns null for a JSON array (not an object)', () => {
    expect(source.parse('[{"rule":"test"}]', NS, PREFIX)).toBeNull()
  })

  it('returns null for a JSON object missing the rule field', () => {
    const line = JSON.stringify({ time: '2026-01-01T00:00:00Z', output_fields: { 'k8s.ns.name': NS, 'k8s.pod.name': POD } })
    expect(source.parse(line, NS, PREFIX)).toBeNull()
  })

  it('returns null for a JSON object missing the time field', () => {
    const line = JSON.stringify({ rule: 'Some Rule', output_fields: { 'k8s.ns.name': NS, 'k8s.pod.name': POD } })
    expect(source.parse(line, NS, PREFIX)).toBeNull()
  })

  it('returns null for an empty string', () => {
    expect(source.parse('', NS, PREFIX)).toBeNull()
  })

  it('returns null for whitespace-only input', () => {
    expect(source.parse('   ', NS, PREFIX)).toBeNull()
  })

  it('returns null for syntactically invalid JSON', () => {
    expect(source.parse('{rule: broken json}', NS, PREFIX)).toBeNull()
  })

  it('returns null for a valid JSON primitive', () => {
    expect(source.parse('"just a string in JSON"', NS, PREFIX)).toBeNull()
  })
})
