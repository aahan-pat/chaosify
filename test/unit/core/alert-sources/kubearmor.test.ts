import { describe, it, expect } from 'vitest'
import * as k8s from '@kubernetes/client-node'
import { KubeArmorAlertSource } from '../../../../src/core/alert-sources/adapters/kubearmor.js'

// ---------------------------------------------------------------------------
// Testable subclass — exposes protected parseLine for unit testing
// ---------------------------------------------------------------------------

class TestableKubeArmor extends KubeArmorAlertSource {
  parse(line: string, ns: string, prefix: string) {
    return this.parseLine(line, ns, prefix)
  }
}

const source = new TestableKubeArmor({} as k8s.KubeConfig)

const NS = 'chaosclaw-test'
const PREFIX = 'chaosclaw-test-'
const POD = 'chaosclaw-test-abc1'

// Build a KubeArmor log event with sensible defaults.
function kubeArmorEvent(
  ns: string,
  podName: string,
  opts: { type?: string; action?: string; policyName?: string; operation?: string } = {},
): string {
  return JSON.stringify({
    NamespaceName: ns,
    PodName: podName,
    Type: opts.type ?? 'MatchedPolicy',
    Action: opts.action ?? 'Audit',
    PolicyName: opts.policyName ?? 'block-exec',
    Operation: opts.operation ?? 'Process',
    UpdatedTime: '2026-01-01T00:00:00.000Z',
  })
}

// ---------------------------------------------------------------------------
// MatchedPolicy events
// ---------------------------------------------------------------------------

describe('KubeArmorAlertSource.parseLine — MatchedPolicy events', () => {
  it('returns an alert for a MatchedPolicy event matching the test pod', () => {
    const alert = source.parse(kubeArmorEvent(NS, POD), NS, PREFIX)
    expect(alert).not.toBeNull()
    expect(alert?.source).toBe('kubearmor')
  })

  it('returns action "blocked" when Action is "Block"', () => {
    const alert = source.parse(kubeArmorEvent(NS, POD, { action: 'Block' }), NS, PREFIX)
    expect(alert?.action).toBe('blocked')
  })

  it('returns action "detected" when Action is "Audit"', () => {
    const alert = source.parse(kubeArmorEvent(NS, POD, { action: 'Audit' }), NS, PREFIX)
    expect(alert?.action).toBe('detected')
  })

  it('returns action "detected" for any non-Block action (default)', () => {
    const alert = source.parse(kubeArmorEvent(NS, POD, { action: 'Allow' }), NS, PREFIX)
    expect(alert?.action).toBe('detected')
  })

  it('uses PolicyName as ruleName when available', () => {
    const alert = source.parse(kubeArmorEvent(NS, POD, { policyName: 'restrict-shell' }), NS, PREFIX)
    expect(alert?.ruleName).toBe('restrict-shell')
  })

  it('falls back to Operation when PolicyName is absent', () => {
    const line = JSON.stringify({
      NamespaceName: NS,
      PodName: POD,
      Type: 'MatchedPolicy',
      Action: 'Block',
      Operation: 'Process',
      UpdatedTime: '2026-01-01T00:00:00.000Z',
    })
    const alert = source.parse(line, NS, PREFIX)
    expect(alert?.ruleName).toBe('Process')
  })

  it('falls back to "policy_match" when both PolicyName and Operation are absent', () => {
    const line = JSON.stringify({
      NamespaceName: NS,
      PodName: POD,
      Type: 'MatchedPolicy',
      Action: 'Block',
      UpdatedTime: '2026-01-01T00:00:00.000Z',
    })
    const alert = source.parse(line, NS, PREFIX)
    expect(alert?.ruleName).toBe('policy_match')
  })

  it('captures namespace and pod name from the event', () => {
    const alert = source.parse(kubeArmorEvent(NS, POD), NS, PREFIX)
    expect(alert?.namespace).toBe(NS)
    expect(alert?.podName).toBe(POD)
  })
})

// ---------------------------------------------------------------------------
// MatchedHostPolicy
// ---------------------------------------------------------------------------

describe('KubeArmorAlertSource.parseLine — MatchedHostPolicy', () => {
  it('returns an alert for MatchedHostPolicy events', () => {
    const line = kubeArmorEvent(NS, POD, { type: 'MatchedHostPolicy' })
    const alert = source.parse(line, NS, PREFIX)
    expect(alert).not.toBeNull()
  })

  it('respects Block action in MatchedHostPolicy', () => {
    const line = kubeArmorEvent(NS, POD, { type: 'MatchedHostPolicy', action: 'Block' })
    expect(source.parse(line, NS, PREFIX)?.action).toBe('blocked')
  })
})

// ---------------------------------------------------------------------------
// Non-policy event types are ignored
// ---------------------------------------------------------------------------

describe('KubeArmorAlertSource.parseLine — ignored event types', () => {
  it('returns null for raw telemetry Type "ContainerLog"', () => {
    const line = kubeArmorEvent(NS, POD, { type: 'ContainerLog' })
    expect(source.parse(line, NS, PREFIX)).toBeNull()
  })

  it('returns null for Type "HostLog"', () => {
    const line = kubeArmorEvent(NS, POD, { type: 'HostLog' })
    expect(source.parse(line, NS, PREFIX)).toBeNull()
  })

  it('returns null when Type is set to an unrecognised value', () => {
    const line = kubeArmorEvent(NS, POD, { type: 'Unknown' })
    expect(source.parse(line, NS, PREFIX)).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Missing required fields
// ---------------------------------------------------------------------------

describe('KubeArmorAlertSource.parseLine — missing required fields', () => {
  it('returns null when NamespaceName is absent', () => {
    const line = JSON.stringify({ PodName: POD, Type: 'MatchedPolicy', Action: 'Block' })
    expect(source.parse(line, NS, PREFIX)).toBeNull()
  })

  it('returns null when PodName is absent', () => {
    const line = JSON.stringify({ NamespaceName: NS, Type: 'MatchedPolicy', Action: 'Block' })
    expect(source.parse(line, NS, PREFIX)).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Namespace and pod filtering
// ---------------------------------------------------------------------------

describe('KubeArmorAlertSource.parseLine — filtering', () => {
  it('returns null when NamespaceName does not match the target namespace', () => {
    expect(source.parse(kubeArmorEvent('other-ns', POD), NS, PREFIX)).toBeNull()
  })

  it('returns null when PodName does not start with the prefix', () => {
    expect(source.parse(kubeArmorEvent(NS, 'foreign-pod-abc'), NS, PREFIX)).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Malformed lines
// ---------------------------------------------------------------------------

describe('KubeArmorAlertSource.parseLine — malformed lines', () => {
  it('returns null for a non-JSON line', () => {
    expect(source.parse('kubearmor: loading policies', NS, PREFIX)).toBeNull()
  })

  it('returns null for syntactically invalid JSON', () => {
    expect(source.parse('{NamespaceName: broken}', NS, PREFIX)).toBeNull()
  })

  it('returns null for an empty string', () => {
    expect(source.parse('', NS, PREFIX)).toBeNull()
  })
})
