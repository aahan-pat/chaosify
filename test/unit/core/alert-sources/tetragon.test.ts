import { describe, it, expect } from 'vitest'
import * as k8s from '@kubernetes/client-node'
import { TetragonAlertSource } from '../../../../src/core/alert-sources/adapters/tetragon.js'

// ---------------------------------------------------------------------------
// Testable subclass — exposes protected parseLine for unit testing
// ---------------------------------------------------------------------------

class TestableTetragon extends TetragonAlertSource {
  parse(line: string, ns: string, prefix: string) {
    return this.parseLine(line, ns, prefix)
  }
}

const source = new TestableTetragon({} as k8s.KubeConfig)

const NS = 'chaosclaw-test'
const PREFIX = 'chaosclaw-test-'
const POD = 'chaosclaw-test-abc1'

// Build a Tetragon process_exec event.
function execEvent(ns: string, podName: string, binary = '/bin/cat'): string {
  return JSON.stringify({
    process_exec: { process: { pod: { namespace: ns, name: podName }, binary } },
    time: '2026-01-01T00:00:00.000Z',
  })
}

// Build a Tetragon process_kprobe event, optionally with an enforcement action.
function kprobeEvent(ns: string, podName: string, action?: string, policyName?: string): string {
  return JSON.stringify({
    process_kprobe: {
      process: { pod: { namespace: ns, name: podName } },
      function_name: '__x64_sys_read',
      policy_name: policyName,
      action,
    },
    time: '2026-01-01T00:00:00.000Z',
  })
}

// Build a process_tracepoint event, optionally with an enforcement action.
function tracepointEvent(ns: string, podName: string, action?: string): string {
  return JSON.stringify({
    process_tracepoint: {
      process: { pod: { namespace: ns, name: podName } },
      subsys: 'raw_syscalls',
      call: 'sys_enter',
      action,
    },
    time: '2026-01-01T00:00:00.000Z',
  })
}

// ---------------------------------------------------------------------------
// process_exec events
// ---------------------------------------------------------------------------

describe('TetragonAlertSource.parseLine — process_exec', () => {
  it('returns an alert for a matching process_exec event', () => {
    const alert = source.parse(execEvent(NS, POD), NS, PREFIX)
    expect(alert).not.toBeNull()
    expect(alert?.source).toBe('tetragon')
  })

  it('returns action "detected" for process_exec (no enforcement action)', () => {
    const alert = source.parse(execEvent(NS, POD), NS, PREFIX)
    expect(alert?.action).toBe('detected')
  })

  it('uses the binary path as ruleName when no policy name is available', () => {
    const alert = source.parse(execEvent(NS, POD, '/bin/cat'), NS, PREFIX)
    expect(alert?.ruleName).toBe('/bin/cat')
  })

  it('captures namespace and pod name from the process reference', () => {
    const alert = source.parse(execEvent(NS, POD), NS, PREFIX)
    expect(alert?.namespace).toBe(NS)
    expect(alert?.podName).toBe(POD)
  })
})

// ---------------------------------------------------------------------------
// process_kprobe enforcement actions
// ---------------------------------------------------------------------------

describe('TetragonAlertSource.parseLine — process_kprobe enforcement', () => {
  it('returns action "blocked" when kprobe action is SIGKILL', () => {
    const alert = source.parse(kprobeEvent(NS, POD, 'SIGKILL'), NS, PREFIX)
    expect(alert?.action).toBe('blocked')
  })

  it('returns action "blocked" when kprobe action is Override', () => {
    const alert = source.parse(kprobeEvent(NS, POD, 'Override'), NS, PREFIX)
    expect(alert?.action).toBe('blocked')
  })

  it('returns action "detected" for any other kprobe action', () => {
    const alert = source.parse(kprobeEvent(NS, POD, 'Post'), NS, PREFIX)
    expect(alert?.action).toBe('detected')
  })

  it('returns action "detected" when kprobe has no action field', () => {
    const alert = source.parse(kprobeEvent(NS, POD), NS, PREFIX)
    expect(alert?.action).toBe('detected')
  })

  it('prefers policy_name over function_name as ruleName', () => {
    const alert = source.parse(kprobeEvent(NS, POD, undefined, 'block-writes'), NS, PREFIX)
    expect(alert?.ruleName).toBe('block-writes')
  })

  it('falls back to function_name when policy_name is absent', () => {
    const alert = source.parse(kprobeEvent(NS, POD), NS, PREFIX)
    expect(alert?.ruleName).toBe('__x64_sys_read')
  })
})

// ---------------------------------------------------------------------------
// process_tracepoint
// ---------------------------------------------------------------------------

describe('TetragonAlertSource.parseLine — process_tracepoint', () => {
  it('returns an alert for a tracepoint event', () => {
    const alert = source.parse(tracepointEvent(NS, POD), NS, PREFIX)
    expect(alert).not.toBeNull()
    expect(alert?.action).toBe('detected')
  })

  it('returns action "blocked" for tracepoint with Override action', () => {
    const alert = source.parse(tracepointEvent(NS, POD, 'Override'), NS, PREFIX)
    expect(alert?.action).toBe('blocked')
  })
})

// ---------------------------------------------------------------------------
// Namespace and pod filtering
// ---------------------------------------------------------------------------

describe('TetragonAlertSource.parseLine — filtering', () => {
  it('returns null when the event namespace does not match', () => {
    expect(source.parse(execEvent('other-ns', POD), NS, PREFIX)).toBeNull()
  })

  it('returns null when the pod name does not start with the prefix', () => {
    expect(source.parse(execEvent(NS, 'foreign-pod-abc'), NS, PREFIX)).toBeNull()
  })

  it('returns null when the event has no process reference in any event type', () => {
    const line = JSON.stringify({ time: '2026-01-01T00:00:00Z' })
    expect(source.parse(line, NS, PREFIX)).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Malformed lines
// ---------------------------------------------------------------------------

describe('TetragonAlertSource.parseLine — malformed lines', () => {
  it('returns null for a non-JSON line', () => {
    expect(source.parse('tetragon init: loading BPF programs', NS, PREFIX)).toBeNull()
  })

  it('returns null for syntactically invalid JSON', () => {
    expect(source.parse('{process_exec: broken}', NS, PREFIX)).toBeNull()
  })

  it('returns null for an empty string', () => {
    expect(source.parse('', NS, PREFIX)).toBeNull()
  })

  it('returns null for a JSON object with no recognised event type keys', () => {
    const line = JSON.stringify({ unknown_field: true })
    expect(source.parse(line, NS, PREFIX)).toBeNull()
  })
})
