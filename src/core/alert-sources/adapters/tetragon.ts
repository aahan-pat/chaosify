// Alert source adapter for Tetragon.
// Reads process events from the export-stdout sidecar container and correlates
// them to the test pod by namespace and pod name prefix.
//
// Tetragon emits raw process execution events (process_exec, process_kprobe,
// process_tracepoint) rather than named alerts. Any event associated with the
// test pod is treated as alert_fired â€” confirming Tetragon observed the action.
//
// Requirement: Tetragon must be deployed with the export-stdout sidecar container
// (enabled by default in the Helm chart).
import { LogBasedAlertSource } from './log-based.js'
import type { RuntimeAlert } from '../types.js'

interface TetragonProcessRef {
    pod?: { namespace?: string; name?: string }
    binary?: string
}

interface TetragonEvent {
    process_exec?: { process?: TetragonProcessRef }
    process_kprobe?: {
        process?: TetragonProcessRef
        function_name?: string
        policy_name?: string
        action?: string
    }
    process_tracepoint?: {
        process?: TetragonProcessRef
        subsys?: string
        call?: string
        policy_name?: string
        action?: string
    }
    time?: string
}

export class TetragonAlertSource extends LogBasedAlertSource {
    readonly name = 'tetragon'

    protected readonly labelSelectors = [
        'app.kubernetes.io/name=tetragon', // Helm chart
        'app=tetragon',
    ]

    // Process events are written to stdout by the export-stdout sidecar.
    protected readonly containerName = 'export-stdout'

    protected parseLine(line: string, namespace: string, podNamePrefix: string): RuntimeAlert | null {
        // Ignore non-JSON lines to avoid paying the parse cost on startup log messages.
        if (!line.startsWith('{')) return null
        try {
            const ev = JSON.parse(line) as TetragonEvent
            // Identify the process reference regardless of which event type fired.
            const process = ev.process_exec?.process
                ?? ev.process_kprobe?.process
                ?? ev.process_tracepoint?.process
            if (!process) return null

            // Extract Kubernetes pod context embedded in Tetragon's process reference.
            const alertNs = process.pod?.namespace ?? ''
            const alertPod = process.pod?.name ?? ''
            // Skip events from other namespaces or pods not belonging to this test run.
            if (alertNs !== namespace || !alertPod.startsWith(podNamePrefix)) return null

            const kprobeAction = ev.process_kprobe?.action ?? ev.process_tracepoint?.action
            // Build a descriptive rule name by preferring the policy name, falling back to function/call.
            const ruleName = ev.process_kprobe?.policy_name
                ?? ev.process_tracepoint?.policy_name
                ?? ev.process_kprobe?.function_name
                ?? ev.process_tracepoint?.call
                ?? process.binary
                ?? 'process_event'

            return {
                source: 'tetragon',
                ruleName,
                namespace: alertNs,
                podName: alertPod,
                triggeredAt: ev.time ?? new Date().toISOString(),
                // Tetragon enforcement actions include SIGKILL and Override â€” treat those as blocked.
                action: kprobeAction === 'SIGKILL' || kprobeAction === 'Override' ? 'blocked' : 'detected',
                raw: line,
            }
        } catch {
            return null
        }
    }
}
