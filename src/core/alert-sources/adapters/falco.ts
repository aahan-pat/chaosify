// Alert source adapter for Falco.
// Reads JSON-formatted alerts from Falco pod logs and correlates them to the
// test pod by namespace and pod name prefix.
//
// Requirement: Falco must be configured with JSON output enabled.
// Set json_output: true in falco.yaml or pass --json-output to the Falco process.
import { LogBasedAlertSource } from './log-based.js'
import type { RuntimeAlert } from '../types.js'

interface FalcoJsonEvent {
    rule?: string
    time?: string
    priority?: string
    output_fields?: Record<string, string>
}

export class FalcoAlertSource extends LogBasedAlertSource {
    readonly name = 'falco'

    protected readonly labelSelectors = [
        'app.kubernetes.io/name=falco', // current Helm chart
        'app=falco',                     // legacy / manual deployments
    ]

    protected readonly containerName = 'falco'

    protected parseLine(line: string, namespace: string, podNamePrefix: string): RuntimeAlert | null {
        // Quickly skip non-JSON lines (e.g. startup messages) before paying the parse cost.
        if (!line.startsWith('{')) return null
        try {
            const ev = JSON.parse(line) as FalcoJsonEvent
            // Discard events missing required fields â€” they cannot be attributed to a rule or time.
            if (!ev.rule || !ev.time) return null

            // Extract the Kubernetes namespace and pod name from Falco's output_fields map.
            const fields = ev.output_fields ?? {}
            const alertNs = fields['k8s.ns.name'] ?? ''
            const alertPod = fields['k8s.pod.name'] ?? ''
            // Filter out events not related to the current test pod.
            if (alertNs !== namespace || !alertPod.startsWith(podNamePrefix)) return null

            return {
                source: 'falco',
                ruleName: ev.rule,
                namespace: alertNs,
                podName: alertPod,
                triggeredAt: ev.time,
                action: 'detected', // Falco is detection-only; it never blocks syscalls
                raw: line,
            }
        } catch {
            return null
        }
    }
}
