// Alert source adapter for KubeArmor.
// Reads policy-match events from KubeArmor pod logs and correlates them to the
// test pod by namespace and pod name prefix.
//
// KubeArmor logs MatchedPolicy events to stdout when a KubeArmorPolicy rule
// triggers. The Action field distinguishes detection (Audit) from enforcement (Block).
//
// Requirement: KubeArmorPolicies must be installed targeting the test namespace.
import { LogBasedAlertSource } from './log-based.js'
import type { RuntimeAlert } from '../types.js'

interface KubeArmorLog {
    NamespaceName?: string
    PodName?: string
    PolicyName?: string
    Operation?: string
    Action?: string
    Type?: string
    UpdatedTime?: string
}

const MATCHED_POLICY_TYPES = new Set(['MatchedPolicy', 'MatchedHostPolicy'])

export class KubeArmorAlertSource extends LogBasedAlertSource {
    readonly name = 'kubearmor'

    protected readonly labelSelectors = [
        'kubearmor-app=kubearmor', // official Helm chart
        'app=kubearmor',
    ]

    protected readonly containerName = 'kubearmor'

    protected parseLine(line: string, namespace: string, podNamePrefix: string): RuntimeAlert | null {
        // Skip non-JSON lines before attempting to parse the log entry.
        if (!line.startsWith('{')) return null
        try {
            const ev = JSON.parse(line) as KubeArmorLog
            // Discard entries without the namespace and pod fields required for correlation.
            if (!ev.NamespaceName || !ev.PodName) return null
            // Filter events to only those belonging to the current test pod.
            if (ev.NamespaceName !== namespace || !ev.PodName.startsWith(podNamePrefix)) return null

            // Only surface policy-match events â€” raw telemetry events don't represent detections.
            if (ev.Type && !MATCHED_POLICY_TYPES.has(ev.Type)) return null

            return {
                source: 'kubearmor',
                // Use PolicyName as the rule name, falling back to Operation, then a generic label.
                ruleName: ev.PolicyName ?? ev.Operation ?? 'policy_match',
                namespace: ev.NamespaceName,
                podName: ev.PodName,
                triggeredAt: ev.UpdatedTime ?? new Date().toISOString(),
                // KubeArmor's Action field explicitly distinguishes Block from Audit.
                action: ev.Action === 'Block' ? 'blocked' : 'detected',
                raw: line,
            }
        } catch {
            return null
        }
    }
}
