// Shared base for alert sources that work by tailing agent pod logs.
// Each adapter subclass declares which pods to watch and how to parse log lines.
// Requires list/get pods permission in the namespaces where the agent is deployed.
import * as k8s from '@kubernetes/client-node'
import type { RuntimeAlertSource, RuntimeAlert } from '../types.js'

const POLL_INTERVAL_MS = 2_000
// Cap per poll so a very chatty agent doesn't stall the observation loop.
const LOG_LIMIT_BYTES = 512_000

export abstract class LogBasedAlertSource implements RuntimeAlertSource {
    abstract readonly name: string

    /** Label selectors tried in order until one returns running pods */
    protected abstract readonly labelSelectors: string[]

    /** Container name within each agent pod whose stdout contains alert JSON */
    protected abstract readonly containerName: string

    constructor(protected readonly kc: k8s.KubeConfig) {}

    // Confirm the agent is running by finding at least one Running pod matching the label selectors.
    async isAvailable(): Promise<boolean> {
        try {
            const pods = await this.findAgentPods()
            return pods.length > 0
        } catch {
            return false
        }
    }

    // Poll agent pod logs repeatedly until a matching alert is found or the observation window expires.
    async pollForAlert(
        namespace: string,
        podNamePrefix: string,
        windowStart: string,
        windowMs: number,
    ): Promise<RuntimeAlert | null> {
        // Compute the absolute deadline so the loop terminates even if checkLogs is slow.
        const deadline = Date.now() + windowMs
        while (Date.now() < deadline) {
            const alert = await this.checkLogs(namespace, podNamePrefix, windowStart)
            if (alert) return alert
            // Sleep only as long as the remaining window allows, to avoid overshooting the deadline.
            const remaining = deadline - Date.now()
            if (remaining <= 0) break
            await new Promise(r => setTimeout(r, Math.min(POLL_INTERVAL_MS, remaining)))
        }
        return null
    }

    /**
     * Parse one stdout line from the agent pod.
     * Return a RuntimeAlert if the line represents an event for the test pod, null otherwise.
     * Implementations should return null (never throw) for unparseable lines.
     */
    protected abstract parseLine(
        line: string,
        namespace: string,
        podNamePrefix: string,
    ): RuntimeAlert | null

    private async checkLogs(
        namespace: string,
        podNamePrefix: string,
        windowStart: string,
    ): Promise<RuntimeAlert | null> {
        const coreApi = this.kc.makeApiClient(k8s.CoreV1Api)
        const pods = await this.findAgentPods()

        // Compute how far back to fetch â€” elapsed time since the observation window opened
        // plus a 2-second buffer to account for clock skew between nodes and the client.
        const elapsedMs = Date.now() - new Date(windowStart).getTime()
        const sinceSeconds = Math.max(2, Math.ceil(elapsedMs / 1000) + 2)

        for (const pod of pods) {
            const podName = pod.metadata?.name ?? ''
            const podNamespace = pod.metadata?.namespace ?? 'default'
            try {
                // Fetch recent log bytes from the agent container, bounded by LOG_LIMIT_BYTES.
                const logs = await coreApi.readNamespacedPodLog({
                    name: podName,
                    namespace: podNamespace,
                    container: this.containerName,
                    sinceSeconds,
                    limitBytes: LOG_LIMIT_BYTES,
                })
                // Scan line-by-line and delegate JSON parsing to the subclass implementation.
                for (const line of logs.split('\n')) {
                    const trimmed = line.trim()
                    if (!trimmed) continue
                    const alert = this.parseLine(trimmed, namespace, podNamePrefix)
                    if (alert) return alert
                }
            } catch { /* skip individual pod failures â€” another pod may have the event */ }
        }
        return null
    }

    // Try each label selector in order and return the first set of Running pods found.
    protected async findAgentPods(): Promise<k8s.V1Pod[]> {
        const coreApi = this.kc.makeApiClient(k8s.CoreV1Api)
        for (const selector of this.labelSelectors) {
            try {
                const response = await coreApi.listPodForAllNamespaces({ labelSelector: selector })
                // Only consider Running pods â€” pending/failed pods won't have useful logs.
                const running = response.items.filter(p => p.status?.phase === 'Running')
                if (running.length > 0) return running
            } catch { continue }
        }
        return []
    }
}
