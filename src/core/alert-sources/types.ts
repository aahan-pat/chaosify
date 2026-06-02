// Core types for the alert source abstraction layer.
// Defined here so adapters and the executor can both import without a circular dependency.

/**
 * A normalised alert record produced by any supported runtime security tool.
 * Each AlertSource adapter is responsible for translating tool-specific
 * alert formats into this shape.
 */
export interface RuntimeAlert {
    /** The tool that produced this alert (e.g. 'falco', 'tetragon', 'kubearmor') */
    source: string
    /** Rule or policy name that triggered (tool-specific label) */
    ruleName: string
    /** Namespace the event occurred in */
    namespace: string
    /** Pod name associated with the event */
    podName: string
    /** ISO timestamp from the tool's alert payload */
    triggeredAt: string
    /** Raw alert body preserved for the evidence artifact */
    raw: string
    /**
     * Whether the runtime tool blocked the action at the kernel level.
     * 'blocked' maps to action_blocked; 'detected' (default) maps to alert_fired.
     * Only enforcement-capable tools (KubeArmor, Tetragon) can emit 'blocked'.
     */
    action?: 'detected' | 'blocked'
}

/**
 * Pluggable interface for runtime security alert sources.
 * Implement one adapter per supported tool and register it with AlertSourceRegistry.
 */
export interface RuntimeAlertSource {
    /** Human-readable name of this source, used in evidence and diagnostics */
    readonly name: string

    /**
     * Check whether this alert source is reachable and operational on the cluster.
     * Called during preflight — returning false causes runtime scenarios to be skipped.
     */
    isAvailable(): Promise<boolean>

    /**
     * Poll for alerts that match the given correlation criteria within a time window.
     * @param namespace Test namespace ChaosClaw used for this scenario.
     * @param podNamePrefix Prefix used to correlate alerts to this specific test pod.
     * @param windowStart ISO timestamp marking the start of the observation window.
     * @param windowMs How long (in ms) to wait for a matching alert.
     */
    pollForAlert(
        namespace: string,
        podNamePrefix: string,
        windowStart: string,
        windowMs: number,
    ): Promise<RuntimeAlert | null>
}
