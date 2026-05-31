// Types for the recon layer — intentionally separate from the evidence schema.
// Recon findings feed OpenClaw for analysis, not the pass/fail verdict system.

export type ReconFindingSeverity = 'CRITICAL' | 'HIGH' | 'WARN' | 'INFO' | 'SKIP'

export interface ReconFinding {
    severity: ReconFindingSeverity
    title: string
    detail: string
    /** Which permission was missing — present on SKIP findings only. */
    missingPermission?: string
    /** What coverage was lost — present on SKIP findings only. */
    coverageImpact?: string
}

// Result from one recon tool — always returned, never thrown, even on permission errors.
export interface ReconToolResult {
    tool: string
    status: 'ok' | 'skip' | 'error'
    findings: ReconFinding[]
    /** Raw structured API data for OpenClaw consumption. */
    data: unknown
}

// Top-level artifact written by `chaosclaw recon all`.
export interface ReconReport {
    runId: string
    clusterContext: string
    namespace: string
    startedAt: string
    endedAt: string
    summary: { critical: number; high: number; warn: number; info: number; skip: number }
    tools: ReconToolResult[]
}

export interface ReconOptions {
    namespace: string
    context?: string
    verbose?: boolean
    /** Include kube-system service accounts — off by default to reduce noise. */
    includeSystem?: boolean
    /** Force a specific policy engine instead of auto-detecting. */
    engine?: string
}
