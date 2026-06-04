// Types for the recon layer — intentionally separate from the evidence schema used for pass/fail verdicts.

export type ReconFindingSeverity = 'CRITICAL' | 'HIGH' | 'WARN' | 'INFO' | 'SKIP'

export interface ReconFinding {
    severity: ReconFindingSeverity
    title: string
    detail: string
    /** SKIP findings only. */
    missingPermission?: string
    /** SKIP findings only. */
    coverageImpact?: string
}

// Result from one recon tool — always returned, never thrown, even on permission errors.
export interface ReconToolResult {
    tool: string
    status: 'ok' | 'skip' | 'error'
    findings: ReconFinding[]
    /** Raw structured data for agentic AI consumption. */
    data: unknown
}

// Top-level artifact written by `chaosify recon all`.
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
