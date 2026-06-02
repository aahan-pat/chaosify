// Types for scenario execution results and the JSON evidence artifact produced by a run.
// A RunEvidence document is the primary audit output — it records what ran, what was
// expected, what was observed, and a count-level summary.

/** High-level verdict for a single scenario execution */
export type ScenarioOutcome = 'Pass' | 'Fail' | 'Error' | 'Skipped'

/** Outcome of the post-execution resource cleanup step */
export type CleanupStatus = 'success' | 'failed' | 'skipped' | 'partial'

/** Detailed result for one scenario within a run */
export interface ScenarioResult {
    scenarioId: string
    version: number
    status: ScenarioOutcome
    /** Human-readable form of the scenario's expected admission outcome */
    expectedOutcome: string
    /** Human-readable form of what the cluster actually did */
    observedOutcome: string
    cleanupStatus: CleanupStatus
    startedAt: string
    endedAt: string
    /** Raw Kubernetes API response body for debugging */
    rawResponse?: string
    /** The manifest that was submitted, captured at execution time */
    manifestSnapshot?: string
    /** Best-guess explanation when the scenario fails */
    likelyIssue?: string
    skipReason?: string
    errorReason?: string
}

/** Aggregate pass/fail counts across all scenarios in a run */
export interface RunSummary {
    pass: number
    fail: number
    error: number
    skipped: number
}

/** Top-level evidence artifact written to disk (or stdout) after a verification run */
export interface RunEvidence {
    /** UUID uniquely identifying this run */
    runId: string
    toolVersion: string
    clusterContext: string
    /** OS user that initiated the run */
    initiatedBy: string
    packId?: string
    packVersion?: string
    /** Set when a single scenario was targeted instead of a full pack */
    scenarioId?: string
    startedAt: string
    endedAt: string
    summary: RunSummary
    results: ScenarioResult[]
}
