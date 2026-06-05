import { randomUUID } from 'node:crypto'
import { mkdir, writeFile } from 'node:fs/promises'
import { dirname } from 'node:path'
import type { ScenarioResult, RunEvidence, RunSummary } from '../../types/evidence.js'

const VERSION = '0.1.1'

/** Metadata provided once at the start of a run (before any scenarios execute) */
export interface EvidenceBuilderOptions {
    clusterContext: string
    packId?: string
    packVersion?: string
    /** Set when a single scenario was targeted rather than a full pack */
    scenarioId?: string
    startedAt: string
}

// A new UUID is generated per instance so concurrent runs produce distinct artifacts.
export class EvidenceBuilder {
    private readonly runId = randomUUID()
    private readonly results: ScenarioResult[] = []
    private readonly options: EvidenceBuilderOptions

    constructor(options: EvidenceBuilderOptions) {
        this.options = options
    }

    /** Append the result of one scenario execution to this run's evidence */
    addResult(result: ScenarioResult): void {
        this.results.push(result)
    }

    /**
     * Assembles the final RunEvidence document.
     * @param endedAt Timestamp to record as the run end time.
     */
    build(endedAt: string): RunEvidence {
        const summary = this.summarize()
        return {
            runId: this.runId,
            toolVersion: VERSION,
            clusterContext: this.options.clusterContext,
            initiatedBy: process.env['USER'] ?? process.env['USERNAME'] ?? 'unknown',
            packId: this.options.packId,
            // packVersion is stored as a string even when provided as a number.
            packVersion: this.options.packVersion !== undefined ? String(this.options.packVersion) : undefined,
            scenarioId: this.options.scenarioId,
            startedAt: this.options.startedAt,
            endedAt,
            summary,
            results: this.results,
        }
    }

    /** Writes the evidence document to a JSON file, creating parent directories as needed */
    async writeToFile(filePath: string, evidence: RunEvidence): Promise<void> {
        await mkdir(dirname(filePath), { recursive: true })
        await writeFile(filePath, JSON.stringify(evidence, null, 2), 'utf-8')
    }

    private summarize(): RunSummary {
        return this.results.reduce<RunSummary>(
            (acc, r) => {
                switch (r.status) {
                    case 'Pass':    return { ...acc, pass: acc.pass + 1 }
                    case 'Fail':    return { ...acc, fail: acc.fail + 1 }
                    case 'Error':   return { ...acc, error: acc.error + 1 }
                    case 'Skipped': return { ...acc, skipped: acc.skipped + 1 }
                }
            },
            { pass: 0, fail: 0, error: 0, skipped: 0 },
        )
    }
}
