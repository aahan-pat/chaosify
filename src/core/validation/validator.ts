import type { ScenarioDefinition } from '../../types/scenario.js'
import type { ScenarioOutcome } from '../../types/evidence.js'
import type { ExecutionResult, ObservedOutcome } from '../scenarios/exec/executor.js'

const OUTCOME_LABEL: Record<ObservedOutcome, string> = {
    admission_rejected: 'admission rejected',
    admission_allowed: 'workload admitted',
    timeout: 'timeout',
    api_error: 'API error',
}

/** The verdict produced after comparing expected vs observed outcomes */
export interface ValidationResult {
    status: ScenarioOutcome
    /** Human-readable description of what the cluster did */
    observedOutcome: string
    /** Best-effort explanation of why the scenario did not pass */
    likelyIssue?: string
}

// timeout and api_error are surfaced as Error before the comparison so they never count as policy failures.
export class ValidationEngine {
    /**
     * Returns Pass/Fail/Error by comparing the scenario's expected admission outcome against what the cluster did.
     * @param scenario Scenario containing the expected outcome.
     * @param execution Raw result from the executor.
     */
    validate(scenario: ScenarioDefinition, execution: ExecutionResult): ValidationResult {
        const expected = scenario.expectedOutcome.type

        if (execution.observedOutcome === 'timeout') {
            return {
                status: 'Error',
                observedOutcome: 'timeout',
                likelyIssue: 'Request timed out waiting for Kubernetes API response',
            }
        }

        if (execution.observedOutcome === 'api_error') {
            return {
                status: 'Error',
                observedOutcome: 'api_error',
                likelyIssue: 'Kubernetes API returned an unexpected error',
            }
        }

        const observedLabel = OUTCOME_LABEL[execution.observedOutcome]

        if (expected === execution.observedOutcome) {
            return { status: 'Pass', observedOutcome: observedLabel }
        }

        return {
            status: 'Fail',
            observedOutcome: observedLabel,
            likelyIssue: this.diagnose(scenario, execution.observedOutcome),
        }
    }

    // Direction matters: rejected but got allowed → policy missing; allowed but got rejected → policy too broad.
    private diagnose(scenario: ScenarioDefinition, observed: ObservedOutcome): string {
        if (scenario.expectedOutcome.type === 'admission_rejected' && observed === 'admission_allowed') {
            return `${scenario.controlObjective} — policy may not be installed, or does not cover this resource type`
        }
        if (scenario.expectedOutcome.type === 'admission_allowed' && observed === 'admission_rejected') {
            return `Policy is more restrictive than expected — check admission rules for ${scenario.controlObjective}`
        }
        return 'Unexpected outcome — inspect the raw response for details'
    }
}
