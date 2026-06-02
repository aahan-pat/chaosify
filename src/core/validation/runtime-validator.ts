// Validates runtime detection scenarios where the signal is an alert, not an admission decision.
import type { RuntimeScenarioDefinition } from '../../types/runtime-scenario.js'
import type { RuntimeExecutionResult, RuntimeObservedOutcome } from '../scenarios/exec/runtime-executor.js'
import type { ValidationResult } from './validator.js'

const OUTCOME_LABEL: Record<RuntimeObservedOutcome, string> = {
    alert_fired: 'alert fired',
    action_blocked: 'action blocked',
    no_alert: 'no alert observed',
    timeout: 'timeout',
    api_error: 'API error',
}

export class RuntimeValidationEngine {
    validate(scenario: RuntimeScenarioDefinition, execution: RuntimeExecutionResult): ValidationResult {
        const expected = scenario.expectedOutcome.type

        // timeout and api_error are infra failures, not detection gaps — surface as Error not Fail.
        if (execution.observedOutcome === 'timeout') {
            return {
                status: 'Error',
                observedOutcome: 'timeout',
                likelyIssue: 'Executor timed out before the observation window closed',
            }
        }

        if (execution.observedOutcome === 'api_error') {
            return {
                status: 'Error',
                observedOutcome: 'api_error',
                likelyIssue: 'Kubernetes API error during scenario setup — check cluster connectivity and RBAC',
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

    private diagnose(scenario: RuntimeScenarioDefinition, observed: RuntimeObservedOutcome): string {
        if (observed === 'no_alert') {
            return `${scenario.controlObjective} — runtime tool may not be installed, or this rule is not enabled`
        }
        return 'Unexpected outcome — inspect the alert detail for more information'
    }
}
