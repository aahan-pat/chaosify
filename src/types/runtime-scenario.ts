// Type definitions for runtime detection scenarios.
// Runtime scenarios differ from preventive scenarios in that the workload is
// expected to be admitted — the signal under test is whether the runtime
// security tool detects a threat after the pod is running.
import type { ScenarioPrerequisite, ScenarioCleanup, ScenarioSafety, ScenarioPack } from './scenario.js'

/** The outcome a runtime scenario expects the security tool to produce */
export type RuntimeExpectedOutcomeType = 'alert_fired' | 'action_blocked'

/**
 * A command to exec inside a running container to trigger a threat behaviour.
 * The command is expected to exercise a specific syscall or action that a
 * runtime security tool should detect (e.g. reading a sensitive file,
 * spawning a shell, making an unexpected network connection).
 */
export interface RuntimeScenarioExecStep {
    /** Must match a container name in the scenario manifest */
    container: string
    /** Argv of the command to run inside the container */
    command: string[]
    /** How long to wait for the exec to complete before giving up (ms). Defaults to 10 000. */
    timeoutMs?: number
}

/** Full definition of a single runtime detection scenario */
export interface RuntimeScenarioDefinition {
    id: string
    version: number
    name: string
    description: string
    category: 'detective'
    controlObjective: string
    prerequisites: ScenarioPrerequisite[]
    /** Pod manifest — expected to be admitted by the cluster */
    manifest: Record<string, unknown>
    /** Command to exec inside the running pod to trigger the threat */
    execStep: RuntimeScenarioExecStep
    /** What the runtime security tool should observe */
    expectedOutcome: { type: RuntimeExpectedOutcomeType }
    cleanup: ScenarioCleanup
    safety: ScenarioSafety
    packMembership?: string[]
}

export type { ScenarioPack }
