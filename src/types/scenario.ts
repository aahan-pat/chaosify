// Core type definitions for scenario definitions and packs.
// These types describe the shape of a verification scenario: what to run,
// what outcome to expect, and how to clean up afterwards.

/** Broad category describing when a control takes effect */
export type ScenarioCategory = 'preventive' | 'detective' | 'responsive'

/** Risk rating for the scenario — used to gate execution in sensitive environments */
export type SafetyLevel = 'low' | 'medium' | 'high'

/** The two possible admission outcomes a scenario can test for */
export type ExpectedOutcomeType = 'admission_rejected' | 'admission_allowed'

/** A named pre-condition that must be satisfied before a scenario can run */
export interface ScenarioPrerequisite {
    name: string
    description: string
}

/** Declares the admission result the scenario expects to observe */
export interface ScenarioExpectedOutcome {
    type: ExpectedOutcomeType
}

/** Controls whether created Kubernetes resources are deleted after execution */
export interface ScenarioCleanup {
    deleteCreatedResources: boolean
}

/** Risk metadata used to decide whether the scenario is safe to run in an environment */
export interface ScenarioSafety {
    level: SafetyLevel
    /** Whether execution is isolated to a single namespace (reduces blast radius) */
    namespaceScoped: boolean
}

/** Full definition of a single verification scenario */
export interface ScenarioDefinition {
    id: string
    version: number
    name: string
    description: string
    category: ScenarioCategory
    /** The security control being exercised (used in diagnostic messages) */
    controlObjective: string
    prerequisites: ScenarioPrerequisite[]
    /** Kubernetes manifest as a plain object, applied to the test namespace */
    manifest: Record<string, unknown>
    expectedOutcome: ScenarioExpectedOutcome
    cleanup: ScenarioCleanup
    safety: ScenarioSafety
    /** IDs of packs this scenario belongs to; optional for standalone scenarios */
    packMembership?: string[]
}

/** A named collection of scenario IDs that can be run together */
export interface ScenarioPack {
    id: string
    version: number
    name: string
    description: string
    scenarioIds: string[]
}
