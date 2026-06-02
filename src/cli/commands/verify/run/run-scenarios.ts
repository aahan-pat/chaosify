import chalk from 'chalk'
import type { ScenarioResult } from '../../../../types/evidence.js'
import { blank, indent, outcomeLabel, section } from '../../../output.js'
import { isRuntimeScenario } from './resolve.js'
import type { AnyScenario } from './resolve.js'
import type { RunContext } from './run-context.js'

const DEFAULT_TIMEOUT_MS = 30_000
const DEFAULT_RUNTIME_TIMEOUT_MS = 60_000

export interface RunScenariosOpts {
    namespace: string
    timeout?: string
    cleanup: string
    failFast?: boolean
    format: string
    verbose?: boolean
}

export interface RunScenariosResult {
    exitCode: number
    notRun: number
}

export async function runScenarios(
    targetScenarios: AnyScenario[],
    ctx: RunContext,
    opts: RunScenariosOpts
): Promise<RunScenariosResult> {
    let exitCode = 0
    let notRun = 0

    for (const scenario of targetScenarios) {
        const result = await executeOne(scenario, ctx, opts)
        ctx.builder.addResult(result)

        if (opts.format !== 'json') {
            indent(`${outcomeLabel(result.status)} ${scenario.id}`)
            if (opts.verbose && (result.status === 'Fail' || result.status === 'Error')) {
                if (result.likelyIssue) indent(`Likely issue:      ${result.likelyIssue}`, 4)
                if (result.rawResponse) indent(`Raw response:      ${result.rawResponse}`, 4)
                if (result.manifestSnapshot) indent(`Manifest snapshot: ${result.manifestSnapshot}`, 4)
            }
        }

        if (result.status === 'Fail' || result.status === 'Error') {
            exitCode = 1
            if (opts.failFast) {
                notRun = targetScenarios.length - targetScenarios.indexOf(scenario) - 1
                break
            }
        }
    }

    return { exitCode, notRun }
}

async function executeOne(
    scenario: AnyScenario,
    ctx: RunContext,
    opts: RunScenariosOpts
): Promise<ScenarioResult> {
    const { namespace } = opts

    if (isRuntimeScenario(scenario)) {
        const timeoutMs = opts.timeout ? parseInt(opts.timeout, 10) : DEFAULT_RUNTIME_TIMEOUT_MS
        const execution = await ctx.runtimeExecutor!.execute(scenario, { namespace, timeoutMs })
        const validation = ctx.runtimeValidator.validate(scenario, execution)
        const createdResources = execution.createdResourceName
            ? [{ kind: 'Pod' as const, name: execution.createdResourceName, namespace }]
            : []
        const cleanupResult = await processCleanup(ctx, createdResources, opts.cleanup, validation.status)
        printCleanupWarning(cleanupResult)
        return {
            scenarioId: scenario.id,
            version: scenario.version,
            status: validation.status,
            expectedOutcome: scenario.expectedOutcome.type.replace('_', ' '),
            observedOutcome: validation.observedOutcome,
            cleanupStatus: cleanupResult.status,
            startedAt: execution.startedAt,
            endedAt: execution.endedAt,
            rawResponse: execution.alertDetail ? JSON.stringify(execution.alertDetail) : execution.rawResponse,
            manifestSnapshot: execution.manifestSnapshot,
            likelyIssue: validation.likelyIssue,
        }
    }

    const timeoutMs = opts.timeout ? parseInt(opts.timeout, 10) : DEFAULT_TIMEOUT_MS
    const execution = await ctx.executor.execute(scenario, { namespace, timeoutMs })
    const validation = ctx.validator.validate(scenario, execution)
    const createdResources = execution.createdResourceName
        ? [{ kind: 'Pod' as const, name: execution.createdResourceName, namespace }]
        : []
    const cleanupResult = await processCleanup(ctx, createdResources, opts.cleanup, validation.status)
    printCleanupWarning(cleanupResult)
    return {
        scenarioId: scenario.id,
        version: scenario.version,
        status: validation.status,
        expectedOutcome: scenario.expectedOutcome.type.replace('_', ' '),
        observedOutcome: validation.observedOutcome,
        cleanupStatus: cleanupResult.status,
        startedAt: execution.startedAt,
        endedAt: execution.endedAt,
        rawResponse: execution.rawResponse,
        manifestSnapshot: execution.manifestSnapshot,
        likelyIssue: validation.likelyIssue,
    }
}

async function processCleanup(
    ctx: RunContext,
    createdResources: Array<{ kind: 'Pod'; name: string; namespace: string }>,
    cleanupMode: string,
    status: string
) {
    const shouldCleanup = cleanupMode === 'always' || (cleanupMode === 'on-success' && status === 'Pass')
    return shouldCleanup
        ? ctx.cleanup.cleanup(createdResources)
        : Promise.resolve({ status: 'skipped' as const, remainingResources: [] })
}

// Local cleanup warning for run-scenarios â€” includes a Details/Next breakdown for better operator guidance.
function printCleanupWarning(cleanupResult: { remainingResources: Array<{ kind: string; name: string; namespace: string }> }): void {
    if (cleanupResult.remainingResources.length === 0) return
    blank()
    console.log(chalk.yellow('[WARN] Cleanup incomplete'))
    section('Details')
    for (const r of cleanupResult.remainingResources) {
        indent(`${r.kind} ${r.name} could not be deleted automatically`)
    }
    section('Next')
    for (const r of cleanupResult.remainingResources) {
        indent(`kubectl delete ${r.kind.toLowerCase()} ${r.name} -n ${r.namespace}`)
    }
}
