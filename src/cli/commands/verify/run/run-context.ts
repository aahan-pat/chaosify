import { ScenarioExecutor } from '../../../../core/scenarios/exec/executor.js'
import { ValidationEngine } from '../../../../core/validation/validator.js'
import { RuntimeScenarioExecutor } from '../../../../core/scenarios/exec/runtime-executor.js'
import { RuntimeValidationEngine } from '../../../../core/validation/runtime-validator.js'
import { buildAlertSource } from '../../../../core/alert-sources/index.js'
import { CleanupManager } from '../../../../core/teardown/cleanup.js'
import { EvidenceBuilder } from '../../../../core/teardown/evidence-builder.js'
import { ensureNamespace } from '../../../../core/scenarios/exec/pod-runner.js'
import { buildKubeConfig } from '../../recon/utils/shared.js'
import type * as k8s from '@kubernetes/client-node'

export interface RunContext {
    kc: k8s.KubeConfig
    clusterContext: string
    executor: ScenarioExecutor
    validator: ValidationEngine
    runtimeExecutor: RuntimeScenarioExecutor | null
    runtimeValidator: RuntimeValidationEngine
    cleanup: CleanupManager
    builder: EvidenceBuilder
}

export async function buildRunContext(opts: {
    context?: string
    namespace: string
    alertSource: string
    pack?: string
    scenario?: string
    hasRuntime: boolean
}): Promise<RunContext> {
    const { kc, clusterContext } = buildKubeConfig(opts.context)

    await ensureNamespace(kc, opts.namespace)

    const executor = new ScenarioExecutor(kc)
    const validator = new ValidationEngine()
    // Only instantiate the runtime executor if the run includes runtime scenarios.
    const runtimeExecutor = opts.hasRuntime
        ? new RuntimeScenarioExecutor(kc, buildAlertSource(opts.alertSource, kc))
        : null
    const runtimeValidator = new RuntimeValidationEngine()
    const cleanup = new CleanupManager(kc)
    const builder = new EvidenceBuilder({
        clusterContext,
        packId: opts.pack,
        packVersion: opts.pack ? '1' : undefined,
        scenarioId: opts.scenario,
        startedAt: new Date().toISOString(),
    })

    return { kc, clusterContext, executor, validator, runtimeExecutor, runtimeValidator, cleanup, builder }
}
