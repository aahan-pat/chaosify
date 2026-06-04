import type { RunEvidence } from '../../../../types/evidence.js'
import { header, field, section, indent, blank } from '../../../output.js'
import type { AnyScenario } from './resolve.js'

export function printHeader(
    clusterContext: string,
    targetScenarios: AnyScenario[],
    opts: {
        pack?: string
        scenario?: string
        manifest?: string
        expect?: string
        namespace: string
        cleanup: string
        alertSource: string
        hasRuntime: boolean
        failFast?: boolean
        verbose?: boolean
    }
): void {
    header('Chaosify Probe Run')
    field('Cluster Context', clusterContext)
    if (opts.pack) field('Scenario Pack', opts.pack)
    if (opts.scenario) field('Scenario', opts.scenario)
    if (opts.manifest) {
        field('Manifest', opts.manifest)
        field('Expect', opts.expect!)
    }
    field('Scenarios', String(targetScenarios.length))
    field('Test Namespace', opts.namespace)
    field('Cleanup', opts.cleanup)
    if (opts.hasRuntime) field('Alert Source', opts.alertSource)
    if (opts.failFast) field('Mode', 'fail-fast')
    if (opts.verbose) field('Verbose', 'on')
    section(targetScenarios.length === 1 ? 'Running Scenario' : 'Running Scenarios')
}

export function printSummary(
    evidence: RunEvidence,
    notRun: number,
    exitCode: number,
    opts: { output?: string }
): void {
    section('Summary')
    indent(`Pass:    ${evidence.summary.pass}`)
    indent(`Fail:    ${evidence.summary.fail}`)
    indent(`Error:   ${evidence.summary.error}`)
    indent(`Skipped: ${evidence.summary.skipped}`)
    if (notRun > 0) indent(`Not Run: ${notRun}`)

    const failed = evidence.results.filter(r => r.status === 'Fail')
    const errors = evidence.results.filter(r => r.status === 'Error')

    if (failed.length > 0) {
        section('Failed Scenarios')
        for (const r of failed) {
            blank()
            indent(`${r.scenarioId}`)
            indent(`Expected: ${r.expectedOutcome}`, 4)
            indent(`Observed: ${r.observedOutcome}`, 4)
            if (r.likelyIssue) indent(`Likely issue: ${r.likelyIssue}`, 4)
        }
    }

    if (errors.length > 0) {
        section('Errors')
        for (const r of errors) {
            blank()
            indent(`${r.scenarioId}`)
            if (r.errorReason) indent(`Reason: ${r.errorReason}`, 4)
        }
    }

    if (notRun > 0) {
        blank()
        section('Stopped Early')
        indent('Execution stopped after first failed scenario because --fail-fast was enabled')
    }

    if (opts.output) {
        section('Artifacts')
        indent(`JSON report written to: ${opts.output}`)
    }

    if (exitCode !== 0) {
        blank()
        section('Exit Code')
        indent(String(exitCode))
    }

    blank()
}
