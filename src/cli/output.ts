// Shared terminal output helpers â€” centralises chalk styling across all commands.
import chalk from 'chalk'
import type { ScenarioOutcome } from '../types/evidence.js'
import type { PreflightCheckStatus } from '../core/setup/preflight.js'
import type { ReconFinding } from '../types/recon.js'

/**
 * Prints a bold section title preceded by a blank line.
 * @param title Title text to display.
 */
export function header(title: string): void {
    console.log()
    console.log(chalk.bold(title))
}

/**
 * Prints a dimmed key followed by its value on a single line.
 * @param key Label to display dimmed.
 * @param value Value to display alongside the key.
 */
export function field(key: string, value: string): void {
    console.log(`${chalk.dim(key + ':')} ${value}`)
}

/**
 * Prints a bold sub-section heading preceded by a blank line.
 * @param title Heading text to display.
 */
export function section(title: string): void {
    console.log()
    console.log(chalk.bold(title))
}

/**
 * Prints text indented by a given number of spaces.
 * @param text Text to indent.
 * @param depth Number of spaces to indent by.
 */
export function indent(text: string, depth = 2): void {
    console.log(' '.repeat(depth) + text)
}

/** Prints an empty line for vertical spacing. */
export function blank(): void {
    console.log()
}

// Single badge lookup for all status strings â€” index with any status key across all commands.
export const badge = {
    PASS: chalk.green('[PASS]'),
    FAIL: chalk.red('[FAIL]'),
    ERROR: chalk.red('[ERROR]'),
    SKIPPED: chalk.yellow('[SKIPPED]'),
    WARN: chalk.yellow('[WARN]'),
    CRITICAL: chalk.red('[CRITICAL]'),
    HIGH: chalk.red('[HIGH]'),
    INFO: chalk.dim('[INFO]'),
    SKIP: chalk.yellow('[SKIP]'),
    ok: chalk.green('[OK]'),
    'already-existed': chalk.dim('[OK]'),
    failed: chalk.red('[ERROR]'),
}

/** Maps a ScenarioOutcome to its coloured badge string */
export function outcomeLabel(outcome: ScenarioOutcome): string {
    switch (outcome) {
        case 'Pass':    return badge.PASS
        case 'Fail':    return badge.FAIL
        case 'Error':   return badge.ERROR
        case 'Skipped': return badge.SKIPPED
    }
}

/** Maps a PreflightCheckStatus to its coloured badge string */
export function preflightLabel(s: PreflightCheckStatus): string {
    switch (s) {
        case 'pass': return badge.PASS
        case 'fail': return badge.FAIL
        case 'warn': return badge.WARN
    }
}

/** Print an alert detail section for exec/network/detect commands */
export function printAlertSection(alert: { source: string; ruleName: string; podName: string; triggeredAt: string; action?: string }): void {
    section('Alert Fired')
    indent(`Source:    ${alert.source}`)
    indent(`Rule:      ${alert.ruleName}`)
    indent(`Pod:       ${alert.podName}`)
    indent(`Action:    ${alert.action ?? 'detected'}`)
    indent(`Triggered: ${alert.triggeredAt}`)
}

/** Print a cleanup warning listing resources that need manual deletion */
export function printCleanupWarning(resources: Array<{ kind: string; name: string; namespace: string }>): void {
    if (resources.length === 0) return
    blank()
    console.log(chalk.yellow('[WARN] Cleanup incomplete'))
    section('Details')
    for (const r of resources) {
        indent(`${r.kind} ${r.name} could not be deleted automatically`)
    }
    section('Next')
    for (const r of resources) {
        indent(`kubectl delete ${r.kind.toLowerCase()} ${r.name} -n ${r.namespace}`)
    }
}

/**
 * Prints the Findings section for any recon command.
 * @param findings List of findings to render.
 */
export function renderFindings(findings: ReconFinding[]): void {
    if (findings.length === 0) return
    section('Findings')
    for (const f of findings) {
        blank()
        indent(`${badge[f.severity]} ${f.title}`)
        indent(f.detail, 9)
        if (f.coverageImpact) indent(`Impact: ${f.coverageImpact}`, 9)
    }
}
