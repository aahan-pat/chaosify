// Shared terminal output helpers — centralises chalk styling across all commands.
import chalk from 'chalk'
import type { ReconFinding, ReconFindingSeverity } from '../types/recon.js'


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

// Single badge lookup for all status strings — index with any status key across all commands.
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

/**
 * Prints the Findings section for any recon command.
 * @param findings List of findings to render.
 */
export function renderReconFindings(findings: ReconFinding[]): void {
    if (findings.length === 0) return
    section('Findings')
    for (const f of findings) {
        blank()
        indent(`${badge[f.severity]} ${f.title}`)
        indent(f.detail, 9)
        if (f.coverageImpact) indent(`Impact: ${f.coverageImpact}`, 9)
    }
}
