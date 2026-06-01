import { isForbidden } from '../kube/errors.js'
import type { ReconFinding, ReconToolResult } from '../../types/recon.js'

/**
 * Convenience wrapper mapping 403 to skip and other errors to error status.
 * Optional — commands with custom error handling can write their own try/catch.
 * @param tool Tool name used in the returned ReconToolResult.
 * @param skip Skip finding fields — severity is always SKIP and is set automatically.
 * @param fn The actual survey work to run.
 */
export async function reconWrapper(
    tool: string,
    skip: Omit<ReconFinding, 'severity'>,
    fn: () => Promise<{ findings: ReconFinding[], data: unknown }>
): Promise<ReconToolResult> {
    try {
        const { findings, data } = await fn()
        return { tool, status: 'ok', findings, data }
    } catch (err) {
        if (isForbidden(err)) return { tool, status: 'skip', findings: [{ severity: 'SKIP', ...skip }], data: {} }
        return { tool, status: 'error', findings: [], data: { error: err instanceof Error ? err.message : String(err) } }
    }
}
