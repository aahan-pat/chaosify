import { isConflict } from '../kube/errors.js'

export interface Step {
    name: string
    status: 'ok' | 'already-existed' | 'failed'
    detail?: string
}

/**
 * Runs an async operation and normalizes the result into a Step.
 * @param name Label identifying this step in the result.
 * @param fn Operation to run.
 */
export async function runStep(name: string, fn: () => Promise<void>): Promise<Step> {
    try {
        await fn()
        return { name, status: 'ok' }
    } catch (err) {
        if (isConflict(err)) return { name, status: 'already-existed' }
        return { name, status: 'failed', detail: err instanceof Error ? err.message : String(err) }
    }
}
