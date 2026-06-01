import { spawn, type SpawnOptions } from 'node:child_process'
import { existsSync, readdirSync } from 'node:fs'
import type { ReconOptions, ReconToolResult } from '../../types/recon.js'

const GRAPH_DIR = 'graphnetes-out'
const GRAPH_PATH = `${GRAPH_DIR}/graph.json`
export const GRAPHNETES_REPO = 'https://github.com/aahan-pat/graphnetes'

/**
 * Wraps spawn in a promise, optionally streaming child output to the terminal.
 * @param cmd Binary to execute.
 * @param args Arguments to pass.
 * @param silent Suppress stdout/stderr — use when caller owns the terminal output.
 */
function spawnAsync(cmd: string, args: string[], silent: boolean): Promise<void> {
    return new Promise((resolve, reject) => {
        // Silence child output in json mode so it doesn't corrupt machine-readable stdout.
        const opts: SpawnOptions = { stdio: silent ? ['ignore', 'ignore', 'pipe'] : ['ignore', 'inherit', 'inherit'] }
        const child = spawn(cmd, args, opts)

        // Capture stderr when silent so we can include it in error messages.
        let stderrBuf = ''
        child.stderr?.on('data', (chunk: Buffer) => { stderrBuf += chunk.toString() })

        // Forward Ctrl+C to the child so both processes exit cleanly together.
        const forwardSigint = () => child.kill('SIGINT')
        process.on('SIGINT', forwardSigint)

        // Kill the child after 60 s and surface a clear timeout message.
        const timeout = setTimeout(() => {
            child.kill('SIGTERM')
            reject(new Error('graphnetes build timed out after 60 seconds'))
        }, 60_000)

        child.on('error', (err: NodeJS.ErrnoException) => {
            clearTimeout(timeout)
            process.off('SIGINT', forwardSigint)
            // ENOENT means the binary is not on PATH — propagate the code so callers can detect it.
            reject(Object.assign(new Error(err.message), { code: err.code }))
        })

        child.on('close', (code: number | null) => {
            clearTimeout(timeout)
            process.off('SIGINT', forwardSigint)
            if (code === 0) return resolve()
            const detail = stderrBuf.trim() ? `: ${stderrBuf.trim()}` : ''
            reject(new Error(`graphnetes exited with code ${code}${detail}`))
        })
    })
}

/**
 * Runs graphnetes build and returns the list of artifacts it created.
 * @param graphPath Path to an existing graph.json — skips the build step when provided.
 * @param options Recon options containing namespace and optional context.
 * @param silent Suppress graphnetes output — set true when the caller owns stdout (e.g. json format).
 */
export async function surveyTopology(
    graphPath: string | undefined,
    options: ReconOptions,
    silent: boolean,
): Promise<ReconToolResult> {
    if (graphPath) {
        // Caller supplied an existing graph — validate the path before returning.
        if (!existsSync(graphPath)) {
            return { tool: 'topology', status: 'error', findings: [], data: { error: `Graph file not found: ${graphPath}` } }
        }
        const artifacts = [graphPath]
        return { tool: 'topology', status: 'ok', findings: [], data: { artifacts } }
    }

    const args = ['build']
    if (options.namespace) args.push('--namespace', options.namespace)
    if (options.context) args.push('--context', options.context)

    try {
        await spawnAsync('graphnetes', args, silent)
    } catch (err) {
        const e = err as NodeJS.ErrnoException
        // ENOENT means graphnetes is not installed — return skip so the CLI can prompt the user.
        if (e.code === 'ENOENT') {
            return {
                tool: 'topology',
                status: 'skip',
                findings: [],
                data: {},
            }
        }
        return { tool: 'topology', status: 'error', findings: [], data: { error: e.message } }
    }

    if (!existsSync(GRAPH_PATH)) {
        return { tool: 'topology', status: 'error', findings: [], data: { error: `graphnetes exited successfully but ${GRAPH_PATH} was not created` } }
    }

    // Enumerate all files written to graphnetes-out/ so the CLI can surface them as artifacts.
    const artifacts = readdirSync(GRAPH_DIR).map(f => `${GRAPH_DIR}/${f}`)
    return { tool: 'topology', status: 'ok', findings: [], data: { artifacts } }
}
