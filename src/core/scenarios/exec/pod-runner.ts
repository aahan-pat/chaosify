// Low-level utilities shared by probe exec, probe network, and probe detect.
// Handles pod lifecycle (submit, wait, exec with output capture) independently
// of any scenario schema or alert observation logic.
import * as k8s from '@kubernetes/client-node'
import stream from 'node:stream'

const POD_READY_POLL_INTERVAL_MS = 500
const STDOUT_MAX_BYTES = 4096
const STDERR_MAX_BYTES = 4096

export interface ExecOutcome {
    result: 'succeeded' | 'failed' | 'denied' | 'timeout'
    exitCode?: number
    stdout: string
    stderr: string
}

/**
 * Submit a Pod manifest and return the server-assigned pod name.
 * Throws if the API rejects the manifest (admission failure or API error).
 */
export async function submitPod(
    kc: k8s.KubeConfig,
    namespace: string,
    manifest: Record<string, unknown>,
): Promise<string> {
    // Build a namespaced Pod client from the active kubeconfig credentials.
    const coreApi = kc.makeApiClient(k8s.CoreV1Api)
    const created = await coreApi.createNamespacedPod({ namespace, body: manifest as k8s.V1Pod })
    // The server-assigned name is required for subsequent wait/exec/cleanup calls.
    const name = created.metadata?.name
    if (!name) throw new Error('Pod was created but the server returned no name')
    return name
}

/**
 * Poll until all containers in the pod are Running and ready.
 * Throws if the pod reaches a terminal phase (Failed/Succeeded) or the
 * timeout elapses before the pod becomes ready.
 */
export async function waitForPodRunning(
    kc: k8s.KubeConfig,
    namespace: string,
    name: string,
    timeoutMs: number,
): Promise<void> {
    const coreApi = kc.makeApiClient(k8s.CoreV1Api)
    // Record the absolute deadline so the loop terminates even if API calls are slow.
    const deadline = Date.now() + timeoutMs
    for (;;) {
        const pod = await coreApi.readNamespacedPod({ name, namespace })
        const phase = pod.status?.phase
        // Require all containers to be ready, not just the pod phase, before returning.
        const allReady = pod.status?.containerStatuses?.every(cs => cs.ready) ?? false
        if (phase === 'Running' && allReady) return
        // Terminal phases mean the pod will never become exec-able â€” bail out immediately.
        if (phase === 'Failed' || phase === 'Succeeded') {
            throw new Error(`Pod ${name} entered terminal phase ${phase} before becoming ready`)
        }
        if (Date.now() >= deadline) {
            throw new Error(`Pod ${name} did not reach Running within ${timeoutMs}ms`)
        }
        await new Promise(r => setTimeout(r, POD_READY_POLL_INTERVAL_MS))
    }
}

/**
 * Exec a command inside a running container and capture stdout + stderr.
 * Exit code 0 â†’ succeeded, non-zero â†’ failed.
 * 403 from the exec API â†’ denied (RBAC blocks pods/exec).
 * Hard timeout â†’ timeout.
 *
 * stdout and stderr are each truncated at 4KB to bound evidence artifact size.
 */
export async function execCapturing(
    kc: k8s.KubeConfig,
    namespace: string,
    podName: string,
    container: string,
    command: string[],
    timeoutMs: number,
): Promise<ExecOutcome> {
    const exec = new k8s.Exec(kc)
    let stdoutBuf = ''
    let stderrBuf = ''

    const stdoutStream = new stream.Writable({
        write(chunk: Buffer, _enc: BufferEncoding, cb: () => void) {
            stdoutBuf += (chunk as Buffer).toString()
            cb()
        },
    })
    const stderrStream = new stream.Writable({
        write(chunk: Buffer, _enc: BufferEncoding, cb: () => void) {
            stderrBuf += (chunk as Buffer).toString()
            cb()
        },
    })

    return new Promise<ExecOutcome>((resolve, reject) => {
        // Resolve as 'timeout' after timeoutMs so the caller always gets a result within the budget.
        const timer = setTimeout(() => {
            resolve({
                result: 'timeout',
                stdout: stdoutBuf.slice(0, STDOUT_MAX_BYTES),
                stderr: stderrBuf.slice(0, STDERR_MAX_BYTES),
            })
        }, timeoutMs)

        exec.exec(
            namespace, podName, container, command,
            stdoutStream, stderrStream,
            null,  // stdin
            false, // tty
            (status: k8s.V1Status) => {
                clearTimeout(timer)
                // Extract the numeric exit code from the status cause list; fall back to 0 on Success.
                const exitCodeStr = status.details?.causes?.find(c => c.reason === 'ExitCode')?.message
                const exitCode = exitCodeStr !== undefined
                    ? parseInt(exitCodeStr, 10)
                    : (status.status === 'Success' ? 0 : 1)
                resolve({
                    result: exitCode === 0 ? 'succeeded' : 'failed',
                    exitCode,
                    // Truncate output to avoid bloating the evidence artifact with excessive output.
                    stdout: stdoutBuf.slice(0, STDOUT_MAX_BYTES),
                    stderr: stderrBuf.slice(0, STDERR_MAX_BYTES),
                })
            },
        ).catch((err: unknown) => {
            clearTimeout(timer)
            // A 403 from the exec endpoint means RBAC blocks pods/exec â€” report it as 'denied'
            // so the caller can distinguish an access control finding from an infrastructure failure.
            const statusCode = (err as { statusCode?: number }).statusCode
                ?? (err as { code?: number }).code
            if (statusCode === 403) {
                resolve({
                    result: 'denied',
                    stdout: stdoutBuf.slice(0, STDOUT_MAX_BYTES),
                    stderr: stderrBuf.slice(0, STDERR_MAX_BYTES),
                })
            } else {
                reject(err instanceof Error ? err : new Error(String(err)))
            }
        })
    })
}

/** Inject namespace + generateName so test pods get unique, trackable names */
export function injectNamespace(
    manifest: Record<string, unknown>,
    namespace: string,
): Record<string, unknown> {
    const meta = (manifest['metadata'] as Record<string, unknown> | undefined) ?? {}
    return {
        ...manifest,
        metadata: { ...meta, namespace, generateName: 'chaosify-test-', name: undefined },
    }
}

/** Create the test namespace if it does not already exist (409 = already exists, ignored) */
export async function ensureNamespace(kc: k8s.KubeConfig, namespace: string): Promise<void> {
    const coreApi = kc.makeApiClient(k8s.CoreV1Api)
    try {
        await coreApi.createNamespace({ body: { apiVersion: 'v1', kind: 'Namespace', metadata: { name: namespace } } })
    } catch (err: unknown) {
        // 409 Conflict means the namespace already exists â€” that is the desired state, so ignore it.
        const code = (err as { code?: number }).code ?? (err as { statusCode?: number }).statusCode
        if (code !== 409) throw err
    }
}

/** Load and parse a Pod manifest file (YAML or JSON). Exits with code 4 on any error. */
export async function loadPodManifest(filePath: string): Promise<Record<string, unknown>> {
    const { readFile } = await import('node:fs/promises')
    let content: string
    try {
        content = await readFile(filePath, 'utf-8')
    } catch {
        // Exit immediately with a user-friendly message instead of throwing an unhandled error.
        console.error(`\nError\n  Could not read pod manifest: ${filePath}`)
        process.exit(4)
    }

    let parsed: unknown
    try {
        // Use the Kubernetes client's YAML parser so both YAML and JSON manifests are accepted.
        parsed = k8s.loadYaml(content)
    } catch {
        console.error(`\nError\n  Could not parse manifest (expected YAML or JSON): ${filePath}`)
        process.exit(4)
    }

    if (!parsed || typeof parsed !== 'object') {
        console.error(`\nError\n  Manifest is empty or not a valid object: ${filePath}`)
        process.exit(4)
    }

    // Enforce Pod-only constraint before returning, since the executor only supports Pod creation.
    const manifest = parsed as Record<string, unknown>
    if (manifest['kind'] !== 'Pod') {
        console.error(`\nError\n  Only Pod manifests are supported. Found kind: ${manifest['kind'] ?? 'unknown'}`)
        process.exit(4)
    }

    return manifest
}

/** Return the name of the first container in the pod spec, or undefined if the spec is missing */
export function resolveFirstContainer(manifest: Record<string, unknown>): string | undefined {
    const spec = manifest['spec'] as Record<string, unknown> | undefined
    const containers = spec?.['containers'] as Array<{ name?: string }> | undefined
    return containers?.[0]?.name
}
