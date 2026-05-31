import * as k8s from '@kubernetes/client-node'
import { Writable } from 'stream'

export interface ExecResult {
    stdout: string
    stderr: string
    exitCode: number
}

/**
 * Submits a pod manifest to the cluster and returns the created pod object.
 * @param api CoreV1Api client to use.
 * @param namespace Namespace to create the pod in.
 * @param manifest Pod manifest to submit.
 */
export async function submitPod(api: k8s.CoreV1Api, namespace: string, manifest: k8s.V1Pod): Promise<k8s.V1Pod> {
    const { body } = await api.createNamespacedPod({ namespace, body: manifest })
    return body
}

/**
 * Polls pod status until it reaches Running phase or the timeout elapses.
 * @param api CoreV1Api client to use.
 * @param namespace Namespace the pod lives in.
 * @param name Pod name to watch.
 * @param timeoutMs Maximum wait time in milliseconds.
 */
export async function waitForReady(api: k8s.CoreV1Api, namespace: string, name: string, timeoutMs = 30_000): Promise<void> {
    const deadline = Date.now() + timeoutMs
    while (Date.now() < deadline) {
        const { body } = await api.readNamespacedPodStatus({ name, namespace })
        if (body.status?.phase === 'Running') return
        // Wait 1s between polls to avoid hammering the API server.
        await new Promise(r => setTimeout(r, 1_000))
    }
    throw new Error(`Pod ${name} did not reach Running state within ${timeoutMs}ms`)
}

/**
 * Execs a command inside a running pod container and captures stdout, stderr, and exit code.
 * @param kc Loaded kubeconfig used to open the exec WebSocket.
 * @param namespace Namespace the pod lives in.
 * @param pod Pod name to exec into.
 * @param container Container name within the pod.
 * @param command Command and arguments to run.
 */
export async function execInPod(kc: k8s.KubeConfig, namespace: string, pod: string, container: string, command: string[]): Promise<ExecResult> {
    const exec = new k8s.Exec(kc)
    let stdout = ''
    let stderr = ''

    // Capture stdout and stderr into strings via writable streams.
    const outStream = new Writable({ write(chunk, _enc, cb) { stdout += chunk.toString(); cb() } })
    const errStream = new Writable({ write(chunk, _enc, cb) { stderr += chunk.toString(); cb() } })

    // Wrap the WebSocket-based exec call in a Promise that resolves with the exit code.
    const exitCode = await new Promise<number>((resolve, reject) => {
        exec.exec(namespace, pod, container, command, outStream, errStream, null, false, (status) => {
            if (status.status === 'Success') resolve(0)
            else resolve(Number(status.details?.causes?.[0]?.message ?? 1))
        }).catch(reject)
    })

    return { stdout, stderr, exitCode }
}

/**
 * Deletes a pod from the namespace.
 * @param api CoreV1Api client to use.
 * @param namespace Namespace the pod lives in.
 * @param name Pod name to delete.
 */
export async function deletePod(api: k8s.CoreV1Api, namespace: string, name: string): Promise<void> {
    await api.deleteNamespacedPod({ name, namespace })
}
