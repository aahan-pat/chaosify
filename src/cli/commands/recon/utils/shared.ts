import { writeFile } from 'node:fs/promises'
import * as k8s from '@kubernetes/client-node'

/**
 * Loads kubeconfig, optionally switches context, and returns both the config and active context name.
 * @param context Kubernetes context to activate, uses current if omitted.
 */
export function buildKubeConfig(context?: string): { kc: k8s.KubeConfig; clusterContext: string } {
    const kc = new k8s.KubeConfig()
    kc.loadFromDefault()
    if (context) kc.setCurrentContext(context)
    return { kc, clusterContext: kc.getCurrentContext() }
}

/**
 * Serializes data as formatted JSON and writes it to a file.
 * @param filePath Destination file path.
 * @param data Data to serialize.
 */
export async function writeJsonToFile(filePath: string, data: unknown): Promise<void> {
    await writeFile(filePath, JSON.stringify(data, null, 2), 'utf-8')
}

/**
 * Writes plain text to a file (used by `--format summary` to persist the TSV artifact).
 * @param filePath Destination file path.
 * @param text Text to write; a trailing newline is ensured.
 */
export async function writeTextToFile(filePath: string, text: string): Promise<void> {
    await writeFile(filePath, text.endsWith('\n') ? text : text + '\n', 'utf-8')
}
