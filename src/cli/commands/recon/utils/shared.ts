import { writeFile } from 'node:fs/promises'
import * as k8s from '@kubernetes/client-node'

export const DEFAULT_RECON_NAMESPACE = 'chaosify'

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
