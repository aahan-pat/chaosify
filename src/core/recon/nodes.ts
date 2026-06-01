import * as k8s from '@kubernetes/client-node'
import { coreV1Api } from '../kube/client.js'
import { reconWrapper } from '../utils/recon.js'
import type { ReconFinding, ReconOptions, ReconToolResult } from '../../types/recon.js'

export interface NodeInfo {
    name: string
    os: string
    kernel: string
    runtime: string
    appArmorEnabled: boolean
    seccompDefault: string
}

// Extracts a flat NodeInfo summary from the Kubernetes node status and annotation fields.
function extractNodeInfo(node: k8s.V1Node): NodeInfo {
    const info = node.status?.nodeInfo
    return {
        name: node.metadata?.name ?? 'unknown',
        os: info?.osImage ?? 'unknown',
        kernel: info?.kernelVersion ?? 'unknown',
        runtime: info?.containerRuntimeVersion ?? 'unknown',
        // AppArmor presence is surfaced via node annotations in some distributions.
        appArmorEnabled: Object.keys(node.metadata?.annotations ?? {}).some(k => k.toLowerCase().includes('apparmor')),
        seccompDefault: 'runtime/default',
    }
}

function analyze(nodes: NodeInfo[]): ReconFinding[] {
    if (nodes.length === 0) return []

    // Count occurrences of each kernel version to identify the fleet-dominant version.
    const kernelCounts = new Map<string, number>()
    for (const n of nodes) kernelCounts.set(n.kernel, (kernelCounts.get(n.kernel) ?? 0) + 1)

    // Sort descending so the most-common kernel is first.
    const [[dominantKernel] = []] = [...kernelCounts.entries()].sort((a, b) => b[1] - a[1])
    if (!dominantKernel) return []

    // Nodes on a different kernel may have different security capabilities or vulnerability exposure.
    const outliers = nodes.filter(n => n.kernel !== dominantKernel)
    if (outliers.length === 0) return []

    return [{
        severity: 'INFO',
        title: `${outliers.length} node(s) running a different kernel version`,
        detail: outliers.map(n => `${n.name}: kernel ${n.kernel}, runtime ${n.runtime}`).join('; '),
    }]
}

/**
 * Surveys cluster nodes for kernel version, container runtime, and security feature support.
 * @param kc Loaded kubeconfig to use for all API calls.
 * @param options Recon options containing namespace and optional context.
 */
export function surveyNodes(kc: k8s.KubeConfig, options: ReconOptions): Promise<ReconToolResult> {
    const core = coreV1Api(kc)
    return reconWrapper('nodes', {
        title: 'Node recon skipped',
        detail: 'Cannot list nodes — insufficient permissions',
        missingPermission: 'list nodes',
        coverageImpact: 'Node kernel versions, container runtimes, and security feature support cannot be assessed',
    }, async () => {
        const nodes = (await core.listNode()).items.map(extractNodeInfo)
        return { findings: analyze(nodes), data: { nodes } }
    })
}
