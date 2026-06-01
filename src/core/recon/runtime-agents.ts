import * as k8s from '@kubernetes/client-node'
import { appsV1Api } from '../kube/client.js'
import { reconWrapper } from '../utils/recon.js'
import type { ReconFinding, ReconOptions, ReconToolResult } from '../../types/recon.js'

export interface AgentStatus {
    name: string
    detected: boolean
    readyNodes?: number
    desiredNodes?: number
    namespace?: string
}

// Well-known DaemonSet names for each runtime security agent.
const KNOWN_AGENTS: Record<string, string[]> = {
    Falco: ['falco', 'falco-falco', 'falco-node'],
    KubeArmor: ['kubearmor'],
    Tetragon: ['tetragon'],
    Tracee: ['tracee'],
}

function analyze(agents: AgentStatus[]): ReconFinding[] {
    const findings: ReconFinding[] = []
    const detected = agents.filter(a => a.detected)

    // No agents at all is a HIGH finding — runtime behavioral detection is completely absent.
    if (detected.length === 0) {
        findings.push({
            severity: 'HIGH',
            title: 'No runtime detection agents detected',
            detail: 'Falco, KubeArmor, Tetragon, and Tracee are all absent. Runtime behavioral detection is unavailable.',
        })
        return findings
    }

    // Report each detected agent with its node coverage.
    for (const agent of detected) {
        const coverage = agent.readyNodes === agent.desiredNodes
            ? 'full node coverage'
            : `${agent.readyNodes}/${agent.desiredNodes} nodes ready`
        findings.push({
            severity: 'INFO',
            title: `${agent.name} detected (${coverage})`,
            detail: `Deployed in namespace: ${agent.namespace}`,
        })
    }

    // Falco detects only — warn when no LSM-capable enforcement tool is present alongside it.
    const hasFalco = agents.find(a => a.name === 'Falco')?.detected
    const hasLsm = agents.find(a => a.name === 'KubeArmor')?.detected || agents.find(a => a.name === 'Tetragon')?.detected
    if (hasFalco && !hasLsm) findings.push({
        severity: 'WARN',
        title: 'No LSM-based runtime enforcement detected',
        detail: 'KubeArmor and Tetragon are absent. Falco detects threats but cannot block syscalls at the kernel level.',
    })

    return findings
}

/**
 * Detects installed runtime security DaemonSets and reports node coverage per agent.
 * @param kc Loaded kubeconfig to use for all API calls.
 * @param options Recon options containing namespace and optional context.
 */
export function surveyRuntimeAgents(kc: k8s.KubeConfig, options: ReconOptions): Promise<ReconToolResult> {
    const apps = appsV1Api(kc)
    return reconWrapper('runtime-agents', {
        title: 'Runtime agent recon skipped',
        detail: 'Cannot list DaemonSets cluster-wide — insufficient permissions',
        missingPermission: 'list daemonsets (all namespaces)',
        coverageImpact: 'Runtime detection agent presence cannot be confirmed',
    }, async () => {
        const daemonsets = (await apps.listDaemonSetForAllNamespaces()).items

        // Match each known agent against the DaemonSet inventory and capture readiness counts.
        const agents: AgentStatus[] = Object.entries(KNOWN_AGENTS).map(([agentName, knownNames]) => {
            const ds = daemonsets.find(d => knownNames.includes(d.metadata?.name ?? ''))
            if (!ds) return { name: agentName, detected: false }
            return {
                name: agentName,
                detected: true,
                readyNodes: ds.status?.numberReady ?? 0,
                desiredNodes: ds.status?.desiredNumberScheduled ?? 0,
                namespace: ds.metadata?.namespace ?? 'unknown',
            }
        })

        return { findings: analyze(agents), data: { daemonsetsScanned: daemonsets.length, agents } }
    })
}
