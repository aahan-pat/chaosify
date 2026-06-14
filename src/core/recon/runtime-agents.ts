import * as k8s from '@kubernetes/client-node'
import { appsV1Api } from '../kube/client.js'
import { reconWrapper } from '../utils/recon.js'
import type {
    ReconFinding,
    ReconOptions,
    ReconToolResult,
    AgentStatus,
    RuntimeThreatFinding,
    RuntimeThreatGraph,
    RuntimeThreatSeverity,
} from '../../types/recon.js'

// Re-exported for callers that still import the inventory type from this module.
export type { AgentStatus } from '../../types/recon.js'

// Well-known DaemonSet names for each runtime security agent.
const KNOWN_AGENTS: Record<string, string[]> = {
    Falco: ['falco', 'falco-falco', 'falco-node'],
    KubeArmor: ['kubearmor'],
    Tetragon: ['tetragon'],
    Tracee: ['tracee'],
}

const SEVERITY_BADGE: Record<RuntimeThreatSeverity, ReconFinding['severity']> = {
    critical: 'CRITICAL',
    high: 'HIGH',
    medium: 'WARN',
    low: 'INFO',
}

// A probe that confirms a detection actually fires, rather than assuming the agent's mere presence detects.
const DETECT_PROBE = `probe detect --pod <probe.yaml> --run "cat /etc/shadow" --expect alert_fired --alert-source`

/**
 * Builds the runtime detection threat findings from the detected agents:
 *  - partial node coverage → pods on uncovered nodes run unmonitored (detection_gap),
 *  - Falco present but no LSM-based enforcer → threats are seen but cannot be blocked (no_enforcement).
 */
function classifyAgents(agents: AgentStatus[]): RuntimeThreatFinding[] {
    const findings: RuntimeThreatFinding[] = []
    const detected = agents.filter(a => a.detected)

    for (const a of detected) {
        const ready = a.readyNodes ?? 0
        const desired = a.desiredNodes ?? 0
        if (desired > 0 && ready < desired) findings.push({
            agent: a.name,
            exploitClasses: ['detection_gap'],
            impact: `${a.name} is ready on only ${ready}/${desired} node(s) → workloads scheduled on the ${desired - ready} uncovered node(s) execute with no runtime detection. An attacker who lands on an uncovered node operates unobserved.`,
            suggestedProbe: `${DETECT_PROBE} ${a.name.toLowerCase()}`,
            severity: 'high',
        })
    }

    // Falco detects but cannot block at the kernel level; flag the absence of an LSM enforcer.
    const hasFalco = detected.some(a => a.name === 'Falco')
    const hasLsm = detected.some(a => a.name === 'KubeArmor' || a.name === 'Tetragon')
    if (hasFalco && !hasLsm) findings.push({
        agent: 'Falco',
        exploitClasses: ['no_enforcement'],
        impact: 'Falco detects threats but cannot block syscalls — KubeArmor and Tetragon are absent. A detected attack still executes; detection without enforcement only shortens response time, it does not prevent the action.',
        suggestedProbe: `${DETECT_PROBE} falco`,
        severity: 'medium',
    })

    return findings
}

/**
 * Projects the threat graph into the shared ReconFinding shape. Total absence of agents is a
 * cluster-level HIGH; otherwise a positive INFO lists what is detected, followed by each scored gap.
 */
function toReconFindings(graph: RuntimeThreatGraph): ReconFinding[] {
    if (graph.agentsDetected === 0) {
        return [{
            severity: 'HIGH',
            title: 'No runtime detection agents detected',
            detail: 'Falco, KubeArmor, Tetragon, and Tracee are all absent. Runtime behavioral detection is unavailable — nothing observes process, file, or network activity inside running pods.',
        }]
    }

    const detected = graph.agents.filter(a => a.detected)
    const summary: ReconFinding = {
        severity: 'INFO',
        title: `${detected.length} runtime agent(s) detected: ${detected.map(a => a.name).join(', ')}`,
        detail: detected.map(a => {
            const coverage = a.readyNodes === a.desiredNodes ? 'full node coverage' : `${a.readyNodes}/${a.desiredNodes} nodes ready`
            return `${a.name} (${coverage}, ns ${a.namespace})`
        }).join('; '),
    }

    const gapFindings = graph.findings.map(f => ({
        severity: SEVERITY_BADGE[f.severity],
        title: `${f.agent} — ${f.exploitClasses.join(', ')}`,
        detail: f.impact,
    }))

    return [summary, ...gapFindings]
}

/**
 * Detects installed runtime security DaemonSets and scores detection gaps: total absence, partial
 * node coverage (pods on uncovered nodes run unmonitored), and detect-only posture with no kernel
 * enforcement. Agent *presence* is never read as proof a threat is actually detected — that requires
 * probe detect, and the gap is stated as a blind spot.
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

        const findings = classifyAgents(agents)
        const order: RuntimeThreatSeverity[] = ['critical', 'high', 'medium', 'low']
        findings.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity))

        const blindSpots = [
            'Agent presence is inferred from DaemonSet name and readiness; a running DaemonSet does not prove its rules are loaded or in alert/enforce mode. Confirm an alert actually fires with probe detect.',
            'Detection rules vary — an agent may run with defaults that miss the specific techniques in runtime-baseline. "Detected" here means the agent is scheduled, not that a given threat is observed.',
            'Node coverage is taken from DaemonSet ready counts; nodes intentionally excluded by nodeSelector or taints are not distinguished from failed rollouts.',
        ]

        const graph: RuntimeThreatGraph = {
            daemonsetsScanned: daemonsets.length,
            agentsDetected: agents.filter(a => a.detected).length,
            findings,
            agents,
            blindSpots,
        }

        return { findings: toReconFindings(graph), data: graph }
    })
}
