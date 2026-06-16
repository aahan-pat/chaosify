// TSV summary renderer for `recon ... --format summary`.
//
// Why TSV: the consumer is an AI agent's context window. A header row names each
// column once; data rows are tab-delimited (values never contain tabs, so no
// quoting). This keeps the token cost of the full `--format json` artifact down
// without losing the fields an agent acts on. Nested arrays are flattened to
// sub-delimited strings — the full typed structure is always one `--format json`
// away. Lines beginning with `#` are metadata/blind-spots; every other line is a
// data row that splits cleanly on `\t`.

import type {
    ReconToolResult,
    RbacThreatGraph,
    RbacDangerousPermission,
    NetpolThreatGraph,
    PsaThreatGraph,
    PolicyThreatGraph,
    WebhookThreatGraph,
    RuntimeThreatGraph,
    NodeInfo,
    RbacThreatSeverity,
} from '../types/recon.js'

const TAB = '\t'

/** Lowercase threat severities, ranked most-severe first for stable sorting. */
const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 }

function sevRank(s: string): number {
    return SEV_RANK[s.toLowerCase()] ?? 99
}

/** Join a row's cells with tabs, stringifying booleans/numbers. */
function row(...cells: Array<string | number | boolean>): string {
    return cells.map(c => String(c)).join(TAB)
}

/** Compact a deduped permission set to `resources:verbs; resources:verbs`. */
function joinPerms(perms: RbacDangerousPermission[]): string {
    return perms.map(p => `${p.resources.join(',')}:${p.verbs.join(',')}`).join('; ')
}

/** Append `# blindSpot:` comment lines for any blind spots. */
function appendBlindSpots(lines: string[], blindSpots: string[] | undefined): void {
    for (const b of blindSpots ?? []) lines.push(`# blindSpot: ${b}`)
}

function bySeverity<T extends { severity: RbacThreatSeverity | string }>(findings: T[]): T[] {
    return [...findings].sort((a, b) => sevRank(a.severity) - sevRank(b.severity))
}

/**
 * Renders a single recon tool result as a TSV summary string (no trailing newline).
 * Pure: takes a result, returns text — no console or process side effects.
 * @param result The recon tool result to summarise.
 */
export function buildReconSummary(result: ReconToolResult): string {
    const lines: string[] = []

    // Non-ok results carry no threat graph — surface status + finding titles only.
    if (result.status !== 'ok') {
        lines.push(`# tool=${result.tool} status=${result.status}`)
        for (const f of result.findings) lines.push(`# ${f.severity}: ${f.title}`)
        return lines.join('\n')
    }

    switch (result.tool) {
        case 'rbac': {
            const d = result.data as RbacThreatGraph
            lines.push(`# tool=rbac status=ok podsScanned=${d.podsScanned} tokensHarvested=${d.tokensHarvested}`)
            lines.push(row('sev', 'pod', 'ns', 'sa', 'crossNs', 'exploits', 'perms'))
            for (const f of bySeverity(d.findings)) {
                lines.push(row(f.severity.toUpperCase(), f.pod, f.namespace, f.serviceAccount,
                    f.crossNamespaceAccess, f.exploitClasses.join(','), joinPerms(f.dangerousPermissions)))
            }
            appendBlindSpots(lines, d.blindSpots)
            break
        }
        case 'network-policies': {
            const d = result.data as NetpolThreatGraph
            lines.push(`# tool=network-policies status=ok podsScanned=${d.podsScanned} policiesScanned=${d.policiesScanned}`)
            if (d.findings[0]) lines.push(`# note: ${d.findings[0].impact}`)
            lines.push(row('sev', 'pod', 'ns', 'podCount', 'egress', 'ingress', 'exploits', 'probe'))
            for (const f of bySeverity(d.findings)) {
                lines.push(row(f.severity.toUpperCase(), f.examplePod, f.namespace, f.podCount,
                    f.egressOpen, f.ingressOpen, f.exploitClasses.join(','), f.suggestedProbe))
            }
            appendBlindSpots(lines, d.blindSpots)
            break
        }
        case 'psa': {
            const d = result.data as PsaThreatGraph
            lines.push(`# tool=psa status=ok podsScanned=${d.podsScanned} namespacesScanned=${d.namespacesScanned}`)
            lines.push(row('sev', 'pod', 'ns', 'enforceLevel', 'confirmed', 'traits', 'exploits', 'probe'))
            for (const f of bySeverity(d.findings)) {
                lines.push(row(f.severity.toUpperCase(), f.examplePod, f.namespace, f.enforceLevel,
                    f.confirmed, f.observedTraits.join(',') || '-', f.exploitClasses.join(','), f.suggestedProbe))
            }
            appendBlindSpots(lines, d.blindSpots)
            break
        }
        case 'policies': {
            // Rows are the full policy inventory (with enforcement mode), flagged
            // where a finding marks the mode as bypassable — the complete picture
            // of what is and isn't enforced, which is the triage signal here.
            const d = result.data as PolicyThreatGraph
            lines.push(`# tool=policies status=ok engine=${d.engine} policiesScanned=${d.policiesScanned}`)
            lines.push(row('sev', 'policy', 'engine', 'mode', 'exploits'))
            for (const p of d.policies) {
                const finding = d.findings.find(f => f.policy === p.name)
                lines.push(row(finding ? finding.severity.toUpperCase() : '-', p.name, p.engine,
                    p.validationFailureAction ?? '-', finding ? finding.exploitClasses.join(',') : ''))
            }
            appendBlindSpots(lines, d.blindSpots)
            break
        }
        case 'webhooks': {
            const d = result.data as WebhookThreatGraph
            lines.push(`# tool=webhooks status=ok webhooksScanned=${d.webhooksScanned}`)
            lines.push(row('sev', 'webhook', 'type', 'scope', 'failurePolicy', 'exploits'))
            for (const w of d.webhooks) {
                const finding = d.findings.find(f =>
                    f.webhook === w.name && f.type === w.type && f.scope === w.scope && f.failurePolicy === w.failurePolicy)
                lines.push(row(finding ? finding.severity.toUpperCase() : '-', w.name, w.type, w.scope,
                    w.failurePolicy, finding ? finding.exploitClasses.join(',') : ''))
            }
            appendBlindSpots(lines, d.blindSpots)
            break
        }
        case 'runtime-agents': {
            const d = result.data as RuntimeThreatGraph
            lines.push(`# tool=runtime-agents status=ok daemonsetsScanned=${d.daemonsetsScanned} agentsDetected=${d.agentsDetected}`)
            lines.push(row('agent', 'detected', 'readyNodes', 'desiredNodes', 'namespace'))
            for (const a of d.agents) {
                lines.push(row(a.name, a.detected, a.readyNodes ?? '-', a.desiredNodes ?? '-', a.namespace ?? '-'))
            }
            for (const f of bySeverity(d.findings)) {
                lines.push(`# finding: ${f.severity.toUpperCase()} ${f.agent} ${f.exploitClasses.join(',')}`)
            }
            appendBlindSpots(lines, d.blindSpots)
            break
        }
        case 'nodes': {
            const d = result.data as { nodes: NodeInfo[] }
            lines.push(`# tool=nodes status=ok`)
            lines.push(row('name', 'os', 'kernel', 'runtime', 'appArmor', 'seccompDefault'))
            for (const n of d.nodes ?? []) {
                lines.push(row(n.name, n.os, n.kernel, n.runtime, n.appArmorEnabled, n.seccompDefault))
            }
            break
        }
        default: {
            // Unknown tool (e.g. topology when it returns ok with no schema we model).
            lines.push(`# tool=${result.tool} status=ok`)
            for (const f of result.findings) lines.push(`# ${f.severity}: ${f.title}`)
        }
    }

    return lines.join('\n')
}
