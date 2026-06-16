import { describe, it, expect } from 'vitest'
import { buildReconSummary } from '../../../src/cli/recon-summary.js'
import type { ReconToolResult } from '../../../src/types/recon.js'

// buildReconSummary is pure (result → TSV text), so these drive it with
// hand-built threat graphs and assert the structural guarantees: deduped/compact
// rows, `#` metadata lines, a single column header, and tab-splittable data rows.

/** Lines that are not `#` comments must all split into the same number of cells. */
function dataRows(text: string): string[][] {
    return text.split('\n').filter(l => l && !l.startsWith('#')).map(l => l.split('\t'))
}

describe('buildReconSummary', () => {
    it('rbac: one row per finding with compacted perms, header + blindSpots as comments', () => {
        const result: ReconToolResult = {
            tool: 'rbac',
            status: 'ok',
            findings: [],
            data: {
                podsScanned: 10,
                tokensHarvested: 3,
                blindSpots: ['roles unbound are out of scope'],
                findings: [{
                    pod: 'attacker-pod', namespace: 'pentest-lab', serviceAccount: 'privileged-sa',
                    automountToken: true, tokenHarvested: true,
                    exploitClasses: ['privilege_escalation', 'secret_access'],
                    dangerousPermissions: [
                        { resources: ['pods', 'pods/exec'], verbs: ['get', 'create'], apiGroups: [''], exploitClasses: ['privilege_escalation'] },
                        { resources: ['secrets', 'configmaps'], verbs: ['get', 'list'], apiGroups: [''], exploitClasses: ['secret_access'] },
                    ],
                    attackChain: 'noise that should be dropped from the summary',
                    severity: 'critical', crossNamespaceAccess: false,
                }],
            },
        }
        const out = buildReconSummary(result)
        expect(out).toContain('# tool=rbac status=ok podsScanned=10 tokensHarvested=3')
        // header + exactly one data row
        const rows = dataRows(out)
        expect(rows).toHaveLength(2)
        expect(rows[0]).toEqual(['sev', 'pod', 'ns', 'sa', 'crossNs', 'exploits', 'perms'])
        expect(rows[1]![0]).toBe('CRITICAL')
        // perms compacted to `resources:verbs; resources:verbs`
        expect(rows[1]![6]).toBe('pods,pods/exec:get,create; secrets,configmaps:get,list')
        // narrative prose is not carried into the summary
        expect(out).not.toContain('noise that should be dropped')
        expect(out).toContain('# blindSpot: roles unbound are out of scope')
    })

    it('all data rows have the same column count as the header (tab-splittable)', () => {
        const result: ReconToolResult = {
            tool: 'network-policies', status: 'ok', findings: [],
            data: {
                podsScanned: 5, policiesScanned: 7, blindSpots: [],
                findings: [
                    { namespace: 'a', examplePod: 'pa', podCount: 1, egressOpen: true, ingressOpen: true, exploitClasses: ['metadata_exposure'], impact: 'same impact', suggestedProbe: 'probe x', severity: 'high' },
                    { namespace: 'b', examplePod: 'pb', podCount: 2, egressOpen: true, ingressOpen: false, exploitClasses: ['lateral_movement'], impact: 'same impact', suggestedProbe: 'probe y', severity: 'high' },
                ],
            },
        }
        const out = buildReconSummary(result)
        // shared impact hoisted to a single note line, not repeated per row
        expect(out.match(/# note: same impact/g)).toHaveLength(1)
        const rows = dataRows(out)
        const width = rows[0]!.length
        for (const r of rows) expect(r).toHaveLength(width)
    })

    it('policies: inventory rows carry enforcement mode and flag bypassable ones', () => {
        const result: ReconToolResult = {
            tool: 'policies', status: 'ok', findings: [],
            data: {
                engine: 'kyverno', policiesScanned: 2, blindSpots: [],
                policies: [
                    { name: 'disallow-host-path', engine: 'kyverno', validationFailureAction: 'Enforce' },
                    { name: 'require-run-as-nonroot', engine: 'kyverno', validationFailureAction: 'Audit' },
                ],
                findings: [
                    { policy: 'require-run-as-nonroot', engine: 'kyverno', exploitClasses: ['admission_bypass'], impact: '', suggestedProbe: '', severity: 'high' },
                ],
            },
        }
        const out = buildReconSummary(result)
        const rows = dataRows(out)
        expect(rows).toContainEqual(['-', 'disallow-host-path', 'kyverno', 'Enforce', ''])
        expect(rows).toContainEqual(['HIGH', 'require-run-as-nonroot', 'kyverno', 'Audit', 'admission_bypass'])
    })

    it('non-ok status emits only a status line and finding titles', () => {
        const result: ReconToolResult = {
            tool: 'topology', status: 'skip',
            findings: [{ severity: 'SKIP', title: 'graphnetes not installed', detail: 'd' }],
            data: {},
        }
        const out = buildReconSummary(result)
        expect(out).toContain('# tool=topology status=skip')
        expect(out).toContain('# SKIP: graphnetes not installed')
        // no TSV data rows for a skip
        expect(dataRows(out)).toHaveLength(0)
    })

    it('byte-budget guard: a 3-finding rbac graph summarises to <= 12 lines', () => {
        const mk = (pod: string) => ({
            pod, namespace: 'ns', serviceAccount: 'sa', automountToken: true, tokenHarvested: true,
            exploitClasses: ['secret_access' as const],
            dangerousPermissions: [{ resources: ['secrets'], verbs: ['get'], apiGroups: [''], exploitClasses: ['secret_access' as const] }],
            attackChain: 'x', severity: 'high' as const, crossNamespaceAccess: false,
        })
        const result: ReconToolResult = {
            tool: 'rbac', status: 'ok', findings: [],
            data: { podsScanned: 3, tokensHarvested: 3, blindSpots: ['one'], findings: [mk('p1'), mk('p2'), mk('p3')] },
        }
        expect(buildReconSummary(result).split('\n').length).toBeLessThanOrEqual(12)
    })
})
