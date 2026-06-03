// Implements “chaosclaw probe identity” — the RBAC capability primitive.
// Tests what a specific service account is actually authorized to do by issuing
// a SubjectAccessReview against the Kubernetes API.
// No pod is created; this is a pure API call. Runtime detection does not apply.
import * as k8s from '@kubernetes/client-node'
import type { Command } from 'commander'
import { EvidenceBuilder } from '../../../core/teardown/evidence-builder.js'
import { header, field, section, indent, outcomeLabel, blank } from '../../output.js'
import { buildKubeConfig } from '../recon/utils/shared.js'
import { DEFAULT_PROBE_NAMESPACE } from './utils/shared.js'

const VALID_EXPECTS = ['allowed', 'denied'] as const
type IdentityExpect = (typeof VALID_EXPECTS)[number]

/**
 * Attaches the "identity" subcommand to the probe command group.
 * @param probe The probe command group to attach to.
 */
export function identity(probe: Command): void {
    probe
        .command('identity')
        .description('Test what a service account is authorized to do via SubjectAccessReview')
        .requiredOption('--as <sa-name>', 'Service account name to test')
        .requiredOption('--can <verb>', 'Verb to test: get, list, create, delete, *, exec, etc.')
        .requiredOption('--resource <resource>', 'Resource to test: secrets, pods, pods/exec, clusterrolebindings, etc.')
        .option('--resource-namespace <ns>', 'Namespace to scope the permission check (omit for cluster-scoped check)')
        .option('--group <api-group>', 'API group of the resource (default: "" for core resources; use rbac.authorization.k8s.io for RBAC resources)')
        .requiredOption('--expect <outcome>', 'Expected outcome: allowed, denied')
        .option('--context <name>', 'Kubernetes context to use')
        .option('--namespace <name>', 'Namespace the service account lives in', DEFAULT_PROBE_NAMESPACE)
        .option('--output <path>', 'Write JSON evidence artifact to file')
        .option('--format <mode>', 'Output mode: table, json', 'table')
        .action(async (opts: {
            as: string
            can: string
            resource: string
            resourceNamespace?: string
            group?: string
            expect: string
            context?: string
            namespace: string
            output?: string
            format: string
        }) => {
            if (!VALID_EXPECTS.includes(opts.expect as IdentityExpect)) {
                console.error(`\nError\n  --expect must be one of: ${VALID_EXPECTS.join(', ')}. Got: "${opts.expect}"`)
                process.exit(4)
            }

            const { kc, clusterContext } = buildKubeConfig(opts.context)

            // Split 'pods/exec' into resource='pods', subresource='exec' for the SubjectAccessReview spec.
            const [resource, subresource] = opts.resource.includes('/')
                ? opts.resource.split('/', 2) as [string, string | undefined]
                : [opts.resource, undefined]

            // Build the fully-qualified service account user string expected by the authorization API.
            const saUser = `system:serviceaccount:${opts.namespace}:${opts.as}`
            const scenarioId = `identity:${opts.as}/${opts.can}/${opts.resource}`
            const startedAt = new Date().toISOString()
            const builder = new EvidenceBuilder({ clusterContext, startedAt })

            if (opts.format !== 'json') {
                header('ChaosClaw Identity')
                field('Cluster Context', clusterContext)
                field('Service Account', saUser)
                field('Verb', opts.can)
                field('Resource', opts.resource)
                if (opts.resourceNamespace) field('Resource Namespace', opts.resourceNamespace)
                if (opts.group) field('API Group', opts.group)
                field('Expect', opts.expect)
                section('Running')
            }

            let observedOutcome: string
            let likelyIssue: string | undefined
            let rawResponse: string

            try {
                // Issue a SubjectAccessReview to ask the API server what the target SA is allowed to do.
                const authApi = kc.makeApiClient(k8s.AuthorizationV1Api)
                const review = await authApi.createSubjectAccessReview({
                    body: {
                        apiVersion: 'authorization.k8s.io/v1',
                        kind: 'SubjectAccessReview',
                        spec: {
                            user: saUser,
                            resourceAttributes: {
                                namespace: opts.resourceNamespace,
                                verb: opts.can,
                                resource,
                                subresource,
                                group: opts.group ?? '',
                            },
                        },
                    },
                })

                // Translate the API response into a simple allowed/denied observation.
                const allowed = review.status?.allowed === true
                observedOutcome = allowed ? 'allowed' : 'denied'
                rawResponse = JSON.stringify({
                    serviceAccount: saUser,
                    verb: opts.can,
                    resource: opts.resource,
                    resourceNamespace: opts.resourceNamespace,
                    allowed,
                    evaluationError: review.status?.evaluationError,
                })
            } catch (err: unknown) {
                const statusCode = (err as { statusCode?: number }).statusCode ?? (err as { code?: number }).code
                if (statusCode === 403) {
                    // 403 on the SubjectAccessReview endpoint means our credentials lack permission to ask the question.
                    console.error('\nError\n  Insufficient permissions to create SubjectAccessReview')
                    console.error('  This requires: create subjectaccessreviews (authorization.k8s.io)')
                    process.exit(2)
                }
                observedOutcome = 'api_error'
                rawResponse = err instanceof Error ? err.message : String(err)
                likelyIssue = 'Kubernetes API error â€” check cluster connectivity and RBAC'
            }

            // Map the observed outcome to Pass/Fail/Error by comparing against the expected value.
            const status = observedOutcome === 'api_error' ? 'Error' as const
                : observedOutcome === opts.expect ? 'Pass' as const
                : 'Fail' as const

            if (status === 'Fail') likelyIssue = diagnoseIdentity(opts.expect as IdentityExpect, observedOutcome, opts.as, opts.can, opts.resource)

            const result = {
                scenarioId,
                version: 1,
                status,
                expectedOutcome: opts.expect,
                observedOutcome,
                cleanupStatus: 'skipped' as const,
                startedAt,
                endedAt: new Date().toISOString(),
                rawResponse,
                likelyIssue,
            }

            builder.addResult(result)
            const evidence = builder.build(new Date().toISOString())

            if (opts.format === 'json') {
                console.log(JSON.stringify(evidence, null, 2))
                process.exit(status === 'Pass' ? 0 : 1)
            }

            indent(`${outcomeLabel(result.status)} ${scenarioId}`)

            section('Summary')
            indent(`Status:          ${status}`)
            indent(`Service Account: ${saUser}`)
            indent(`Permission:      ${opts.can} ${opts.resource}${opts.resourceNamespace ? ` in ${opts.resourceNamespace}` : ' (cluster-scoped)'}`)
            indent(`Expected:        ${opts.expect}`)
            indent(`Observed:        ${observedOutcome}`)
            if (likelyIssue) indent(`Issue:           ${likelyIssue}`)

            if (opts.output) {
                await builder.writeToFile(opts.output, evidence)
                section('Artifacts')
                indent(`JSON report written to: ${opts.output}`)
            }

            blank()
            process.exit(status === 'Pass' ? 0 : 1)
        })
}

// Return a targeted diagnostic message based on whether the SA has more or fewer permissions than expected.
function diagnoseIdentity(expected: IdentityExpect, observed: string, sa: string, verb: string, resource: string): string {
    if (expected === 'denied' && observed === 'allowed') {
        return `${sa} can ${verb} ${resource} â€” RBAC grants more permission than expected`
    }
    if (expected === 'allowed' && observed === 'denied') {
        return `${sa} cannot ${verb} ${resource} â€” check RoleBinding or ClusterRoleBinding`
    }
    return 'Unexpected outcome â€” inspect the raw response for details'
}
