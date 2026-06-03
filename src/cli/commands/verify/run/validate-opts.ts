export interface RunOpts {
    pack?: string
    scenario?: string
    manifest?: string
    expect?: string
    context?: string
    namespace: string
    alertSource: string
    output?: string
    format: string
    timeout?: string
    failFast?: boolean
    cleanup: string
    verbose?: boolean
}

export function validateOpts(opts: RunOpts): void {
    const targetCount = [opts.pack, opts.scenario, opts.manifest].filter(Boolean).length
    if (targetCount === 0) {
        console.error('\nError\n  Missing required target: specify exactly one of --pack, --scenario, or --manifest')
        console.error('\nExamples')
        console.error('  chaosclaw probe run --pack preventive-baseline')
        console.error('  chaosclaw probe run --pack runtime-baseline --alert-source none')
        console.error('  chaosclaw probe run --scenario deny-hostpath')
        console.error('  chaosclaw probe run --manifest ./my-pod.yaml --expect rejected')
        process.exit(4)
    }
    if (targetCount > 1) {
        console.error('\nError\n  Specify exactly one of --pack, --scenario, or --manifest')
        process.exit(4)
    }
    if (opts.manifest && !opts.expect) {
        console.error('\nError\n  --expect is required when using --manifest (values: rejected, allowed)')
        process.exit(4)
    }
    if (opts.manifest && opts.expect !== 'rejected' && opts.expect !== 'allowed') {
        console.error(`\nError\n  --expect must be "rejected" or "allowed", got "${opts.expect}"`)
        process.exit(4)
    }
}
