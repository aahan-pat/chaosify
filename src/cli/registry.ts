import { Command } from 'commander'
import { init } from './commands/setup/init.js'
import { cleanup } from './commands/setup/cleanup.js'
import { preflight } from './commands/verify/preflight.js'
import { exec } from './commands/verify/exec.js'
import { network } from './commands/verify/network.js'
import { detect } from './commands/verify/detect.js'
import { identity } from './commands/verify/identity.js'
import { run } from './commands/verify/run/index.js'
import { networkPolicies } from './commands/recon/network-policies.js'
import { nodes } from './commands/recon/nodes.js'
import { policies } from './commands/recon/policies.js'
import { psa } from './commands/recon/psa.js'
import { rbac } from './commands/recon/rbac.js'
import { runtimeAgents } from './commands/recon/runtime-agents.js'
import { topology } from './commands/recon/topology.js'
import { webhooks } from './commands/recon/webhooks.js'

// Provides a registration layer for attaching subcommands to a Commander program.
export class Registry {

    /**
     * Invokes a command factory against the given program to attach a subcommand.
     * @param program Root program.
     * @param command Command function.
     */
    register(program: Command, command: (program: Command) => void): void {
        command(program)
    }

    /**
     * Builds and returns a configured Commander program with all subcommands wired up.
     */
    static build(): Command {
        const program = new Command()
        program
            .name('chaosclaw')
            .description('Deterministic CLI for Kubernetes Continuous Control Verification')
            .version('0.1.0')

        const registry = new Registry()

        program
            .command('version')
            .description('Print the chaosclaw version')
            .action(() => console.log(`chaosclaw v${program.version()}`))

        // Register setup commands.
        const setup = program
            .command('setup')
            .description('Initialize and tear down the chaosclaw test environment')

        registry.register(setup, init)
        registry.register(setup, cleanup)

        // Register verify commands.
        const verify = program
            .command('verify')
            .description('Run security verification scenarios against the cluster')

        registry.register(verify, preflight)
        registry.register(verify, run)
        registry.register(verify, exec)
        registry.register(verify, network)
        registry.register(verify, detect)
        registry.register(verify, identity)

        // Register recon commands.
        const recon = program
            .command('recon')
            .description('Survey cluster security posture before pentest execution')

        registry.register(recon, networkPolicies)
        registry.register(recon, nodes)
        registry.register(recon, policies)
        registry.register(recon, psa)
        registry.register(recon, rbac)
        registry.register(recon, runtimeAgents)
        registry.register(recon, topology)
        registry.register(recon, webhooks)

        return program
    }
}
