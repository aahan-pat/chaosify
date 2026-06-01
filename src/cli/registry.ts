import { Command } from 'commander'
import { init } from './commands/recon/init.js'
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

        const recon = program
            .command('recon')
            .description('Survey cluster security posture before pentest execution')

        // Register commands here.
        registry.register(recon, init)
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
