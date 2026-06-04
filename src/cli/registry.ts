import { Command } from 'commander'
import { init } from './commands/setup/init.js'
import { cleanup } from './commands/setup/cleanup.js'
import { list } from './commands/scenarios/list.js'
import { show } from './commands/scenarios/show.js'
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
            .name('chaosify')
            .description('Deterministic CLI for Kubernetes Continuous Control Verification')
            .version('0.1.0')

        const registry = new Registry()

        program
            .command('version')
            .description('Print the chaosify version')
            .action(() => console.log(`chaosify v${program.version()}`))

        // Register setup commands.
        const setup = program
            .command('setup')
            .description('Initialize and tear down the chaosify test environment')

        registry.register(setup, init)
        registry.register(setup, cleanup)

        // Register scenarios commands.
        const scenarios = program
            .command('scenarios')
            .description('Discover and inspect available scenario packs and scenarios')

        registry.register(scenarios, list)
        registry.register(scenarios, show)

        // Register probe commands.
        const probe = program
            .command('probe')
            .description('Execute attack primitives and scenario packs against the cluster')

        registry.register(probe, preflight)
        registry.register(probe, run)
        registry.register(probe, exec)
        registry.register(probe, network)
        registry.register(probe, detect)
        registry.register(probe, identity)

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
