import * as k8s from '@kubernetes/client-node'
import type { RuntimeAlertSource } from './types.js'
import { NullAlertSource } from './adapters/null.js'
import { FalcoAlertSource } from './adapters/falco.js'
import { TetragonAlertSource } from './adapters/tetragon.js'
import { KubeArmorAlertSource } from './adapters/kubearmor.js'

type AlertSourceFactory = (kc: k8s.KubeConfig) => RuntimeAlertSource

// Provides a registration layer for mapping tool names to alert source factories.
export class AlertSourceRegistry {

    private readonly sources = new Map<string, AlertSourceFactory>()

    /**
     * Registers a named alert source factory.
     * @param name Tool name used on the CLI (e.g. 'falco').
     * @param factory Function that constructs the source given a kubeconfig.
     */
    register(name: string, factory: AlertSourceFactory): void {
        this.sources.set(name, factory)
    }

    /**
     * Creates an alert source for the given tool name.
     * Falls back to NullAlertSource when the name is unrecognised or 'none'.
     * @param name Tool name from CLI flags.
     * @param kc Loaded kubeconfig to pass to the factory.
     */
    create(name: string, kc: k8s.KubeConfig): RuntimeAlertSource {
        return this.sources.get(name)?.(kc) ?? new NullAlertSource()
    }

    /**
     * Builds and returns a registry with all built-in alert sources registered.
     */
    static build(): AlertSourceRegistry {
        const registry = new AlertSourceRegistry()

        // Register alert sources here
        registry.register('falco',     kc => new FalcoAlertSource(kc))
        registry.register('tetragon',  kc => new TetragonAlertSource(kc))
        registry.register('kubearmor', kc => new KubeArmorAlertSource(kc))

        return registry
    }
}
