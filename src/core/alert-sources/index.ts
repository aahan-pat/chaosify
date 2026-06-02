import * as k8s from '@kubernetes/client-node'
import type { RuntimeAlertSource } from './types.js'
import { AlertSourceRegistry } from './registry.js'

export { AlertSourceRegistry }
export type { RuntimeAlertSource }
export type { RuntimeAlert } from './types.js'

// Module-level default registry — built once and reused across all calls.
const defaultRegistry = AlertSourceRegistry.build()

/**
 * Creates an alert source for the given tool name using the default registry.
 * @param name Tool name from CLI flags (e.g. 'falco', 'none').
 * @param kc Loaded kubeconfig.
 */
export function buildAlertSource(name: string, kc: k8s.KubeConfig): RuntimeAlertSource {
    return defaultRegistry.create(name, kc)
}
