import * as k8s from '@kubernetes/client-node'

/**
 * Loads kubeconfig from the default location and optionally switches context.
 * @param context Kubernetes context to activate, uses current if omitted.
 */
export function buildKubeConfig(context?: string): k8s.KubeConfig {
    const kc = new k8s.KubeConfig()
    kc.loadFromDefault()
    if (context) kc.setCurrentContext(context)
    return kc
}

/**
 * Creates a CoreV1Api client bound to the given kubeconfig.
 * @param kc Loaded kubeconfig to bind the client to.
 */
export function coreV1Api(kc: k8s.KubeConfig): k8s.CoreV1Api {
    return kc.makeApiClient(k8s.CoreV1Api)
}

/**
 * Creates an RbacAuthorizationV1Api client bound to the given kubeconfig.
 * @param kc Loaded kubeconfig to bind the client to.
 */
export function rbacV1Api(kc: k8s.KubeConfig): k8s.RbacAuthorizationV1Api {
    return kc.makeApiClient(k8s.RbacAuthorizationV1Api)
}

/**
 * Creates an AppsV1Api client bound to the given kubeconfig.
 * @param kc Loaded kubeconfig to bind the client to.
 */
export function appsV1Api(kc: k8s.KubeConfig): k8s.AppsV1Api {
    return kc.makeApiClient(k8s.AppsV1Api)
}

/**
 * Creates a NetworkingV1Api client bound to the given kubeconfig.
 * @param kc Loaded kubeconfig to bind the client to.
 */
export function networkingV1Api(kc: k8s.KubeConfig): k8s.NetworkingV1Api {
    return kc.makeApiClient(k8s.NetworkingV1Api)
}

/**
 * Creates an AdmissionregistrationV1Api client bound to the given kubeconfig.
 * @param kc Loaded kubeconfig to bind the client to.
 */
export function admissionregistrationV1Api(kc: k8s.KubeConfig): k8s.AdmissionregistrationV1Api {
    return kc.makeApiClient(k8s.AdmissionregistrationV1Api)
}

