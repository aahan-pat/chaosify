import * as k8s from '@kubernetes/client-node'
import { isConflict } from './errors.js'
import { RESOURCE_QUOTA_NAME } from '../../constants.js'

/**
 * Creates the namespace if it does not exist, returns false if it already did.
 * @param api CoreV1Api client to use.
 * @param name Namespace to create.
 */
export async function ensureNamespace(api: k8s.CoreV1Api, name: string): Promise<boolean> {
    try {
        await api.createNamespace({ body: { metadata: { name } } })
        return true
    } catch (err) {
        // 409 means the namespace already exists — treat as success.
        if (isConflict(err)) return false
        throw err
    }
}

/**
 * Applies a ResourceQuota to the namespace, skipping silently if one already exists.
 * @param api CoreV1Api client to use.
 * @param namespace Namespace to apply the quota to.
 */
export async function applyResourceQuota(api: k8s.CoreV1Api, namespace: string): Promise<void> {
    const quota: k8s.V1ResourceQuota = {
        metadata: { name: RESOURCE_QUOTA_NAME, namespace },
        spec: {
            hard: {
                pods: '10',
                'requests.cpu': '2',
                'limits.cpu': '4',
                'requests.memory': '2Gi',
                'limits.memory': '4Gi',
            }
        }
    }
    try {
        await api.createNamespacedResourceQuota({ namespace, body: quota })
    } catch (err) {
        if (isConflict(err)) return
        throw err
    }
}

/**
 * Creates a ServiceAccount in the namespace, skipping silently if it already exists.
 * @param api CoreV1Api client to use.
 * @param namespace Namespace to create the account in.
 * @param name ServiceAccount name.
 */
export async function applyServiceAccount(api: k8s.CoreV1Api, namespace: string, name: string): Promise<void> {
    try {
        await api.createNamespacedServiceAccount({ namespace, body: { metadata: { name, namespace } } })
    } catch (err) {
        if (isConflict(err)) return
        throw err
    }
}

/**
 * Creates a namespace-scoped Role with pod and exec permissions, skipping if it already exists.
 * @param rbac RbacAuthorizationV1Api client to use.
 * @param namespace Namespace to create the role in.
 * @param name Role name.
 */
export async function applyRole(rbac: k8s.RbacAuthorizationV1Api, namespace: string, name: string): Promise<void> {
    const role: k8s.V1Role = {
        metadata: { name, namespace },
        rules: [
            { apiGroups: [''], resources: ['pods', 'pods/exec', 'pods/log'], verbs: ['get', 'list', 'create', 'delete'] },
        ]
    }
    try {
        await rbac.createNamespacedRole({ namespace, body: role })
    } catch (err) {
        if (isConflict(err)) return
        throw err
    }
}

/**
 * Binds a Role to a ServiceAccount in the namespace, skipping if the binding already exists.
 * @param rbac RbacAuthorizationV1Api client to use.
 * @param namespace Namespace to create the binding in.
 * @param serviceAccount ServiceAccount name to bind.
 * @param roleName Role to bind the account to.
 */
export async function applyRoleBinding(rbac: k8s.RbacAuthorizationV1Api, namespace: string, serviceAccount: string, roleName: string): Promise<void> {
    const binding: k8s.V1RoleBinding = {
        metadata: { name: `${roleName}-binding`, namespace },
        subjects: [{ kind: 'ServiceAccount', name: serviceAccount, namespace }],
        roleRef: { apiGroup: 'rbac.authorization.k8s.io', kind: 'Role', name: roleName }
    }
    try {
        await rbac.createNamespacedRoleBinding({ namespace, body: binding })
    } catch (err) {
        if (isConflict(err)) return
        throw err
    }
}
