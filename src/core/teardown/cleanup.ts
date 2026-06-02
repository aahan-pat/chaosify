// Deletes Kubernetes resources that were created during scenario execution.
// Runs after each scenario to keep the cluster clean between test runs.
import * as k8s from '@kubernetes/client-node'
import type { CleanupStatus } from '../../types/evidence.js'

/** A resource that needs to be deleted after a scenario run */
export interface CleanupTarget {
    kind: 'Pod'
    name: string
    namespace: string
}

/** Result of a cleanup attempt, including any resources that could not be removed */
export interface CleanupResult {
    status: CleanupStatus
    detail?: string
    /** Resources that still exist after cleanup â€” callers should surface these to the user */
    remainingResources: CleanupTarget[]
}

/**
 * Deletes test resources created during scenario execution.
 * Each resource deletion is attempted independently so a single failure does not
 * prevent cleanup of other resources (resulting in a 'partial' status).
 */
export class CleanupManager {
    private readonly kc: k8s.KubeConfig

    constructor(kc: k8s.KubeConfig) {
        this.kc = kc
    }

    /**
     * Delete all provided targets and report which (if any) could not be removed.
     * Returns 'skipped' immediately when no targets are provided (e.g. the scenario
     * was rejected by admission and no resource was ever created).
     */
    async cleanup(targets: CleanupTarget[]): Promise<CleanupResult> {
        if (targets.length === 0) {
            return { status: 'skipped', remainingResources: [] }
        }

        const remaining: CleanupTarget[] = []

        for (const target of targets) {
            const ok = await this.deleteResource(target)
            // Collect failures so we can report exactly which resources need manual cleanup.
            if (!ok) remaining.push(target)
        }

        if (remaining.length === 0) {
            return { status: 'success', remainingResources: [] }
        }

        // Some but not all deletions failed â€” report partial so the caller can warn the user.
        if (remaining.length < targets.length) {
            return {
                status: 'partial',
                detail: `${remaining.length} resource(s) could not be deleted`,
                remainingResources: remaining,
            }
        }

        return {
            status: 'failed',
            detail: 'No resources could be deleted',
            remainingResources: remaining,
        }
    }

    /**
     * Attempts to delete a single resource via the Kubernetes API.
     * Returns false on any error so the caller can track it as a remaining resource.
     */
    private async deleteResource(target: CleanupTarget): Promise<boolean> {
        try {
            if (target.kind === 'Pod') {
                const coreApi = this.kc.makeApiClient(k8s.CoreV1Api)
                await coreApi.deleteNamespacedPod({ name: target.name, namespace: target.namespace })
            }
            return true
        } catch {
            return false
        }
    }
}
