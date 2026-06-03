import { basename } from 'node:path'
import { loadPodManifest } from '../../../../core/scenarios/exec/pod-runner.js'
import type { ScenarioDefinition } from '../../../../types/scenario.js'

export async function loadManifestScenario(manifestPath: string, expect: string): Promise<ScenarioDefinition> {
    // loadPodManifest handles file read, YAML parse, and Pod-kind validation with user-friendly exits.
    const manifest = await loadPodManifest(manifestPath)
    return {
        id: `custom:${basename(manifestPath)}`,
        version: 1,
        name: basename(manifestPath),
        description: 'User-submitted manifest',
        category: 'preventive',
        controlObjective: 'User-defined',
        prerequisites: [],
        manifest,
        expectedOutcome: { type: expect === 'rejected' ? 'admission_rejected' : 'admission_allowed' },
        cleanup: { deleteCreatedResources: true },
        safety: { level: 'low', namespaceScoped: true },
    }
}
