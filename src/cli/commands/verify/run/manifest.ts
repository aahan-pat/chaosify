import { readFile } from 'node:fs/promises'
import { basename } from 'node:path'
import * as k8s from '@kubernetes/client-node'
import type { ScenarioDefinition } from '../../../../types/scenario.js'

export async function loadManifestScenario(manifestPath: string, expect: string): Promise<ScenarioDefinition> {
    let content: string
    try {
        content = await readFile(manifestPath, 'utf-8')
    } catch {
        console.error(`\nError\n  Could not read manifest file: ${manifestPath}`)
        process.exit(4)
    }

    let parsed: unknown
    try {
        parsed = k8s.loadYaml(content)
    } catch {
        console.error(`\nError\n  Could not parse manifest file (expected valid YAML or JSON): ${manifestPath}`)
        process.exit(4)
    }

    if (!parsed || typeof parsed !== 'object') {
        console.error(`\nError\n  Manifest file is empty or not a valid object: ${manifestPath}`)
        process.exit(4)
    }

    const manifest = parsed as Record<string, unknown>

    if (manifest['kind'] !== 'Pod') {
        console.error(`\nError\n  Only Pod manifests are supported. Found kind: ${manifest['kind'] ?? 'unknown'}`)
        console.error('  Tip: extract the pod template from a Deployment/DaemonSet into a standalone Pod manifest')
        process.exit(4)
    }

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
