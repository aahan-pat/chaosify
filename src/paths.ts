import { fileURLToPath } from 'node:url'
import { join } from 'node:path'

// Resolves to src/scenarios/ in development and dist/scenarios/ in the built binary.
// import.meta.url points to this file in dev (src/paths.ts) and to dist/index.js in prod,
// so the relative ./scenarios segment lands correctly in both cases.
export const SCENARIOS_DIR = join(fileURLToPath(new URL('.', import.meta.url)), 'scenarios')
