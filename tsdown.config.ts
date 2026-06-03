import { defineConfig } from 'tsdown'

export default defineConfig({
  entry: ['src/index.ts'],
  format: 'esm',
  outDir: 'dist',
  clean: true,
  dts: false,
  // Use .js extension so npm accepts it as a valid bin entry (package.json has "type":"module").
  outExtensions: () => ({ js: '.js' }),
  banner: {
    js: '#!/usr/bin/env node',
  },
  define: {
    'process.env.NODE_ENV': '"production"',
  },
  // Copy scenario YAML files so the built binary can load them at runtime.
  copy: [{ from: 'src/scenarios', to: 'dist' }],
})
