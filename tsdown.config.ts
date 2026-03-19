import { defineConfig } from 'tsdown'

export default defineConfig({
  entry: ['./src/index.ts'],
  outDir: 'dist',
  format: ['cjs', 'esm', 'iife'],
  globalName: 'IwanClient', // explorer window.IwanClient
  dts: true,
  sourcemap: true,
  clean: true,
  minify: true,
  unused: true,
  platform: 'neutral',
  outputOptions: {
    globals: {
      eventemitter3: 'eventemitter3',
    },
  },
  deps: {
    // skipNodeModulesBundle: true,
    neverBundle: ['crypto', 'ws'],
    alwaysBundle: ['eventemitter3'],
    onlyBundle: ['eventemitter3']
  }
});