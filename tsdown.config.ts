import { defineConfig } from 'tsdown'

export default defineConfig({
  entry: ['./src/index.ts'],
  outDir: 'dist',
  format: ['cjs', 'esm', 'iife'],
  globalName: 'IwanSDK', // explorer window.IwanSDK
  dts: true,
  sourcemap: true,
  clean: true,
  minify: true,
  unused: true,
  platform: 'neutral',
  deps: {
    skipNodeModulesBundle: true,
    neverBundle: ['crypto', 'ws']
  }
});