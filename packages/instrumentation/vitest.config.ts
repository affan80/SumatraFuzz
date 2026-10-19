import { defineConfig } from 'vitest/config';
export default defineConfig({
  test: { name: '@sumatrafuzz/instrumentation', include: ['test/**/*.test.ts'] },
});
