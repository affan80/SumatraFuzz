import { defineConfig } from 'vitest/config';
export default defineConfig({
  test: { name: '@sumatrafuzz/evidence', include: ['test/**/*.test.ts'] },
});
