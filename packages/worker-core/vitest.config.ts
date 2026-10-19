import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    name: '@sumatrafuzz/worker-core',
    include: ['test/**/*.test.ts'],
  },
});
