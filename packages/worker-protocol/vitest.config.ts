import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    name: '@sumatrafuzz/worker-protocol',
    include: ['test/**/*.test.ts'],
  },
});
