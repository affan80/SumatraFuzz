import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    name: '@sumatrafuzz/run-store',
    include: ['test/**/*.test.ts'],
  },
});
