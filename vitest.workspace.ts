import { defineWorkspace } from 'vitest/config';

export default defineWorkspace([
  {
    test: {
      name: 'sumatrafuzz',
      include: ['packages/*/test/**/*.test.ts', 'apps/*/test/**/*.test.ts'],
      exclude: ['**/node_modules/**', '**/dist/**'],
    },
  },
]);
