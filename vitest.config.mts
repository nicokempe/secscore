import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

import { defineConfig } from 'vitest/config';

const projectRoot: string = fileURLToPath(new URL('.', import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      '~~': projectRoot,
      '~~/': `${projectRoot}/`,
      '~': resolve(projectRoot, 'app'),
      '~/': `${resolve(projectRoot, 'app')}/`,
    },
  },
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
    globals: true,
    coverage: {
      reporter: ['text', 'html'],
    },
  },
});
