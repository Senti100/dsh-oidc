import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['tests/real-stack.acceptance.ts'],
    testTimeout: 15_000,
    hookTimeout: 30_000,
    fileParallelism: false,
  },
})
