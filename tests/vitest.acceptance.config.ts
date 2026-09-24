import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['tests/real-stack.acceptance.ts'],
    testTimeout: 30_000,
    hookTimeout: 90_000,
    teardownTimeout: 20_000,
    fileParallelism: false,
  },
})
