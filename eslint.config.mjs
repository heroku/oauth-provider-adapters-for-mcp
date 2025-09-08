import { defineConfig } from 'eslint/config';
import js from '@eslint/js';
import tsParser from '@typescript-eslint/parser';
import tsPlugin from '@typescript-eslint/eslint-plugin';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// ESLint flat config for a TypeScript project with dual-build (CJS/ESM) outputs.
// - Ignores built artifacts in `dist/`
// - Applies base JS recommended rules to JS files
// - Applies TypeScript parsing and TS-specific rules to TS files
// - Enables common Mocha globals in test files

export default defineConfig([
  // Global ignores for generated content and dependencies
  {
    ignores: ['dist/**', 'node_modules/**', 'coverage/**'],
  },

  // JavaScript files
  {
    files: ['**/*.js', '**/*.mjs', '**/*.cjs'],
    ...js.configs.recommended,
  },

  // TypeScript source files
  {
    files: ['**/*.ts', '**/*.mts', '**/*.cts'],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        // Use the project tsconfig for type-aware linting
        project: ['./tsconfig.json'],
        tsconfigRootDir: path.dirname(fileURLToPath(import.meta.url)),
        ecmaVersion: 2022,
        sourceType: 'module',
      },
    },
    plugins: {
      '@typescript-eslint': tsPlugin,
    },
    rules: {
      // Align with legacy config behavior
      '@typescript-eslint/no-unused-vars': 'warn',
    },
  },

  // Test files (Mocha)
  {
    files: ['test/**/*.ts', '**/*.spec.ts', '**/*.test.ts'],
    languageOptions: {
      globals: {
        describe: 'readonly',
        it: 'readonly',
        before: 'readonly',
        beforeEach: 'readonly',
        after: 'readonly',
        afterEach: 'readonly',
      },
    },
  },
]);
