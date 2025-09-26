import withNuxt from './.nuxt/eslint.config.mjs';
import tseslint from '@typescript-eslint/eslint-plugin';
import tsParser from '@typescript-eslint/parser';

export default withNuxt(
  {
    files: ['**/*.ts', '**/*.tsx', '**/*.cts', '**/*.mts'],
    languageOptions: {
      parser: tsParser,
    },
  },
  {
    files: ['**/*.vue'],
    languageOptions: {
      sourceType: 'module',
      parserOptions: {
        sourceType: 'module',
        parser: tsParser,
      },
    },
  },
  {
    plugins: {
      '@typescript-eslint': tseslint,
    },
    rules: {
      // Errors
      '@stylistic/indent': ['error', 2],
      '@stylistic/semi': ['error', 'always'],
      'brace-style': ['error', 'stroustrup'],
      // Warnings
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-unused-vars': 'warn',
      '@typescript-eslint/no-this-alias': 'warn',
      'vue/no-unused-vars': 'warn',
      'no-useless-escape': 'warn',
      // Off
      'vue/no-deprecated-filter': 'off',
    },
  },
);
