import withNuxt from './.nuxt/eslint.config.mjs';

export default withNuxt(
  {
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
