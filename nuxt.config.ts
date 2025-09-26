export default defineNuxtConfig({
  modules: ['@nuxt/eslint', '@nuxt/test-utils', '@nuxtjs/turnstile', '@nuxtjs/tailwindcss'],
  devtools: { enabled: true },
  app: {
    pageTransition: { name: 'page', mode: 'out-in' },
    head: {
      titleTemplate: '%s • SecScore',
      charset: 'utf-8',
      viewport: 'width=device-width, initial-scale=1',
      meta: [
        { charset: 'utf-8' },
        { name: 'viewport', content: 'width=device-width,initial-scale=1,shrink-to-fit=no' },
        { id: 'og:site_name', property: 'og:site_name', content: 'SecScore' },
        { id: 'twitter:card', name: 'twitter:card', content: 'summary' },
        { id: 'twitter:site', name: 'twitter:site', content: '@nico_kempe' },
        { id: 'twitter:creator', name: 'twitter:creator', content: '@nico_kempe' },
        { id: 'twitter:creator-id', name: 'twitter:creator:id', content: '990948799504842754' },
        { id: 'twitter:site', name: 'twitter:site', content: '@nico_kempe' },
        { id: 'twitter:site-id', name: 'twitter:site:id', content: '990948799504842754' },
      ],
    },
  },
  css: [
    '~/assets/css/tailwind.css',
  ],
  compatibilityDate: '2025-09-26',
  nitro: {
    preset: 'cloudflare_module',
    experimental: {
      openAPI: true,
    },
  },
  eslint: {
    config: {
      stylistic: true,
    },
  },
  tailwindcss: {
    config: {
      content: ['./app/pages/**/*.{vue,js,ts}', './app/components/**/*.{vue,js,ts}', './app/layouts/**/*.{vue,js,ts}'],
    },
  },
  turnstile: {
    siteKey: process.env.CLOUDFLARE_TURNSTILE_SITE_KEY,
  },
});
