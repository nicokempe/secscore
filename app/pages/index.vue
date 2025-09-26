<template>
  <div class="min-h-screen bg-gradient-to-br from-[#0a0f1c] via-[#0f1b33] to-[#0a0f1c] text-white flex flex-col">
    <!-- Hero Section -->
    <header class="flex-1 flex items-center justify-center px-6">
      <div
        class="backdrop-blur-xl bg-white/5 border border-white/10 rounded-2xl shadow-xl p-10 max-w-3xl text-center"
      >
        <h1 class="text-4xl md:text-5xl font-bold tracking-tight text-blue-400">
          Security Score for CVEs
        </h1>
        <p class="mt-4 text-lg text-neutral-300">
          A proof-of-concept to enrich CVEs with public signals and compute a
          <span class="text-blue-300">time-aware security score</span> for better prioritization.
        </p>

        <!-- Coming Soon Badge -->
        <div
          class="mt-6 inline-block px-5 py-2 rounded-full bg-blue-500/20 border border-blue-400/30 text-blue-300 font-medium tracking-wide"
        >
          Coming Soon
        </div>

        <!-- GitHub Link -->
        <div class="mt-8">
          <a
            href="https://github.com/nicokempe/secscore"
            target="_blank"
            class="inline-block px-6 py-2 rounded-xl bg-blue-500/20 border border-blue-400/30 text-blue-300 hover:bg-blue-500/30 transition"
          >
            View on GitHub
          </a>
        </div>
      </div>
    </header>

    <!-- Footer -->
    <footer
      class="py-6 text-center text-sm text-neutral-400 border-t border-white/10"
    >
      <p>
        © {{ new Date().getFullYear() }} Nico Kempe —
        <a
          href="https://www.nicokempe.eu/legal/imprint"
          target="_blank"
          class="text-blue-400 hover:text-blue-300 transition"
        >
          Legal / Imprint
        </a>
      </p>
    </footer>
  </div>
</template>

<script lang="ts">
useSeoMeta({
  title: 'SecScore • Time-aware CVE Threat Scoring (Nuxt + Nitro)',
  description: 'Open-source PoC to enrich CVEs with public signals (NVD, EPSS, CISA KEV, ExploitDB, OSV) and compute a time-aware SecScore for realistic prioritization. Paste a CVE ID and get instant context.',
  ogTitle: 'SecScore • Time-aware CVE Threat Scoring',
  ogDescription: 'Enrich CVEs with public data and compute a time-aware SecScore using an Asymmetric Laplace model plus EPSS, KEV, and ExploitDB signals.',
  ogImage: '/images/og/secscore.webp',
  ogType: 'website',
  ogUrl: 'https://secscore.nicokempe.de/',
  twitterTitle: 'SecScore • Time-aware CVE Threat Scoring',
  twitterDescription: 'Open-source Nuxt + Nitro PoC that turns a CVE ID into an explainable, time-aware SecScore using public threat signals.',
  twitterImage: '/images/og/secscore.webp',
  twitterCard: 'summary_large_image',
});
</script>
