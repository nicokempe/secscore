<template>
  <header class="sticky top-0 z-40 border-b border-white/10 bg-neutral-900/80 backdrop-blur">
    <div class="mx-auto flex w-full max-w-5xl items-center justify-between gap-4 px-4 py-4 sm:px-6 lg:px-8">
      <NuxtLink
        to="/"
        class="group flex items-center gap-3 text-neutral-200"
      >
        <span class="relative flex h-10 w-10 items-center justify-center overflow-hidden rounded-2xl border border-white/10 bg-gradient-to-br from-cyan-500/30 via-cyan-500/10 to-cyan-500/20">
          <img
            src="/secscore-icon.svg"
            alt="SecScore logo"
            class="h-6 w-6"
          >
          <span class="absolute inset-0 rounded-2xl border border-white/10" />
        </span>
        <span>
          <span class="block text-lg font-semibold tracking-wide">SecScore</span>
          <span class="block text-xs text-neutral-400">Time-aware CVE intelligence</span>
        </span>
      </NuxtLink>

      <nav class="flex flex-wrap items-center justify-end gap-2 sm:gap-3">
        <NuxtLink
          to="https://www.nicokempe.eu/legal/imprint"
          target="_blank"
          rel="noopener noreferrer"
          class="inline-flex items-center rounded-full border border-white/10 bg-white/5 px-4 py-2 text-sm font-medium text-neutral-200 transition duration-200 hover:opacity-80"
        >
          Imprint
        </NuxtLink>
        <NuxtLink
          to="https://github.com/nicokempe/secscore"
          target="_blank"
          rel="noopener noreferrer"
          class="inline-flex items-center gap-2 rounded-full border border-cyan-500/60 bg-cyan-500/10 px-4 py-2 text-sm font-medium text-cyan-200 transition duration-200 hover:opacity-80"
        >
          <svg
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 24 24"
            fill="currentColor"
            class="h-4 w-4"
            aria-hidden="true"
          >
            <path
              fill-rule="evenodd"
              d="M12 .5a12 12 0 0 0-3.79 23.4c.6.11.82-.26.82-.58v-2.02c-3.34.73-4.04-1.61-4.04-1.61a3.18 3.18 0 0 0-1.34-1.76c-1.1-.75.08-.74.08-.74a2.52 2.52 0 0 1 1.84 1.24 2.55 2.55 0 0 0 3.49 1 2.56 2.56 0 0 1 .76-1.6c-2.67-.31-5.47-1.34-5.47-5.94A4.64 4.64 0 0 1 5.6 8.4a4.3 4.3 0 0 1 .12-3.18s1-.32 3.3 1.23a11.43 11.43 0 0 1 6 0C17.3 4.9 18.3 5.22 18.3 5.22a4.3 4.3 0 0 1 .12 3.18 4.64 4.64 0 0 1 1.23 3.22c0 4.62-2.8 5.62-5.48 5.92a2.86 2.86 0 0 1 .81 2.22v3.29c0 .32.22.7.83.58A12 12 0 0 0 12 .5Z"
              clip-rule="evenodd"
            />
          </svg>
          <span class="hidden sm:inline">GitHub</span>
        </NuxtLink>
      </nav>
    </div>
  </header>
</template>
