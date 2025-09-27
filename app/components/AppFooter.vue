<template>
  <footer class="border-t border-white/10 bg-neutral-900/80 backdrop-blur">
    <div class="mx-auto flex w-full max-w-5xl flex-col gap-6 px-4 py-10 sm:px-6 lg:px-8 lg:flex-row lg:items-center lg:justify-between">
      <div class="flex items-center gap-3 text-neutral-400">
        <span class="relative flex h-10 w-10 items-center justify-center overflow-hidden rounded-2xl border border-white/10 bg-gradient-to-br from-cyan-500/30 via-cyan-500/10 to-cyan-500/20">
          <img
            src="/secscore-icon.svg"
            alt="SecScore logo"
            class="h-6 w-6"
          >
          <span class="absolute inset-0 rounded-2xl border border-white/10" />
        </span>
        <div>
          <p class="text-sm font-semibold text-neutral-200">
            SecScore
          </p>
          <p class="text-xs text-neutral-500">
            Elevating vulnerability insights with context.
          </p>
        </div>
      </div>

      <div class="flex flex-col gap-4 text-sm text-neutral-400 sm:flex-row sm:items-center sm:gap-6">
        <p class="text-xs text-neutral-500">
          © {{ currentYear }} Nico Kempe. All rights reserved.
        </p>
        <div class="flex flex-wrap items-center gap-3 sm:justify-end">
          <a
            href="https://www.nicokempe.eu/legal/imprint"
            target="_blank"
            rel="noopener noreferrer"
            class="inline-flex items-center gap-1 text-neutral-300 transition ease-in-out duration-300 hover:opacity-80"
          >
            Imprint
          </a>
          <span class="hidden h-1 w-1 rounded-full bg-neutral-600 sm:inline-flex" />
          <a
            href="https://github.com/nicokempe/secscore"
            target="_blank"
            rel="noopener noreferrer"
            class="inline-flex items-center gap-1 text-neutral-300 transition ease-in-out duration-300 hover:opacity-80"
          >
            GitHub Repository
          </a>
        </div>
      </div>
    </div>
  </footer>
</template>

<script setup lang="ts">
const currentYear = new Date().getFullYear();
</script>
