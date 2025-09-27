<template>
  <div class="relative min-h-screen overflow-x-hidden bg-gradient-to-br from-neutral-950 via-neutral-900 to-neutral-950 text-neutral-100">
    <div class="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(0,170,170,0.12),transparent_55%)]" />
    <div class="pointer-events-none absolute inset-y-0 left-1/2 hidden w-px -translate-x-1/2 bg-gradient-to-b from-transparent via-white/10 to-transparent sm:block" />

    <div class="relative flex min-h-screen flex-col">
      <AppHeader />
      <main class="flex-1">
        <slot />
      </main>
      <AppFooter />
    </div>
  </div>
</template>
