<template>
  <div>
    <NuxtLoadingIndicator
      color="repeating-linear-gradient(to right,#10b981 0%,#047857 50%,#064e3b 100%)"
    />
    <NuxtLayout>
      <NuxtPage
        :transition="{ name: 'page', mode: 'out-in' }"
      />
    </NuxtLayout>
  </div>
</template>

<style>
.page-enter-active,
.page-leave-active {
  transition: all 0.4s;
}
.page-enter-from,
.page-leave-to {
  opacity: 0;
  filter: blur(1rem);
}
</style>
