<template>
  <NuxtLayout>
    <NuxtPage />
  </NuxtLayout>
</template>

<script setup>
useSeoMeta({
  titleTemplate: (titleChunk) => {
    return titleChunk ? `${titleChunk} — Giuseppe Caruso` : 'Directed by Giuseppe Caruso';
  },
  ogType: 'website',
  ogSiteName: 'Giuseppe Caruso',
  twitterCard: 'summary_large_image',
  description: 'Giuseppe Caruso is a Cinema and Digital Media Engineer specializing in high-profile commercials, music videos, and documentary productions.',
  ogDescription: 'Giuseppe Caruso is a Cinema and Digital Media Engineer specializing in high-profile commercials, music videos, and documentary productions.',
  twitterDescription: 'Giuseppe Caruso is a Cinema and Digital Media Engineer specializing in high-profile commercials, music videos, and documentary productions.',
  author: 'Giuseppe Caruso',
});
</script>

<style>
/* Global page transitions */
.page-enter-active,
.page-leave-active {
  transition: opacity 0.3s ease;
}

.page-enter-from,
.page-leave-to {
  opacity: 0;
}
</style>
