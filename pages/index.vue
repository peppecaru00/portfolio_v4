<script setup>
import { onMounted } from "vue";
import { projects } from "~/data/projects";

// Sort projects by year descending and take the first 6
const featuredProjects = [...projects]
  .sort((a, b) => b.year.localeCompare(a.year))
  .slice(0, 6);

onMounted(() => {
  document.body.className = "home";
});
</script>

<template>
  <section class="relative w-full overflow-hidden min-h-svh">
    <figure class="cover transition-opacity duration-300 opacity-100">
      <video
        autoplay
        class="cover transition-opacity duration-300 opacity-100"
        loop
        muted
        playsinline
        preload="auto"
        src="/hero-bg.mp4"
      ></video>
    </figure>
    
    <!-- Hero Slider Content -->
    <div
      class="absolute bottom-0 inset-x-0 z-30 px-4 py-8 justify-center items-stretch transition-opacity duration-700 hidden md:flex opacity-100"
    >
      <NuxtLink
        v-for="project in featuredProjects"
        :key="project.id"
        class="px-5 opacity-40 group hover:opacity-100 transition-opacity cursor-pointer flex-1 text-center nth-[4]:hidden nth-[5]:hidden xl:nth-[4]:block 2xl:nth-[5]:block"
        :to="`/archive/${project.id}`"
      >
        <h3 class="text-[36px] font-secondary -mb-4">{{ project.category }}</h3>
        <h2 class="text-sm leading-none uppercase">
          {{ project.title }}
        </h2>
      </NuxtLink>
    </div>
  </section>
</template>
