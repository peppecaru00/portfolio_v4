<template>
  <div class="flex flex-col pt-24 pb-12 md:pt-36 md:pb-24 gap-y-12 md:gap-y-24">
    <nav class="container items-center justify-center overflow-x-scroll text-center scrollbar-none">
      <div class="inline-flex gap-x-2.5">
        <button class="active button whitespace-nowrap">All</button>
        <button class="button whitespace-nowrap">Commercial</button>
        <button class="button whitespace-nowrap">Creative Short</button>
        <button class="button whitespace-nowrap">Documentary</button>
        <button class="button whitespace-nowrap">Music Video</button>
      </div>
    </nav>
    <section class="container grid grid-cols-1 md:grid-cols-2 gap-2.5">
      <NuxtLink
        v-for="project in projects"
        :key="project.id"
        class="relative overflow-hidden group rounded-md transition-opacity duration-500 opacity-100"
        :to="`/archive/${project.id}`"
      >
        <div class="relative overflow-hidden aspect-10/6">
          <figure :alt="project.title" class="cover">
            <img
              v-if="project.image"
              :alt="project.title"
              class="cover transtion-opacity duration-300 opacity-100"
              height="2160"
              loading="lazy"
              :src="project.image"
              width="3840"
            />
            <video
              v-if="project.videoUrl"
              class="cover transition-opacity duration-300 pointer-events-none opacity-0 group-hover:opacity-100"
              loop
              muted
              playsinline
              preload="metadata"
              :src="project.videoUrl"
              autoplay
            ></video>
          </figure>
        </div>
        <div class="absolute inset-0 z-30 flex flex-col items-center justify-center p-4 opacity-0 bg-black/50 group-hover:opacity-100 transition-opacity duration-500">
          <div class="w-full max-w-xl text-balance mx-auto text-center">
            <h4 class="text-[36px] font-secondary -mb-4.5">
              {{ project.category }}
            </h4>
            <h3 class="text-lg uppercase">{{ project.title }}</h3>
          </div>
        </div>
      </NuxtLink>
    </section>
  </div>
</template>

<script setup lang="ts">
import { onMounted } from "vue";
import { useProjects } from "~/composables/useProjects";

useHead({
  title: "Archive — Directed by Giuseppe Caruso",
});

const { projects } = useProjects();

onMounted(() => {
  document.body.className = "page-archive";
});
</script>
