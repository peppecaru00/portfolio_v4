<template>
  <div v-if="project">
    <!-- Hero -->
    <section class="relative w-full overflow-hidden min-h-svh">
      <figure class="absolute inset-0 overflow-hidden size-full">
        <img
          v-if="project.image"
          :alt="project.title"
          class="size-full absolute inset-0 block object-cover object-center z-20 transition-opacity duration-300 opacity-100"
          loading="lazy"
          :src="project.image"
        />
        <video
          v-if="project.videoUrl"
          class="absolute w-full h-full object-cover top-0 left-0 z-30 transition-opacity duration-300 opacity-100"
          playsinline
          preload="metadata"
          :src="project.videoUrl"
          autoplay
          loop
          muted
        ></video>
      </figure>
    </section>

    <!-- Info section -->
    <section class="container grid grid-cols-1 md:grid-cols-2 gap-2.5 py-6">
      <div class="flex flex-col pb-12 gap-y-8 w-full md:w-10/12">
        <h1 class="text-xl uppercase text-balance">{{ project.title }}</h1>
        <ul class="flex flex-col text-lg gap-y-4">
          <li v-if="project.metaData?.client">
            <div class="text-sm uppercase text-primary-dark">Client</div>
            <div>{{ project.metaData.client }}</div>
          </li>
          <li v-if="project.category">
            <div class="text-sm uppercase text-primary-dark">Category</div>
            <div>{{ project.category }}</div>
          </li>
          <li v-if="project.metaData?.location">
            <div class="text-sm uppercase text-primary-dark">Location</div>
            <div>{{ project.metaData.location }}</div>
          </li>
        </ul>
      </div>

      <article class="flex flex-col gap-y-20">
        <div class="content flex flex-col gap-y-[1em] whitespace-pre-line text-lg">
          <p v-if="project.description">{{ project.description }}</p>
        </div>

        <div v-if="Object.keys(filteredMetaData).length" class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-x-2.5 gap-y-5">
          <div v-for="(value, key) in filteredMetaData" :key="key">
            <div class="text-sm uppercase text-primary-dark">
              {{ formatKey(String(key)) }}
            </div>
            <div class="text-lg">
              <span v-if="Array.isArray(value)">{{ value.join(", ") }}</span>
              <span v-else>{{ value }}</span>
            </div>
          </div>
        </div>
      </article>
    </section>

    <!-- Gallery -->
    <section v-if="galleryImages.length" class="container grid grid-cols-2 gap-2.5 pt-12 md:pt-44">
      <div
        v-for="(img, index) in galleryImages"
        :key="index"
        :class="index % 3 === 0 ? 'col-span-full' : 'col-span-full md:col-span-1'"
        :data-gallery-index="index"
      >
        <figure class="w-full h-auto rounded-md overflow-hidden">
          <img
            :alt="`${project.title} - Image ${index + 1}`"
            class="w-full h-auto rounded-md opacity-100"
            loading="lazy"
            :src="img"
          />
        </figure>
      </div>
    </section>

    <!-- Next project -->
    <section v-if="nextProject" class="container flex items-center justify-center min-h-svh">
      <article class="w-full max-w-2xl mx-auto relative">
        <h3 class="mb-2 text-center uppercase text-primary-dark">Next Project</h3>
        <NuxtLink
          class="relative overflow-hidden group rounded-md transition-opacity duration-300 block"
          :to="`/archive/${nextProject.id}`"
        >
          <div class="w-full relative overflow-hidden aspect-[10/6] z-10 rounded-md">
            <figure class="cover" :alt="nextProject.title">
              <img
                v-if="nextProject.image"
                :alt="nextProject.title"
                class="cover transition-opacity duration-300 opacity-100"
                loading="lazy"
                :src="nextProject.image"
              />
              <video
                v-if="nextProject.videoUrl"
                class="cover transition-opacity duration-300 opacity-0 group-hover:opacity-100 pointer-events-none"
                loop
                muted
                playsinline
                preload="metadata"
                :src="nextProject.videoUrl"
                autoplay
              ></video>
            </figure>
          </div>
          <div class="-mt-4.5 text-center relative z-20">
            <h4 class="font-secondary text-[36px] -mb-4.5">
              {{ nextProject.category }}
            </h4>
            <h3 class="text-lg uppercase">{{ nextProject.title }}</h3>
          </div>
        </NuxtLink>
      </article>
    </section>
  </div>

  <!-- 404 state -->
  <div v-else class="flex items-center justify-center min-h-svh text-center">
    <div>
      <h1 class="text-2xl uppercase mb-4">Project not found</h1>
      <NuxtLink
        to="/archive/"
        class="text-primary-dark hover:text-primary transition-colors uppercase text-sm"
      >
        ← Back to Archive
      </NuxtLink>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted } from "vue";
import { useRoute } from "vue-router";
import { useProjects } from "~/composables/useProjects";

const route = useRoute();
const { projects, getProjectById } = useProjects();

const project = computed(() => getProjectById(route.params.id as string));

const currentIndex = computed(() =>
  projects.findIndex((p) => p.id === project.value?.id),
);
const nextProject = computed(() => {
  if (currentIndex.value === -1) return null;
  return projects[(currentIndex.value + 1) % projects.length];
});

const formatKey = (key: string) => {
  return key
    .replace(/([A-Z])/g, " $1")
    .replace(/^./, (str) => str.toUpperCase());
};

const filteredMetaData = computed(() => {
  if (!project.value?.metaData) return {};
  const { client, location, ...rest } = project.value.metaData as Record<string, any>;
  return rest;
});

const allGalleries = import.meta.glob(
  "/public/projects/*/images/*.{jpg,jpeg,png,webp,gif}",
  { eager: true, import: "default" },
);

const galleryImages = computed(() => {
  if (!project.value) return [];
  const prefix = `/public/projects/${project.value.id}/images/`;
  return Object.keys(allGalleries)
    .filter((path) => path.startsWith(prefix))
    .map((path) => path.replace("/public", ""));
});

useHead({
  title: computed(() => `${project.value?.title || "Project"} — Directed by Giuseppe Caruso`),
});

onMounted(() => {
  document.body.className = "page-project";
});
</script>
