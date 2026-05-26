<template>
  <div class="flex flex-col pt-24 pb-12 md:pt-36 md:pb-24 gap-y-12 md:gap-y-24">
    <nav class="container flex items-center justify-center overflow-x-auto scrollbar-none">
      <div class="inline-flex gap-x-2.5">
        <button 
          class="button whitespace-nowrap" 
          :class="{ active: activeTab === 'video' }" 
          @click="activeTab = 'video'"
        >
          Videos
        </button>
        <button 
          class="button whitespace-nowrap" 
          :class="{ active: activeTab === 'photo' }" 
          @click="activeTab = 'photo'"
        >
          Photos
        </button>
      </div>
    </nav>
    <section class="container grid grid-cols-1 md:grid-cols-2 gap-2.5">
      <NuxtLink
        v-for="project in filteredProjects"
        :key="project.id"
        class="relative overflow-hidden group rounded-md transition-opacity duration-500 opacity-100 reveal-fade"
        :to="`/archive/${project.id}`"
      >
        <div class="relative overflow-hidden aspect-10/6">
          <figure :alt="project.title" class="cover">
              <NuxtImg
                v-if="project.image"
                :alt="project.title"
                :class="project.coverVideo ? 'cover transition-opacity duration-300 opacity-100 group-hover:opacity-0' : 'cover transition-opacity duration-300 opacity-100'"
                height="2160"
                loading="lazy"
                :src="project.image"
                width="3840"
                sizes="sm:100vw md:50vw"
                format="webp"
              />
            <video
              v-if="project.coverVideo"
              class="cover transition-opacity duration-300 pointer-events-none opacity-0 group-hover:opacity-100"
              loop
              muted
              playsinline
              preload="auto"
              :src="project.coverVideo"
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
import { ref, computed, onMounted, onBeforeUnmount, nextTick, watch } from "vue";
import { useProjects } from "~/composables/useProjects";

useSeoMeta({
  title: "Archive",
  ogTitle: "Archive",
  description: "Explore the complete portfolio and archive of works by Giuseppe Caruso.",
  ogDescription: "Explore the complete portfolio and archive of works by Giuseppe Caruso.",
});

const { projects } = useProjects();

const activeTab = useState<'video' | 'photo'>('archive-active-tab', () => 'video');

const filteredProjects = computed(() => {
  return projects.filter((project) => project.type === activeTab.value);
});

let observer: IntersectionObserver | null = null;

const observeElements = () => {
  if (observer) {
    observer.disconnect();
  }

  observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          observer?.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.1, rootMargin: "0px 0px -50px 0px" }
  );

  document.querySelectorAll(".reveal-fade").forEach((el) => {
    observer?.observe(el);
  });
};

watch(activeTab, () => {
  nextTick(() => {
    observeElements();
  });
});

onMounted(() => {
  document.body.className = "page-archive";
  observeElements();
});

onBeforeUnmount(() => {
  if (observer) {
    observer.disconnect();
  }
});
</script>
