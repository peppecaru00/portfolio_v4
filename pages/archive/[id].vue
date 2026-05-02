<template>
  <div v-if="project">
    <!-- Hero -->
    <section id="hero-section" class="relative w-full overflow-hidden min-h-svh group bg-black flex items-center justify-center">
      <figure class="absolute inset-0 overflow-hidden size-full">
        <NuxtImg
          v-if="project.image && (!isPlaying && currentTime === 0)"
          :alt="project.title"
          class="size-full absolute inset-0 block object-cover object-center z-20 transition-opacity duration-300 opacity-100"
          loading="lazy"
          :src="project.image"
          sizes="sm:100vw md:100vw"
          format="webp"
        />
        <video
          v-if="project.videoUrl"
          ref="videoRef"
          class="absolute w-full h-full object-cover top-0 left-0 z-10 transition-opacity duration-300 opacity-100"
          playsinline
          preload="metadata"
          :src="project.videoUrl"
          @timeupdate="onTimeUpdate"
          @loadedmetadata="onLoadedMetadata"
          @ended="onEnded"
          @click="togglePlay"
        ></video>

        <!-- Center Play Button -->
        <button
          v-if="project.videoUrl && !isPlaying"
          @click="togglePlay"
          class="absolute inset-0 m-auto w-24 h-24 flex items-center justify-center z-30 text-white opacity-70 hover:opacity-100 transition-opacity cursor-pointer mix-blend-difference"
        >
          <svg class="w-16 h-16 ml-2" fill="currentColor" viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>
        </button>

        <!-- Bottom Controls -->
        <div v-if="project.videoUrl" class="absolute bottom-0 inset-x-0 h-24 bg-gradient-to-t from-black/80 to-transparent z-30 flex items-end pb-8 px-8 opacity-0 group-hover:opacity-100 transition-opacity duration-300">
          <div class="flex items-center w-full gap-4 text-xs font-mono text-white/90">
            <!-- Play/Pause -->
            <button @click="togglePlay" class="hover:text-white uppercase tracking-widest flex items-center min-w-[80px] gap-1">
              <svg v-if="isPlaying" class="w-3 h-3" fill="currentColor" viewBox="0 0 24 24"><path d="M6 19h4V5H6v14zm8-14v14h4V5h-4z"/></svg>
              <svg v-else class="w-3 h-3" fill="currentColor" viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>
              <span>{{ isPlaying ? 'Pause' : 'Play' }}</span>
            </button>
            
            <!-- Time -->
            <div class="tracking-widest whitespace-nowrap">
              {{ formatTime(currentTime) }} / {{ formatTime(duration) }}
            </div>

            <!-- Seekbar -->
            <div class="flex-1 mx-4 flex items-center relative h-1.5">
              <!-- Background Bar -->
              <div class="absolute inset-x-0 h-[1.5px] bg-white/20 rounded-full"></div>
              <!-- Progress Bar -->
              <div 
                class="absolute left-0 h-[1.5px] bg-white rounded-full pointer-events-none" 
                :style="{ width: `${(currentTime / (duration || 1)) * 100}%` }"
              ></div>
              <!-- Invisible Range for Interaction -->
              <input
                type="range"
                min="0"
                :max="duration || 100"
                :value="currentTime"
                @input="seek"
                class="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-20"
              />
            </div>

            <!-- Mute/Unmute -->
            <button @click="toggleMute" class="hover:text-white min-w-[24px] flex justify-center">
              <svg v-if="isMuted" class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5.586 15H4a1 1 0 01-1-1v-4a1 1 0 011-1h1.586l4.707-4.707C10.923 3.663 12 4.109 12 5v14c0 .891-1.077 1.337-1.707.707L5.586 15z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2"></path></svg>
              <svg v-else class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.536 8.464a5 5 0 010 7.072m2.828-9.9a9 9 0 010 12.728M5.586 15H4a1 1 0 01-1-1v-4a1 1 0 011-1h1.586l4.707-4.707C10.923 3.663 12 4.109 12 5v14c0 .891-1.077 1.337-1.707.707L5.586 15z"></path></svg>
            </button>

            <!-- Fullscreen -->
            <button @click="toggleFullscreen" class="hover:text-white ml-2">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4"></path></svg>
            </button>
          </div>
        </div>
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
          <NuxtImg
            :alt="`${project.title} - Image ${index + 1}`"
            class="w-full h-auto rounded-md opacity-100"
            loading="lazy"
            :src="img"
            sizes="sm:100vw md:50vw"
            format="webp"
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
              <NuxtImg
                v-if="nextProject.image"
                :alt="nextProject.title"
                class="cover transition-opacity duration-300 opacity-100 group-hover:scale-105 transition-transform"
                loading="lazy"
                :src="nextProject.image"
                sizes="sm:100vw md:50vw"
                format="webp"
              />
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
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { useProjects } from "~/composables/useProjects";

const route = useRoute();
const { projects, getProjectById } = useProjects();

const project = computed(() => getProjectById(route.params.id as string));

// Video Player Logic
const videoRef = ref<HTMLVideoElement | null>(null);
const isPlaying = ref(false);
const currentTime = ref(0);
const duration = ref(0);
const isMuted = ref(false);

const formatTime = (timeInSeconds: number) => {
  if (isNaN(timeInSeconds)) return "00:00";
  const m = Math.floor(timeInSeconds / 60).toString().padStart(2, "0");
  const s = Math.floor(timeInSeconds % 60).toString().padStart(2, "0");
  return `${m}:${s}`;
};

const togglePlay = () => {
  if (!videoRef.value) return;
  if (videoRef.value.paused) {
    videoRef.value.play();
    isPlaying.value = true;
  } else {
    videoRef.value.pause();
    isPlaying.value = false;
  }
};

const onTimeUpdate = () => {
  if (videoRef.value) {
    currentTime.value = videoRef.value.currentTime;
  }
};

const onLoadedMetadata = () => {
  if (videoRef.value) {
    duration.value = videoRef.value.duration;
  }
};

const onEnded = () => {
  isPlaying.value = false;
};

const seek = (event: Event) => {
  const target = event.target as HTMLInputElement;
  const time = parseFloat(target.value);
  if (videoRef.value) {
    videoRef.value.currentTime = time;
    currentTime.value = time;
  }
};

const toggleMute = () => {
  if (!videoRef.value) return;
  videoRef.value.muted = !videoRef.value.muted;
  isMuted.value = videoRef.value.muted;
};

const toggleFullscreen = () => {
  const hero = document.getElementById("hero-section");
  if (!hero) return;
  if (!document.fullscreenElement) {
    hero.requestFullscreen().catch((err) => {
      console.error(`Error attempting to enable full-screen mode: ${err.message}`);
    });
  } else {
    document.exitFullscreen();
  }
};

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

useSeoMeta({
  title: computed(() => project.value?.title || "Project"),
  ogTitle: computed(() => project.value?.title || "Project"),
  description: computed(() => project.value?.description || project.value?.category),
  ogDescription: computed(() => project.value?.description || project.value?.category),
  ogImage: computed(() => project.value?.image),
  twitterImage: computed(() => project.value?.image),
});

onMounted(() => {
  document.body.className = "page-project";
});
</script>
