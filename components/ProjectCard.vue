<template>
  <article
    class="project-card"
    :class="{ 'is-large': large }"
    @click="$emit('click', project.id)"
    @mouseenter="playVideo"
    @mouseleave="pauseVideo"
  >
    <div class="project-image-wrap">
      <NuxtImg
        :src="project.image"
        :alt="project.title"
        class="project-image"
        :class="{ 'opacity-0': isHovered && project.coverVideo }"
        :width="large ? 1600 : 800"
        :height="large ? 900 : 450"
        sizes="(max-width: 768px) 100vw, 50vw"
        quality="85"
        format="webp"
        loading="lazy"
      />
      <video
        v-if="project.coverVideo"
        ref="videoRef"
        :src="project.coverVideo"
        class="project-video"
        :class="{ 'opacity-100': isHovered }"
        muted
        loop
        playsinline
        preload="auto"
        autoplay
      ></video>
    </div>
    <div class="project-info">
      <span class="project-year">{{ project.year }}</span>
      <div class="project-meta">
        <span class="project-category">{{ project.category }}</span>
        <h3 class="project-title">{{ project.title }}</h3>
      </div>
    </div>
  </article>
</template>

<script setup lang="ts">
import { ref } from "vue";
import type { Project } from "~/data/projects";

const props = defineProps<{
  project: Project;
  large?: boolean;
}>();

defineEmits<{
  click: [id: string];
}>();

const videoRef = ref<HTMLVideoElement | null>(null);
const isHovered = ref(false);

const playVideo = () => {
  isHovered.value = true;
  if (videoRef.value) {
    videoRef.value.play().catch(() => {});
  }
};

const pauseVideo = () => {
  isHovered.value = false;
  if (videoRef.value) {
    videoRef.value.pause();
  }
};
</script>

<style scoped>
.project-card {
  position: relative;
  overflow: hidden;
  cursor: pointer;
  background: #111;
  aspect-ratio: 16/10;
}

.project-card.is-large {
  aspect-ratio: 16/9;
}

.project-image-wrap {
  position: absolute;
  inset: 0;
  overflow: hidden;
}

.project-image {
  width: 100%;
  height: 100%;
  object-fit: cover;
  transition:
    transform 0.9s var(--transition-smooth),
    filter 0.6s ease,
    opacity 0.6s ease;
  filter: brightness(0.9);
}

.project-video {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  object-fit: cover;
  opacity: 0;
  z-index: 1;
  transition:
    opacity 0.6s ease,
    transform 0.9s var(--transition-smooth),
    filter 0.6s ease;
  filter: brightness(0.9);
  pointer-events: none;
}

.project-card:hover .project-image,
.project-card:hover .project-video {
  transform: scale(1.04);
  filter: brightness(0.65);
}

.project-info {
  position: absolute;
  inset: 0;
  z-index: 2;
  display: flex;
  flex-direction: column;
  justify-content: flex-end;
  padding: 1.5rem;
}

.project-year {
  position: absolute;
  top: 1.25rem;
  right: 1.25rem;
  font-size: 0.7rem;
  color: rgba(255, 255, 255, 0.6);
  opacity: 0;
  transition: opacity 0.4s ease;
}

.project-card:hover .project-year {
  opacity: 1;
}

.project-meta {
  transform: translateY(12px);
  opacity: 0;
  transition: all 0.5s var(--transition-smooth);
}

.project-card:hover .project-meta {
  transform: translateY(0);
  opacity: 1;
}

.project-category {
  display: block;
  font-size: 0.6rem;
  font-weight: 500;
  letter-spacing: 0.2em;
  text-transform: uppercase;
  color: var(--color-accent);
  margin-bottom: 0.4rem;
}

.project-title {
  font-size: 1.1rem;
  font-weight: 500;
  line-height: 1.3;
  color: #fff;
}

@media (max-width: 640px) {
  .project-info {
    padding: 1rem;
  }

  .project-title {
    font-size: 1rem;
  }
}
</style>
