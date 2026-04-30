<template>
  <Teleport to="body">
    <Transition name="modal">
      <div v-if="isOpen" class="modal-backdrop" @click.self="close">
        <div class="modal-content">
          <button class="modal-close" @click="close">
            <span>Close</span>
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
              <path
                d="M1 1L13 13M13 1L1 13"
                stroke="currentColor"
                stroke-width="1.5"
              />
            </svg>
          </button>
          <div class="modal-video">
            <div v-if="project?.videoUrl" class="video-embed">
              <iframe
                :src="embedUrl"
                width="100%"
                height="100%"
                frameborder="0"
                allow="autoplay; fullscreen; picture-in-picture"
                allowfullscreen
              />
            </div>
            <div v-else class="video-placeholder">
              <p>Video coming soon</p>
              <p class="video-placeholder-sub">
                Add your Vimeo/YouTube embed URL in data/projects.ts
              </p>
            </div>
          </div>
          <div class="modal-info">
            <span class="modal-category">{{ project?.category }}</span>
            <h2 class="modal-title">{{ project?.title }}</h2>
            <span class="modal-year">{{ project?.year }}</span>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { computed, watch } from "vue";
import type { Project } from "~/data/projects";

const props = defineProps<{
  isOpen: boolean;
  project: Project | null;
}>();

const emit = defineEmits<{
  close: [];
}>();

const embedUrl = computed(() => {
  if (!props.project?.videoUrl) return "";
  const url = props.project.videoUrl;
  if (url.includes("vimeo.com")) {
    const id = url.split("/").pop();
    return `https://player.vimeo.com/video/${id}?autoplay=1&title=0&byline=0&portrait=0`;
  }
  if (url.includes("youtube.com") || url.includes("youtu.be")) {
    const id = url.includes("v=")
      ? url.split("v=")[1].split("&")[0]
      : url.split("/").pop();
    return `https://www.youtube.com/embed/${id}?autoplay=1&rel=0`;
  }
  return url;
});

const close = () => emit("close");

watch(
  () => props.isOpen,
  (open) => {
    if (open) {
      document.body.style.overflow = "hidden";
    } else {
      document.body.style.overflow = "";
    }
  },
);

onBeforeUnmount(() => {
  document.body.style.overflow = "";
});
</script>

<style scoped>
.modal-backdrop {
  position: fixed;
  inset: 0;
  z-index: 1000;
  background: rgba(0, 0, 0, 0.96);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 2rem;
  backdrop-filter: blur(10px);
}

.modal-content {
  position: relative;
  width: 100%;
  max-width: 1400px;
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.modal-close {
  position: absolute;
  top: -3rem;
  right: 0;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  background: none;
  border: none;
  color: rgba(255, 255, 255, 0.6);
  font-family: var(--font-sans);
  font-size: 0.7rem;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  cursor: pointer;
  transition: color 0.3s ease;
}

.modal-close:hover {
  color: #fff;
}

.modal-video {
  width: 100%;
  aspect-ratio: 16/9;
  background: #111;
}

.video-embed,
.video-embed iframe {
  width: 100%;
  height: 100%;
}

.video-placeholder {
  width: 100%;
  height: 100%;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  color: var(--color-muted);
  gap: 0.5rem;
}

.video-placeholder-sub {
  font-size: 0.8rem;
  opacity: 0.6;
}

.modal-info {
  display: flex;
  align-items: baseline;
  gap: 1rem;
  flex-wrap: wrap;
}

.modal-category {
  font-size: 0.65rem;
  letter-spacing: 0.2em;
  text-transform: uppercase;
  color: var(--color-accent);
}

.modal-title {
  font-size: 1.25rem;
  font-weight: 400;
}

.modal-year {
  font-size: 0.75rem;
  color: var(--color-muted);
  margin-left: auto;
}

/* Transition */
.modal-enter-active,
.modal-leave-active {
  transition: opacity 0.4s ease;
}

.modal-enter-from,
.modal-leave-to {
  opacity: 0;
}

@media (max-width: 640px) {
  .modal-backdrop {
    padding: 1rem;
  }

  .modal-close {
    top: -2.5rem;
  }
}
</style>
