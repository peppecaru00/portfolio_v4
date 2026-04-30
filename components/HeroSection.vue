<template>
  <section class="hero">
    <div class="hero-media">
      <NuxtImg
        :src="featuredProject.image"
        :alt="featuredProject.title"
        class="hero-image"
        width="1920"
        height="1080"
        sizes="100vw"
        quality="85"
        format="webp"
        preload
      />
      <div class="hero-overlay" />
    </div>
    <div class="hero-content">
      <span class="hero-category">{{ featuredProject.category }}</span>
      <h1 class="hero-title">{{ featuredProject.title }}</h1>
      <button class="hero-play" @click="$emit('play', featuredProject.id)">
        <span class="play-icon">
          <svg
            width="12"
            height="14"
            viewBox="0 0 12 14"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path d="M12 7L0 14V0L12 7Z" fill="currentColor" />
          </svg>
        </span>
        <span class="play-text">Watch Film</span>
      </button>
    </div>
    <div class="scroll-hint">
      <span class="scroll-text">Scroll</span>
      <div class="scroll-line" />
    </div>
  </section>
</template>

<script setup lang="ts">
import type { Project } from "~/data/projects";

defineProps<{
  featuredProject: Project;
}>();

defineEmits<{
  play: [id: string];
}>();
</script>

<style scoped>
.hero {
  position: relative;
  width: 100%;
  height: 100vh;
  height: 100dvh;
  overflow: hidden;
  display: flex;
  align-items: flex-end;
}

.hero-media {
  position: absolute;
  inset: 0;
  z-index: 1;
}

.hero-image {
  width: 100%;
  height: 100%;
  object-fit: cover;
  filter: brightness(0.85);
}

.hero-overlay {
  position: absolute;
  inset: 0;
  background: linear-gradient(
    to bottom,
    rgba(0, 0, 0, 0.2) 0%,
    rgba(0, 0, 0, 0.4) 50%,
    rgba(0, 0, 0, 0.7) 100%
  );
  z-index: 2;
}

.hero-content {
  position: relative;
  z-index: 3;
  padding: 0 2rem 4rem;
  max-width: 600px;
  opacity: 0;
  transform: translateY(30px);
  animation: fadeUp 1s var(--transition-smooth) 0.3s forwards;
}

.hero-category {
  display: block;
  font-size: 0.65rem;
  font-weight: 500;
  letter-spacing: 0.25em;
  text-transform: uppercase;
  color: var(--color-accent);
  margin-bottom: 0.75rem;
}

.hero-title {
  font-size: clamp(2rem, 5vw, 3.5rem);
  font-weight: 300;
  line-height: 1.1;
  margin-bottom: 1.5rem;
  letter-spacing: -0.02em;
}

.hero-play {
  display: inline-flex;
  align-items: center;
  gap: 0.75rem;
  background: none;
  border: 1px solid rgba(255, 255, 255, 0.3);
  color: #fff;
  padding: 0.75rem 1.5rem;
  font-family: var(--font-sans);
  font-size: 0.7rem;
  letter-spacing: 0.15em;
  text-transform: uppercase;
  cursor: pointer;
  transition: all 0.4s var(--transition-smooth);
}

.hero-play:hover {
  background: #fff;
  color: #000;
  border-color: #fff;
}

.play-icon {
  display: flex;
  align-items: center;
  justify-content: center;
}

.scroll-hint {
  position: absolute;
  bottom: 2rem;
  left: 50%;
  transform: translateX(-50%);
  z-index: 3;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.5rem;
  opacity: 0;
  animation: fadeIn 1s ease 1s forwards;
}

.scroll-text {
  font-size: 0.6rem;
  letter-spacing: 0.2em;
  text-transform: uppercase;
  color: rgba(255, 255, 255, 0.5);
}

.scroll-line {
  width: 1px;
  height: 40px;
  background: linear-gradient(to bottom, rgba(255, 255, 255, 0.5), transparent);
  animation: scrollPulse 2s ease-in-out infinite;
}

@keyframes fadeUp {
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

@keyframes fadeIn {
  to {
    opacity: 1;
  }
}

@keyframes scrollPulse {
  0%,
  100% {
    opacity: 0.3;
    transform: scaleY(0.5);
  }
  50% {
    opacity: 1;
    transform: scaleY(1);
  }
}

@media (max-width: 640px) {
  .hero-content {
    padding: 0 1.25rem 3rem;
  }
}
</style>
