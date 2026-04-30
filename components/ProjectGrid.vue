<template>
  <section id="archive" class="archive">
    <div class="archive-grid">
      <ProjectCard
        v-for="(project, index) in projects"
        :key="project.id"
        :project="project"
        :large="index === 0"
        class="archive-item"
        :style="{ animationDelay: `${index * 0.08}s` }"
        @click="$emit('select', project.id)"
      />
    </div>
  </section>
</template>

<script setup lang="ts">
import type { Project } from "~/data/projects";

defineProps<{
  projects: Project[];
}>();

defineEmits<{
  select: [id: string];
}>();
</script>

<style scoped>
.archive {
  padding: 0.25rem;
  background: #000;
}

.archive-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 0.25rem;
}

.archive-item {
  opacity: 0;
  transform: translateY(30px);
  animation: fadeUp 0.8s var(--transition-smooth) forwards;
}

.archive-item:first-child {
  grid-column: 1 / -1;
  aspect-ratio: 21/9;
}

@keyframes fadeUp {
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

@media (max-width: 768px) {
  .archive-grid {
    grid-template-columns: 1fr;
  }

  .archive-item:first-child {
    aspect-ratio: 16/10;
  }
}
</style>
