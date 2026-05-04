<script setup>
import { onMounted } from "vue";
import { projects } from "~/data/projects";
import { resolveMediaUrl } from "~/utils/media";

// Sort projects by year descending and take the first 6
const featuredProjects = [...projects]
  .sort((a, b) => b.year.localeCompare(a.year))
  .slice(0, 6);

const heroVideoUrl = resolveMediaUrl("https://peppecaruso-portfolio-storage.s3.eu-north-1.amazonaws.com/showreel_2.mp4");

useSeoMeta({
  title: "Home",
  ogTitle: "Home",
  description: "Director & Filmmaker Portfolio. Giuseppe Caruso specializes in high-profile commercials, music videos, and documentary productions.",
  ogDescription: "Director & Filmmaker Portfolio. Giuseppe Caruso specializes in high-profile commercials, music videos, and documentary productions.",
});

onMounted(() => {
  document.body.className = "home";

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.1 }
  );

  document.querySelectorAll(".reveal-fade").forEach((el) => {
    observer.observe(el);
  });
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
        :src="heroVideoUrl"
      ></video>
    </figure>
    
    <!-- Hero Slider Content -->
    <div
      class="absolute bottom-0 inset-x-0 z-30 px-4 py-8 justify-center items-stretch transition-opacity duration-700 hidden md:flex opacity-100"
    >
      <NuxtLink
        v-for="project in featuredProjects"
        :key="project.id"
        class="px-5 opacity-40 group hover:opacity-100 transition-opacity cursor-pointer flex-1 text-center nth-[4]:hidden nth-[5]:hidden xl:nth-[4]:block 2xl:nth-[5]:block reveal-fade"
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
