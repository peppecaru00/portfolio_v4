<template>
  <div>
    <!-- Center Logo -->
    <div
      class="fixed inset-x-0 z-20 p-4 mix-blend-difference bg-transparent flex items-center justify-center"
    >
      <NuxtLink
        class="transition-all duration-1000 flex flex-col items-center opacity-100"
        to="/"
      >
        <div class="transform text-4xl font-secondary tracking-widest text-center whitespace-nowrap">
          Directed By 
        </div>
        <div class="text-5xl font-primary translate-y-[-1rem]  uppercase font-bold text-center whitespace-nowrap">
          GIUSEPPE CARUSO
        </div>
      </NuxtLink>
    </div>

    <!-- Navigation Header -->
    <header class="container fixed inset-x-0 z-40 py-4">
      <nav class="items-start w-full text-sm leading-none flex justify-between">
        <div class="transition-opacity duration-1000 opacity-100">
          <ul class="uppercase [&_a]:text-primary hidden md:flex gap-x-4">
            <li>
              <NuxtLink
                class="text-primary-dark hover:text-primary transition-colors"
                to="/archive/"
                active-class="text-primary"
              >
                Archive
              </NuxtLink>
            </li>
            <li>
              <NuxtLink
                class="text-primary-dark hover:text-primary transition-colors"
                to="/about/"
                active-class="text-primary"
              >
                About
              </NuxtLink>
            </li>
          </ul>
        </div>
        <div class="flex justify-end transition-opacity duration-1000 opacity-100">
          <nav class="flex gap-x-2 hidden md:flex">
            <button class="uppercase cursor-pointer hover:text-primary transition-colors text-primary">en</button>
            <button class="uppercase cursor-pointer hover:text-primary transition-colors text-primary-dark">es</button>
            <button class="uppercase cursor-pointer hover:text-primary transition-colors text-primary-dark">it</button>
          </nav>
          <button @click="isMenuOpen = !isMenuOpen" class="uppercase cursor-pointer md:hidden">Menu</button>
        </div>
      </nav>
    </header>

    <!-- Mobile Menu -->
    <nav
      class="fixed inset-0 w-full h-dvh bg-black text-cream-lighter flex z-30 transition-opacity duration-300 lg:hidden"
      :class="isMenuOpen ? 'opacity-100 pointer-events-auto' : 'opacity-0 pointer-events-none'"
    >
      <div class="flex flex-col items-center justify-center flex-1 pt-24 pb-8 text-center gap-y-12">
        <ul class="flex flex-col items-center justify-center flex-1 text-lg uppercase gap-y-2">
          <li>
            <NuxtLink
              @click="isMenuOpen = false"
              class="text-primary-dark hover:text-primary transition-colors"
              to="/archive/"
              active-class="text-primary"
            >
              Archive
            </NuxtLink>
          </li>
          <li>
            <NuxtLink
              @click="isMenuOpen = false"
              class="text-primary-dark hover:text-primary transition-colors"
              to="/about/"
              active-class="text-primary"
            >
              About
            </NuxtLink>
          </li>
        </ul>
        <div class="flex gap-x-4">
          <button class="text-sm uppercase text-primary">English</button>
          <button class="text-sm uppercase text-primary-dark hover:text-primary">Spanish</button>
          <button class="text-sm uppercase text-primary-dark hover:text-primary">Italian</button>
        </div>
        <div>
          <ul class="text-base leading-tight flex flex-col gap-y-1 text-primary-dark [&_a]:hover:text-primary [&_a]:transition-colors flex items-center justify-center text-sm text-center md:hidden">
            <li>
              <NuxtLink to="mailto:directedby@giuseppecaruso.com">directedby@giuseppecaruso.com</NuxtLink>
            </li>
            <li class="flex gap-2">
              <NuxtLink to="https://www.instagram.com/giuseppecarusodirector/" target="_blank">Instagram</NuxtLink>
              <NuxtLink to="https://www.linkedin.com/in/giuseppe-caruso/" target="_blank">LinkedIn</NuxtLink>
              <NuxtLink to="https://vimeo.com/giuseppecarusodirector" target="_blank">Vimeo</NuxtLink>
            </li>
            <li>
              <NuxtLink to="tel:+39 3347043970">+39 3347043970</NuxtLink>
            </li>
          </ul>
        </div>
      </div>
    </nav>
  </div>
</template>

<script setup>
import { ref } from 'vue';
const isMenuOpen = ref(false);
</script>
