<template>
  <footer class="container flex flex-col py-5 gap-y-6">
    <section class="flex flex-wrap justify-between text-xs text-primary-dark">
      <article class="flex flex-wrap flex-1 gap-x-5">
        <div>© 2026 All rights reserved @ Directed by Giuseppe Caruso</div>
      </article>
      <nav class="flex gap-x-2">
        <NuxtLink
          aria-label="Visit my Instagram page"
          class="hover:text-primary transition-colors"
          to="https://www.instagram.com/peppecaruso.it/"
          rel="noopener noreferrer"
          target="_blank"
        >
          Instagram
        </NuxtLink>
        <NuxtLink
          aria-label="Visit my LinkedIn page"
          class="hover:text-primary transition-colors"
          to="https://www.linkedin.com/in/giuseppecaruso00/"
          rel="noopener noreferrer"
          target="_blank"
        >
          LinkedIn
        </NuxtLink>
      </nav>
    </section>
  </footer>
</template>
