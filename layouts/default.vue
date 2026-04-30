<template>
  <div class="flex flex-col min-h-svh" id="layout-wrapper">
    <!-- Mouse Follower -->
    <div
      class="fixed top-0 left-0 z-50 hidden bg-white rounded-full pointer-events-none follower md:block -translate-y-2 -translate-x-2 size-4 mix-blend-difference opacity-100"
    ></div>

    <AppHeader />
    
    <main
      class="relative z-10 flex flex-col flex-1 h-full max-w-full"
      id="main-content"
    >
      <slot />
    </main>

    <AppFooter />
  </div>
</template>

<script setup>
import { onMounted, onBeforeUnmount } from "vue";

onMounted(() => {
  let requestRef;
  let mouseX = 0;
  let mouseY = 0;

  const updatePosition = () => {
    const followers = document.querySelectorAll(".follower");
    followers.forEach((follower) => {
      follower.style.left = `${mouseX}px`;
      follower.style.top = `${mouseY}px`;
    });
    requestRef = requestAnimationFrame(updatePosition);
  };

  const onMouseMove = (e) => {
    mouseX = e.clientX;
    mouseY = e.clientY;
  };

  window.addEventListener("mousemove", onMouseMove);
  requestRef = requestAnimationFrame(updatePosition);

  onBeforeUnmount(() => {
    window.removeEventListener("mousemove", onMouseMove);
    cancelAnimationFrame(requestRef);
  });
});
</script>
