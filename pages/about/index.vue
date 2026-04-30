<template>
  <section class="container relative items-stretch min-h-svh main-grid">
    <div class="relative z-20 flex items-end col-span-full md:col-span-2">
      <article class="sticky bottom-0 w-full h-svh pt-[60svh] md:pt-[30svh]">
        <div class="flex flex-col h-full pb-5 gap-y-12 md:justify-between">
          <div class="flex flex-col mt-auto gap-y-6 md:mt-0">
            <div class="content flex flex-col gap-y-[1em] [&amp;_a]:no-underline whitespace-pre-line text-lg md:text-xl">
              <p>
                Giuseppe Caruso is a commercial director with an approach
                deeply rooted in documentary language, working
                internationally.<br />Recognized for his distinctive vision,
                he has been invited to speak on the TEDx stage.
              </p>
            </div>
            <NuxtLink
              aria-label="Watch my TEDx "
              class="button w-fit"
              to="https://www.youtube.com/watch?v=yb0dHadCu4s"
              rel="noopener noreferrer"
              target="_blank"
            >
              Watch my TEDx
            </NuxtLink>
          </div>
          <ul class="text-base leading-tight flex flex-col gap-y-1 text-primary-dark [&amp;_a]:hover:text-primary [&amp;_a]:transition-colors hidden md:block">
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
      </article>
    </div>
    <div class="z-20 col-span-full md:col-span-2 md:col-start-5">
      <article class="mt-16 md:mt-[30svh] flex flex-col gap-y-20 pb-20">
        <div class="content flex flex-col gap-y-[1em] [&amp;_a]:no-underline whitespace-pre-line text-lg">
          <p>
            Giuseppe Caruso is making waves across the international
            creative scene, specializing in high-profile commercials, music
            videos, and documentary productions.
          </p>
          <p>
            Based between Barcelona and Milan, he brings a bold and
            unmistakable Italian artistic vision to every project, turning
            each set into a launchpad for innovative and emotionally
            resonant storytelling.
          </p>
          <p>
            Caruso has already celebrated two national screenings of his
            docu-film shot in Tanzania, focusing on the Hadzabe tribe. This
            unique premiere not only highlighted his directorial talent but
            also underscored his global perspective and deep commitment to
            telling stories that matter.
          </p>
          <p>
            A global citizen at heart, he thrives on the inspiration drawn
            from working and living across cultures. Every destination and
            human connection adds depth to his perspective and nourishes his
            craft.
          </p>
          <p>
            Recognized for his impact as an international director, Giuseppe
            Caruso has also taken the TEDx stage as a speaker, a testament
            to his growing status as a visionary director. With unwavering
            determination and a passion for creativity and human connection,
            he continues to redefine storytelling as an art form that
            transcends all boundaries.
          </p>
        </div>
        <div class="flex flex-col gap-y-8">
          <h4 class="text-xl text-center font-secondary text-primary-dark">
            Trusted by Worldwide Agencies
          </h4>
          <ul class="flex flex-col text-lg gap-y-1">
            <li class="text-center"><NuxtLink to="https://www.ted.com/" target="_blank">TED</NuxtLink></li>
            <li class="text-center"><span>Juventus</span></li>
            <li class="text-center"><span>Tom Ford</span></li>
            <li class="text-center"><span>L'Officiel</span></li>
            <li class="text-center"><span>Marni</span></li>
            <li class="text-center"><span>Max Mara</span></li>
            <li class="text-center"><NuxtLink to="https://www.youtube.com/@ProgettoHappiness" target="_blank">Progetto Happiness</NuxtLink></li>
            <li class="text-center"><NuxtLink to="https://antiestatico.com/" target="_blank">Antiestatico</NuxtLink></li>
            <li class="text-center"><NuxtLink to="https://www.phocuscreators.com/" target="_blank">Phocus Creator</NuxtLink></li>
          </ul>
        </div>
      </article>
    </div>
    <figure alt="About" class="fixed inset-0 overflow-hidden size-full opacity-45">
      <img
        alt="About background"
        class="fixed inset-0 overflow-hidden size-full opacity-45 transtion-opacity duration-300 pointer-events-none opacity-100"
        height="1066"
        loading="lazy"
        src="https://cdn.sanity.io/images/x9j3wb78/production/00ec95f37dc2b4247654d55a5a395acca292ff0c-1600x1066.webp"
        width="1600"
      />
    </figure>
  </section>
</template>

<script setup>
import { onMounted } from "vue";

onMounted(() => {
  document.body.className = "page-about";
});
</script>
