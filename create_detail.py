import re

with open('pages/archive.vue', 'r', encoding='utf-8') as f:
    archive_content = f.read()

# Extract header string up to <main
header_match = re.search(r'(<div class="flex flex-col min-h-svh" id="layout-wrapper">.*?)(<main)', archive_content, re.DOTALL)
header = header_match.group(1) if header_match else ''
header = header.replace('<div class="flex flex-col min-h-svh" id="layout-wrapper">', '<div class="flex flex-col min-h-svh" id="layout-wrapper" v-if="project">')

# Extract footer string from </main> onwards up to </template>
footer_match = re.search(r'(</main>.*?</template>)', archive_content, re.DOTALL)
footer = footer_match.group(1) if footer_match else ''

main_content = """<main class="relative z-10 flex flex-col flex-1 h-full max-w-full" id="main-content">
  <div>
    <section class="relative w-full overflow-hidden min-h-svh">
      <figure class="absolute inset-0 overflow-hidden size-full">
        <img :alt="project.title" class="size-full absolute inset-0 block object-cover object-center z-20 transition-opacity duration-300 opacity-100" loading="lazy" :src="project.image" />
        <video v-if="project.videoUrl" class="absolute w-full h-full object-contain top-0 left-0 z-10 transition-opacity duration-300 opacity-100" playsinline preload="metadata" :src="project.videoUrl" autoplay loop muted></video>
      </figure>
    </section>

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
        <div class="content flex flex-col gap-y-[1em] [&_a]:no-underline whitespace-pre-line text-lg">
          <p v-if="project.description">{{ project.description }}</p>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-x-2.5 gap-y-5" v-if="project.metaData">
          <div v-for="(value, key) in filteredMetaData" :key="key">
            <div class="text-sm uppercase text-primary-dark">{{ formatKey(key) }}</div>
            <div class="text-lg">
              <template v-if="Array.isArray(value)">{{ value.join(', ') }}</template>
              <template v-else>{{ value }}</template>
            </div>
          </div>
        </div>
      </article>
    </section>

    <section class="container grid grid-cols-2 gap-2.5 pt-12 md:pt-44" v-if="galleryImages.length">
      <div v-for="(img, index) in galleryImages" :key="index" class="col-span-full" :class="{'md:col-span-1': index % 3 !== 0}" :data-gallery-index="index">
        <figure class="w-full h-auto rounded-md overflow-hidden relative transition-opacity duration-1000 opacity-100">
          <img :alt="`${project.title} - Image ${index + 1}`" class="w-full h-auto rounded-md overflow-hidden relative transtion-opacity duration-300 opacity-100" loading="lazy" :src="img" />
        </figure>
      </div>
    </section>

    <section class="container flex items-center justify-center min-h-svh" v-if="nextProject">
      <article class="w-full max-w-2xl mx-auto relative transition-opacity duration-500 opacity-100" data-next-project="">
        <h3 class="mb-2 text-center uppercase text-primary-dark">Next Project</h3>
        <NuxtLink class="relative overflow-hidden group rounded-md transition-opacity duration-300" :data-project-id="nextProject.id" :href="`/archive/${nextProject.id}`">
          <div class="w-full relative overflow-hidden aspect-10/6 z-10 rounded-md">
            <figure :alt="nextProject.title" class="cover">
              <img :alt="nextProject.title" class="cover transtion-opacity duration-300 opacity-100" loading="lazy" :src="nextProject.image" />
              <video v-if="nextProject.videoUrl" class="cover transition-opacity duration-300 opacity-0 group-hover:opacity-100 pointer-events-none" loop muted playsinline preload="metadata" :src="nextProject.videoUrl" autoplay></video>
            </figure>
          </div>
          <div class="-mt-4.5 text-center relative z-20">
            <h4 class="font-secondary text-[36px] -mb-4.5">{{ nextProject.category }}</h4>
            <h3 class="text-lg uppercase">{{ nextProject.title }}</h3>
          </div>
        </NuxtLink>
      </article>
    </section>
  </div>
"""

script_content = """
<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { useProjects } from '~/composables/useProjects'

const route = useRoute()
const { projects, getProjectById } = useProjects()

const project = computed(() => getProjectById(route.params.id as string))

const currentIndex = computed(() => projects.findIndex(p => p.id === project.value?.id))
const nextProject = computed(() => {
  if (currentIndex.value === -1) return null
  return projects[(currentIndex.value + 1) % projects.length]
})

const formatKey = (key: string) => {
  return key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())
}

const filteredMetaData = computed(() => {
  if (!project.value?.metaData) return {}
  const { client, location, ...rest } = project.value.metaData
  return rest
})

const allGalleries = import.meta.glob('/public/projects/*/images/*.{jpg,jpeg,png,webp,gif}', { eager: true, import: 'default' })

const galleryImages = computed(() => {
  if (!project.value) return []
  const prefix = `/public/projects/${project.value.id}/images/`
  return Object.keys(allGalleries)
    .filter(path => path.startsWith(prefix))
    .map(path => path.replace('/public', ''))
})

useHead({
  title: computed(() => `${project.value?.title || 'Project'} — Directed by Davide Fantuzzi`)
})

onMounted(() => {
  document.body.className = 'page-project'
})
</script>
"""

with open('pages/archive/[id].vue', 'w', encoding='utf-8') as f:
    f.write(header + main_content + footer + '\n' + script_content)
