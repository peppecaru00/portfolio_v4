import { _ as __nuxt_component_0 } from './nuxt-link-R1wnDmRy.mjs';
import { mergeProps, withCtx, createTextVNode, useSSRContext } from 'vue';
import { ssrRenderAttrs, ssrRenderComponent, ssrRenderAttr } from 'vue/server-renderer';
import { p as publicAssetsURL } from '../_/nitro.mjs';
import { a as useSeoMeta } from './server.mjs';
import 'node:http';
import 'node:https';
import 'node:events';
import 'node:buffer';
import 'node:fs';
import 'node:url';
import 'ipx';
import 'node:path';
import 'node:crypto';
import 'vue-router';
import '../routes/renderer.mjs';
import 'vue-bundle-renderer/runtime';
import 'unhead/server';
import 'devalue';
import 'unhead/plugins';
import 'unhead/utils';

const _imports_0 = publicAssetsURL("/about-bg.webp");
const _sfc_main = {
  __name: "index",
  __ssrInlineRender: true,
  setup(__props) {
    useSeoMeta({
      title: "About",
      ogTitle: "About",
      description: "Learn more about Giuseppe Caruso, Cinema and Digital Media Engineer.",
      ogDescription: "Learn more about Giuseppe Caruso, Cinema and Digital Media Engineer."
    });
    return (_ctx, _push, _parent, _attrs) => {
      const _component_NuxtLink = __nuxt_component_0;
      _push(`<section${ssrRenderAttrs(mergeProps({ class: "container relative items-stretch min-h-svh main-grid" }, _attrs))}><div class="relative z-20 flex items-end col-span-full md:col-span-2"><article class="sticky bottom-0 w-full h-svh pt-[60svh] md:pt-[30svh]"><div class="flex flex-col h-full pb-5 gap-y-12 md:justify-between"><div class="flex flex-col mt-auto gap-y-6 md:mt-0"><div class="content flex flex-col gap-y-[1em] [&amp;_a]:no-underline whitespace-pre-line text-lg md:text-xl"><p> Master&#39;s student in Digital Media Engineering with expertise spanning technical development and creative production. </p><p> I help people bring their visions to life through compelling visual storytelling. </p></div></div><ul class="text-base leading-tight flex flex-col gap-y-1 text-primary-dark [&amp;_a]:hover:text-primary [&amp;_a]:transition-colors hidden md:block mt-8"><li>`);
      _push(ssrRenderComponent(_component_NuxtLink, { to: "mailto:giuseppe.caruso.sc@gmail.com" }, {
        default: withCtx((_, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(`giuseppe.caruso.sc@gmail.com`);
          } else {
            return [
              createTextVNode("giuseppe.caruso.sc@gmail.com")
            ];
          }
        }),
        _: 1
      }, _parent));
      _push(`</li><li class="flex gap-2">`);
      _push(ssrRenderComponent(_component_NuxtLink, {
        to: "https://www.linkedin.com/in/giuseppecaruso00/",
        target: "_blank"
      }, {
        default: withCtx((_, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(`LinkedIn`);
          } else {
            return [
              createTextVNode("LinkedIn")
            ];
          }
        }),
        _: 1
      }, _parent));
      _push(`<span>giuseppecaruso00</span></li><li>`);
      _push(ssrRenderComponent(_component_NuxtLink, { to: "tel:+393925808834" }, {
        default: withCtx((_, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(`+39 3925808834`);
          } else {
            return [
              createTextVNode("+39 3925808834")
            ];
          }
        }),
        _: 1
      }, _parent));
      _push(`</li><li class="pt-4"> Turin, Piedmont, Italy<br> Noto, Syracuse, Sicily </li></ul></div></article></div><div class="z-20 col-span-full md:col-span-2 md:col-start-5"><article class="mt-16 md:mt-[30svh] flex flex-col gap-y-20 pb-20"><div class="content flex flex-col gap-y-[1em] [&amp;_a]:no-underline whitespace-pre-line text-lg"><p> I am a Cinema and Digital Media Engineer, combining a strong technical foundation with a passion for creative production. Currently pursuing my Master&#39;s Degree at Politecnico di Torino, I specialize in the intersection of technology and visual arts. </p><p> My professional journey includes working as a Video Editor and Content Creator at Blank Spaces, where I managed complete post-production workflows\u2014from color grading and sound design to motion graphics and CAD model rendering. Prior to this, I directed and produced visual communication media for Squadra Corse PoliTO, leading a team of designers and videomakers. </p><p> I thrive on bringing complex visions to life, utilizing my expertise in Video Production, Color Grading, 3D Modeling, and Generative AI. Whether operating a drone, crafting a 3D render in KeyShot, or composing visual effects in NukeX, my goal is always to deliver compelling and innovative storytelling. </p></div><div class="flex flex-col gap-y-12"><div class="flex flex-col gap-y-4"><h4 class="text-xl font-secondary text-primary-dark border-b border-primary-dark/30 pb-2"> Work Experience </h4><div class="flex flex-col gap-y-6"><div><div class="flex flex-col md:flex-row md:justify-between md:items-baseline mb-1"><h5 class="text-lg font-bold">Video Editor and Content Creator</h5><span class="text-sm text-primary-dark">Aug 2025 - Feb 2026</span></div><div class="text-primary-dark mb-2">Blank Spaces</div><p class="text-base text-balance opacity-80">Produced and edited video content for digital platforms. Managed complete post-production workflows including color grading, sound design, and motion graphics delivery. CAD models refining and rendering in KeyShot.</p></div><div><div class="flex flex-col md:flex-row md:justify-between md:items-baseline mb-1"><h5 class="text-lg font-bold">Videomaker and Designer</h5><span class="text-sm text-primary-dark">Oct 2023 - Mar 2025</span></div><div class="text-primary-dark mb-2">Squadra Corse PoliTO</div><p class="text-base text-balance opacity-80">Directed and produced visual communication media for university racing team. Managed team of designers and videomakers and digital presence across social media platforms.</p></div></div></div><div class="flex flex-col gap-y-4"><h4 class="text-xl font-secondary text-primary-dark border-b border-primary-dark/30 pb-2"> Education </h4><div class="flex flex-col gap-y-6"><div><div class="flex flex-col md:flex-row md:justify-between md:items-baseline mb-1"><h5 class="text-lg font-bold">Master&#39;s Degree in Cinema &amp; Digital Media Engineering</h5><span class="text-sm text-primary-dark">08/2024 - Now</span></div><div class="text-primary-dark opacity-80">Politecnico di Torino</div></div><div><div class="flex flex-col md:flex-row md:justify-between md:items-baseline mb-1"><h5 class="text-lg font-bold">Bachelor&#39;s Degree in Cinema &amp; Digital Media Engineering</h5><span class="text-sm text-primary-dark">08/2019 - 04/2024</span></div><div class="text-primary-dark opacity-80">Politecnico di Torino</div></div></div></div><div class="flex flex-col gap-y-4"><h4 class="text-xl font-secondary text-primary-dark border-b border-primary-dark/30 pb-2"> Technical Knowledge </h4><ul class="flex flex-col text-base gap-y-3 opacity-80"><li><strong class="text-white block font-medium">Video and Motion:</strong> DaVinci Resolve, Premiere Pro, After Effects, LOG and RAW workflows, Drone Operation.</li><li><strong class="text-white block font-medium">Design and 3D:</strong> Figma, Illustrator, Blender, Plasticity, 3D Printing, KeyShot, CAD Rendering.</li><li><strong class="text-white block font-medium">Photography and Imaging:</strong> Lightroom, Studio Photography, Generative AI, ComfyUI.</li><li><strong class="text-white block font-medium">Audio:</strong> Audition, Reaper, Microphone setup and Calibration.</li></ul></div></div></article></div><figure alt="About" class="fixed inset-0 overflow-hidden size-full opacity-45"><img alt="About background" class="fixed inset-0 overflow-hidden size-full opacity-45 transtion-opacity duration-300 pointer-events-none opacity-100" height="1066" loading="lazy"${ssrRenderAttr("src", _imports_0)} width="1600"></figure></section>`);
    };
  }
};
const _sfc_setup = _sfc_main.setup;
_sfc_main.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("pages/about/index.vue");
  return _sfc_setup ? _sfc_setup(props, ctx) : void 0;
};

export { _sfc_main as default };
//# sourceMappingURL=index-4vwqv920.mjs.map
