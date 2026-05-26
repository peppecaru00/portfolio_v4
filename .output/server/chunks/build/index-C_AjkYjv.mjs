import { _ as __nuxt_component_0 } from './nuxt-link-R1wnDmRy.mjs';
import { mergeProps, unref, withCtx, createVNode, toDisplayString, useSSRContext } from 'vue';
import { ssrRenderAttrs, ssrRenderAttr, ssrRenderList, ssrRenderComponent, ssrInterpolate } from 'vue/server-renderer';
import { p as projects, r as resolveMediaUrl } from './projects-BrkyW9qj.mjs';
import { a as useSeoMeta } from './server.mjs';
import '../_/nitro.mjs';
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

const _sfc_main = {
  __name: "index",
  __ssrInlineRender: true,
  setup(__props) {
    const featuredProjects = [...projects].sort((a, b) => b.year.localeCompare(a.year)).slice(0, 6);
    const heroVideoUrl = resolveMediaUrl("https://peppecaruso-portfolio-storage.s3.eu-north-1.amazonaws.com/showreel_2.mp4");
    useSeoMeta({
      title: "Home",
      ogTitle: "Home",
      description: "Director & Filmmaker Portfolio. Giuseppe Caruso specializes in high-profile commercials, music videos, and documentary productions.",
      ogDescription: "Director & Filmmaker Portfolio. Giuseppe Caruso specializes in high-profile commercials, music videos, and documentary productions."
    });
    return (_ctx, _push, _parent, _attrs) => {
      const _component_NuxtLink = __nuxt_component_0;
      _push(`<section${ssrRenderAttrs(mergeProps({ class: "relative w-full overflow-hidden min-h-svh" }, _attrs))}><figure class="cover transition-opacity duration-300 opacity-100"><video autoplay class="cover transition-opacity duration-300 opacity-100" loop muted playsinline preload="auto"${ssrRenderAttr("src", unref(heroVideoUrl))}></video></figure><div class="absolute bottom-0 inset-x-0 z-30 px-4 py-8 justify-center items-stretch transition-opacity duration-700 hidden md:flex opacity-100"><!--[-->`);
      ssrRenderList(unref(featuredProjects), (project) => {
        _push(ssrRenderComponent(_component_NuxtLink, {
          key: project.id,
          class: "px-5 opacity-40 group hover:opacity-100 transition-opacity cursor-pointer flex-1 text-center nth-[4]:hidden nth-[5]:hidden xl:nth-[4]:block 2xl:nth-[5]:block reveal-fade",
          to: `/archive/${project.id}`
        }, {
          default: withCtx((_, _push2, _parent2, _scopeId) => {
            if (_push2) {
              _push2(`<h3 class="text-[36px] font-secondary -mb-4"${_scopeId}>${ssrInterpolate(project.category)}</h3><h2 class="text-sm leading-none uppercase"${_scopeId}>${ssrInterpolate(project.title)}</h2>`);
            } else {
              return [
                createVNode("h3", { class: "text-[36px] font-secondary -mb-4" }, toDisplayString(project.category), 1),
                createVNode("h2", { class: "text-sm leading-none uppercase" }, toDisplayString(project.title), 1)
              ];
            }
          }),
          _: 2
        }, _parent));
      });
      _push(`<!--]--></div></section>`);
    };
  }
};
const _sfc_setup = _sfc_main.setup;
_sfc_main.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("pages/index.vue");
  return _sfc_setup ? _sfc_setup(props, ctx) : void 0;
};

export { _sfc_main as default };
//# sourceMappingURL=index-C_AjkYjv.mjs.map
