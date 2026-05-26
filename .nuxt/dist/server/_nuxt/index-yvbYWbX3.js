import { _ as __nuxt_component_0 } from "./nuxt-link-R1wnDmRy.js";
import { _ as _sfc_main$1, u as useProjects } from "./useProjects-CTpKfcnA.js";
import { toRef, isRef, defineComponent, computed, watch, nextTick, mergeProps, unref, withCtx, createVNode, openBlock, createBlock, createCommentVNode, toDisplayString, useSSRContext } from "vue";
import { ssrRenderAttrs, ssrRenderClass, ssrRenderList, ssrRenderComponent, ssrRenderAttr, ssrInterpolate } from "vue/server-renderer";
import { b as useNuxtApp, a as useSeoMeta } from "../server.mjs";
import "C:/Users/carus/Documents/Websites/portfolio_v4/node_modules/ufo/dist/index.mjs";
import "C:/Users/carus/Documents/Websites/portfolio_v4/node_modules/defu/dist/defu.mjs";
import "C:/Users/carus/Documents/Websites/portfolio_v4/node_modules/h3/dist/index.mjs";
import "./projects-BrkyW9qj.js";
import "C:/Users/carus/Documents/Websites/portfolio_v4/node_modules/ofetch/dist/node.mjs";
import "#internal/nuxt/paths";
import "C:/Users/carus/Documents/Websites/portfolio_v4/node_modules/hookable/dist/index.mjs";
import "C:/Users/carus/Documents/Websites/portfolio_v4/node_modules/unctx/dist/index.mjs";
import "vue-router";
import "C:/Users/carus/Documents/Websites/portfolio_v4/node_modules/@unhead/vue/dist/index.mjs";
const useStateKeyPrefix = "$s";
function useState(...args) {
  const autoKey = typeof args[args.length - 1] === "string" ? args.pop() : void 0;
  if (typeof args[0] !== "string") {
    args.unshift(autoKey);
  }
  const [_key, init] = args;
  if (!_key || typeof _key !== "string") {
    throw new TypeError("[nuxt] [useState] key must be a string: " + _key);
  }
  if (init !== void 0 && typeof init !== "function") {
    throw new Error("[nuxt] [useState] init must be a function: " + init);
  }
  const key = useStateKeyPrefix + _key;
  const nuxtApp = useNuxtApp();
  const state = toRef(nuxtApp.payload.state, key);
  if (state.value === void 0 && init) {
    const initialValue = init();
    if (isRef(initialValue)) {
      nuxtApp.payload.state[key] = initialValue;
      return initialValue;
    }
    state.value = initialValue;
  }
  return state;
}
const _sfc_main = /* @__PURE__ */ defineComponent({
  __name: "index",
  __ssrInlineRender: true,
  setup(__props) {
    useSeoMeta({
      title: "Archive",
      ogTitle: "Archive",
      description: "Explore the complete portfolio and archive of works by Giuseppe Caruso.",
      ogDescription: "Explore the complete portfolio and archive of works by Giuseppe Caruso."
    });
    const { projects } = useProjects();
    const activeTab = useState("archive-active-tab", () => "video");
    const filteredProjects = computed(() => {
      return projects.filter((project) => project.type === activeTab.value);
    });
    let observer = null;
    const observeElements = () => {
      if (observer) {
        observer.disconnect();
      }
      observer = new IntersectionObserver(
        (entries) => {
          entries.forEach((entry) => {
            if (entry.isIntersecting) {
              entry.target.classList.add("is-visible");
              observer?.unobserve(entry.target);
            }
          });
        },
        { threshold: 0.1, rootMargin: "0px 0px -50px 0px" }
      );
      (void 0).querySelectorAll(".reveal-fade").forEach((el) => {
        observer?.observe(el);
      });
    };
    watch(activeTab, () => {
      nextTick(() => {
        observeElements();
      });
    });
    return (_ctx, _push, _parent, _attrs) => {
      const _component_NuxtLink = __nuxt_component_0;
      const _component_NuxtImg = _sfc_main$1;
      _push(`<div${ssrRenderAttrs(mergeProps({ class: "flex flex-col pt-24 pb-12 md:pt-36 md:pb-24 gap-y-12 md:gap-y-24" }, _attrs))}><nav class="container flex items-center justify-center overflow-x-auto scrollbar-none"><div class="inline-flex gap-x-2.5"><button class="${ssrRenderClass([{ active: unref(activeTab) === "video" }, "button whitespace-nowrap"])}"> Videos </button><button class="${ssrRenderClass([{ active: unref(activeTab) === "photo" }, "button whitespace-nowrap"])}"> Photos </button></div></nav><section class="container grid grid-cols-1 md:grid-cols-2 gap-2.5"><!--[-->`);
      ssrRenderList(filteredProjects.value, (project) => {
        _push(ssrRenderComponent(_component_NuxtLink, {
          key: project.id,
          class: "relative overflow-hidden group rounded-md transition-opacity duration-500 opacity-100 reveal-fade",
          to: `/archive/${project.id}`
        }, {
          default: withCtx((_, _push2, _parent2, _scopeId) => {
            if (_push2) {
              _push2(`<div class="relative overflow-hidden aspect-10/6"${_scopeId}><figure${ssrRenderAttr("alt", project.title)} class="cover"${_scopeId}>`);
              if (project.image) {
                _push2(ssrRenderComponent(_component_NuxtImg, {
                  alt: project.title,
                  class: project.coverVideo ? "cover transition-opacity duration-300 opacity-100 group-hover:opacity-0" : "cover transition-opacity duration-300 opacity-100",
                  height: "2160",
                  loading: "lazy",
                  src: project.image,
                  width: "3840",
                  sizes: "sm:100vw md:50vw",
                  format: "webp"
                }, null, _parent2, _scopeId));
              } else {
                _push2(`<!---->`);
              }
              if (project.coverVideo) {
                _push2(`<video class="cover transition-opacity duration-300 pointer-events-none opacity-0 group-hover:opacity-100" loop muted playsinline preload="auto"${ssrRenderAttr("src", project.coverVideo)} autoplay${_scopeId}></video>`);
              } else {
                _push2(`<!---->`);
              }
              _push2(`</figure></div><div class="absolute inset-0 z-30 flex flex-col items-center justify-center p-4 opacity-0 bg-black/50 group-hover:opacity-100 transition-opacity duration-500"${_scopeId}><div class="w-full max-w-xl text-balance mx-auto text-center"${_scopeId}><h4 class="text-[36px] font-secondary -mb-4.5"${_scopeId}>${ssrInterpolate(project.category)}</h4><h3 class="text-lg uppercase"${_scopeId}>${ssrInterpolate(project.title)}</h3></div></div>`);
            } else {
              return [
                createVNode("div", { class: "relative overflow-hidden aspect-10/6" }, [
                  createVNode("figure", {
                    alt: project.title,
                    class: "cover"
                  }, [
                    project.image ? (openBlock(), createBlock(_component_NuxtImg, {
                      key: 0,
                      alt: project.title,
                      class: project.coverVideo ? "cover transition-opacity duration-300 opacity-100 group-hover:opacity-0" : "cover transition-opacity duration-300 opacity-100",
                      height: "2160",
                      loading: "lazy",
                      src: project.image,
                      width: "3840",
                      sizes: "sm:100vw md:50vw",
                      format: "webp"
                    }, null, 8, ["alt", "class", "src"])) : createCommentVNode("", true),
                    project.coverVideo ? (openBlock(), createBlock("video", {
                      key: 1,
                      class: "cover transition-opacity duration-300 pointer-events-none opacity-0 group-hover:opacity-100",
                      loop: "",
                      muted: "",
                      playsinline: "",
                      preload: "auto",
                      src: project.coverVideo,
                      autoplay: ""
                    }, null, 8, ["src"])) : createCommentVNode("", true)
                  ], 8, ["alt"])
                ]),
                createVNode("div", { class: "absolute inset-0 z-30 flex flex-col items-center justify-center p-4 opacity-0 bg-black/50 group-hover:opacity-100 transition-opacity duration-500" }, [
                  createVNode("div", { class: "w-full max-w-xl text-balance mx-auto text-center" }, [
                    createVNode("h4", { class: "text-[36px] font-secondary -mb-4.5" }, toDisplayString(project.category), 1),
                    createVNode("h3", { class: "text-lg uppercase" }, toDisplayString(project.title), 1)
                  ])
                ])
              ];
            }
          }),
          _: 2
        }, _parent));
      });
      _push(`<!--]--></section></div>`);
    };
  }
});
const _sfc_setup = _sfc_main.setup;
_sfc_main.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("pages/archive/index.vue");
  return _sfc_setup ? _sfc_setup(props, ctx) : void 0;
};
export {
  _sfc_main as default
};
//# sourceMappingURL=index-yvbYWbX3.js.map
