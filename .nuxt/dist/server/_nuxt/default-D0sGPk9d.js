import { _ as __nuxt_component_0 } from "./nuxt-link-R1wnDmRy.js";
import { ref, withCtx, createVNode, createTextVNode, useSSRContext, mergeProps } from "vue";
import { ssrRenderAttrs, ssrRenderComponent, ssrRenderClass, ssrRenderSlot } from "vue/server-renderer";
import { _ as _export_sfc } from "./_plugin-vue_export-helper-1tPrXgE0.js";
import "C:/Users/carus/Documents/Websites/portfolio_v4/node_modules/ufo/dist/index.mjs";
import "../server.mjs";
import "C:/Users/carus/Documents/Websites/portfolio_v4/node_modules/ofetch/dist/node.mjs";
import "#internal/nuxt/paths";
import "C:/Users/carus/Documents/Websites/portfolio_v4/node_modules/hookable/dist/index.mjs";
import "C:/Users/carus/Documents/Websites/portfolio_v4/node_modules/unctx/dist/index.mjs";
import "C:/Users/carus/Documents/Websites/portfolio_v4/node_modules/h3/dist/index.mjs";
import "vue-router";
import "C:/Users/carus/Documents/Websites/portfolio_v4/node_modules/defu/dist/defu.mjs";
import "C:/Users/carus/Documents/Websites/portfolio_v4/node_modules/@unhead/vue/dist/index.mjs";
const _sfc_main$2 = {
  __name: "AppHeader",
  __ssrInlineRender: true,
  setup(__props) {
    const isMenuOpen = ref(false);
    return (_ctx, _push, _parent, _attrs) => {
      const _component_NuxtLink = __nuxt_component_0;
      _push(`<div${ssrRenderAttrs(_attrs)}><div class="fixed inset-x-0 z-20 p-4 mix-blend-difference bg-transparent flex items-center justify-center"><h1 class="m-0 p-0 leading-none flex flex-col items-center">`);
      _push(ssrRenderComponent(_component_NuxtLink, {
        class: "transition-all duration-1000 flex flex-col items-center opacity-100",
        to: "/"
      }, {
        default: withCtx((_, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(`<span class="transform text-2xl md:text-4xl font-secondary tracking-widest text-center whitespace-nowrap block"${_scopeId}> Shot by </span><span class="text-3xl md:text-6xl font-primary translate-y-[-0.7rem] md:translate-y-[-1.2rem] uppercase font-[900] text-center whitespace-nowrap block"${_scopeId}> GIUSEPPE CARUSO </span>`);
          } else {
            return [
              createVNode("span", { class: "transform text-2xl md:text-4xl font-secondary tracking-widest text-center whitespace-nowrap block" }, " Shot by "),
              createVNode("span", { class: "text-3xl md:text-6xl font-primary translate-y-[-0.7rem] md:translate-y-[-1.2rem] uppercase font-[900] text-center whitespace-nowrap block" }, " GIUSEPPE CARUSO ")
            ];
          }
        }),
        _: 1
      }, _parent));
      _push(`</h1></div><header class="container fixed inset-x-0 z-40 py-4"><nav class="items-start w-full text-sm leading-none flex justify-between"><div class="transition-opacity duration-1000 opacity-100"><ul class="uppercase [&amp;_a]:text-primary hidden md:flex gap-x-4"><li>`);
      _push(ssrRenderComponent(_component_NuxtLink, {
        class: "text-primary-dark hover:text-primary transition-colors",
        to: "/archive/",
        "active-class": "text-primary"
      }, {
        default: withCtx((_, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(` Archive `);
          } else {
            return [
              createTextVNode(" Archive ")
            ];
          }
        }),
        _: 1
      }, _parent));
      _push(`</li><li>`);
      _push(ssrRenderComponent(_component_NuxtLink, {
        class: "text-primary-dark hover:text-primary transition-colors",
        to: "/about/",
        "active-class": "text-primary"
      }, {
        default: withCtx((_, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(` About `);
          } else {
            return [
              createTextVNode(" About ")
            ];
          }
        }),
        _: 1
      }, _parent));
      _push(`</li></ul></div><div class="flex justify-end transition-opacity duration-1000 opacity-100"><nav class="flex gap-x-2 hidden md:flex"><button class="uppercase cursor-pointer hover:text-primary transition-colors text-primary">en</button><button class="uppercase cursor-pointer hover:text-primary transition-colors text-primary-dark">it</button></nav><button class="uppercase cursor-pointer md:hidden">Menu</button></div></nav></header><nav class="${ssrRenderClass([isMenuOpen.value ? "opacity-100 pointer-events-auto" : "opacity-0 pointer-events-none", "fixed inset-0 w-full h-dvh bg-black text-cream-lighter flex z-30 transition-opacity duration-300 lg:hidden"])}"><div class="flex flex-col items-center justify-center flex-1 pt-24 pb-8 text-center gap-y-12"><ul class="flex flex-col items-center justify-center flex-1 text-lg uppercase gap-y-2"><li>`);
      _push(ssrRenderComponent(_component_NuxtLink, {
        onClick: ($event) => isMenuOpen.value = false,
        class: "text-primary-dark hover:text-primary transition-colors",
        to: "/archive/",
        "active-class": "text-primary"
      }, {
        default: withCtx((_, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(` Archive `);
          } else {
            return [
              createTextVNode(" Archive ")
            ];
          }
        }),
        _: 1
      }, _parent));
      _push(`</li><li>`);
      _push(ssrRenderComponent(_component_NuxtLink, {
        onClick: ($event) => isMenuOpen.value = false,
        class: "text-primary-dark hover:text-primary transition-colors",
        to: "/about/",
        "active-class": "text-primary"
      }, {
        default: withCtx((_, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(` About `);
          } else {
            return [
              createTextVNode(" About ")
            ];
          }
        }),
        _: 1
      }, _parent));
      _push(`</li></ul><div class="flex gap-x-4"><button class="text-sm uppercase text-primary">English</button><button class="text-sm uppercase text-primary-dark hover:text-primary">Italian</button></div><div><ul class="text-base leading-tight flex flex-col gap-y-1 text-primary-dark [&amp;_a]:hover:text-primary [&amp;_a]:transition-colors flex items-center justify-center text-sm text-center md:hidden"><li>`);
      _push(ssrRenderComponent(_component_NuxtLink, { to: "mailto:directedby@giuseppecaruso.com" }, {
        default: withCtx((_, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(`directedby@giuseppecaruso.com`);
          } else {
            return [
              createTextVNode("directedby@giuseppecaruso.com")
            ];
          }
        }),
        _: 1
      }, _parent));
      _push(`</li><li class="flex gap-2">`);
      _push(ssrRenderComponent(_component_NuxtLink, {
        to: "https://www.instagram.com/giuseppecarusodirector/",
        target: "_blank"
      }, {
        default: withCtx((_, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(`Instagram`);
          } else {
            return [
              createTextVNode("Instagram")
            ];
          }
        }),
        _: 1
      }, _parent));
      _push(ssrRenderComponent(_component_NuxtLink, {
        to: "https://www.linkedin.com/in/giuseppe-caruso/",
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
      _push(ssrRenderComponent(_component_NuxtLink, {
        to: "https://vimeo.com/giuseppecarusodirector",
        target: "_blank"
      }, {
        default: withCtx((_, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(`Vimeo`);
          } else {
            return [
              createTextVNode("Vimeo")
            ];
          }
        }),
        _: 1
      }, _parent));
      _push(`</li><li>`);
      _push(ssrRenderComponent(_component_NuxtLink, { to: "tel:+39 3347043970" }, {
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
      _push(`</li></ul></div></div></nav></div>`);
    };
  }
};
const _sfc_setup$2 = _sfc_main$2.setup;
_sfc_main$2.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("components/AppHeader.vue");
  return _sfc_setup$2 ? _sfc_setup$2(props, ctx) : void 0;
};
const _sfc_main$1 = {};
function _sfc_ssrRender(_ctx, _push, _parent, _attrs) {
  const _component_NuxtLink = __nuxt_component_0;
  _push(`<footer${ssrRenderAttrs(mergeProps({ class: "container flex flex-col py-5 gap-y-6" }, _attrs))}><section class="flex flex-wrap justify-between text-xs text-primary-dark"><article class="flex flex-wrap flex-1 gap-x-5"><div>© 2026 All rights reserved @ Directed by Giuseppe Caruso</div></article><nav class="flex gap-x-2">`);
  _push(ssrRenderComponent(_component_NuxtLink, {
    "aria-label": "Visit my Instagram page",
    class: "hover:text-primary transition-colors",
    to: "https://www.instagram.com/peppecaruso.it/",
    rel: "noopener noreferrer",
    target: "_blank"
  }, {
    default: withCtx((_, _push2, _parent2, _scopeId) => {
      if (_push2) {
        _push2(` Instagram `);
      } else {
        return [
          createTextVNode(" Instagram ")
        ];
      }
    }),
    _: 1
  }, _parent));
  _push(ssrRenderComponent(_component_NuxtLink, {
    "aria-label": "Visit my LinkedIn page",
    class: "hover:text-primary transition-colors",
    to: "https://www.linkedin.com/in/giuseppecaruso00/",
    rel: "noopener noreferrer",
    target: "_blank"
  }, {
    default: withCtx((_, _push2, _parent2, _scopeId) => {
      if (_push2) {
        _push2(` LinkedIn `);
      } else {
        return [
          createTextVNode(" LinkedIn ")
        ];
      }
    }),
    _: 1
  }, _parent));
  _push(`</nav></section></footer>`);
}
const _sfc_setup$1 = _sfc_main$1.setup;
_sfc_main$1.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("components/AppFooter.vue");
  return _sfc_setup$1 ? _sfc_setup$1(props, ctx) : void 0;
};
const __nuxt_component_1 = /* @__PURE__ */ _export_sfc(_sfc_main$1, [["ssrRender", _sfc_ssrRender]]);
const _sfc_main = {
  __name: "default",
  __ssrInlineRender: true,
  setup(__props) {
    return (_ctx, _push, _parent, _attrs) => {
      const _component_AppHeader = _sfc_main$2;
      const _component_AppFooter = __nuxt_component_1;
      _push(`<div${ssrRenderAttrs(mergeProps({
        class: "flex flex-col min-h-svh",
        id: "layout-wrapper"
      }, _attrs))}><div class="fixed top-0 left-0 z-[9999] hidden bg-white rounded-full pointer-events-none follower md:block -translate-y-2 -translate-x-2 size-4 mix-blend-difference opacity-100"></div>`);
      _push(ssrRenderComponent(_component_AppHeader, null, null, _parent));
      _push(`<main class="relative z-10 flex flex-col flex-1 h-full max-w-full" id="main-content">`);
      ssrRenderSlot(_ctx.$slots, "default", {}, null, _push, _parent);
      _push(`</main>`);
      _push(ssrRenderComponent(_component_AppFooter, null, null, _parent));
      _push(`</div>`);
    };
  }
};
const _sfc_setup = _sfc_main.setup;
_sfc_main.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("layouts/default.vue");
  return _sfc_setup ? _sfc_setup(props, ctx) : void 0;
};
export {
  _sfc_main as default
};
//# sourceMappingURL=default-D0sGPk9d.js.map
