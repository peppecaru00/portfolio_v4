import process from 'node:process';globalThis._importMeta_=globalThis._importMeta_||{url:"file:///_entry.js",env:process.env};import http from 'node:http';
import https from 'node:https';
import { EventEmitter } from 'node:events';
import { Buffer as Buffer$1 } from 'node:buffer';
import { promises, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { ipxFSStorage, ipxHttpStorage, createIPX, createIPXH3Handler } from 'ipx';
import { resolve as resolve$1, dirname as dirname$1, join } from 'node:path';
import { createHash } from 'node:crypto';

const suspectProtoRx = /"(?:_|\\u0{2}5[Ff]){2}(?:p|\\u0{2}70)(?:r|\\u0{2}72)(?:o|\\u0{2}6[Ff])(?:t|\\u0{2}74)(?:o|\\u0{2}6[Ff])(?:_|\\u0{2}5[Ff]){2}"\s*:/;
const suspectConstructorRx = /"(?:c|\\u0063)(?:o|\\u006[Ff])(?:n|\\u006[Ee])(?:s|\\u0073)(?:t|\\u0074)(?:r|\\u0072)(?:u|\\u0075)(?:c|\\u0063)(?:t|\\u0074)(?:o|\\u006[Ff])(?:r|\\u0072)"\s*:/;
const JsonSigRx = /^\s*["[{]|^\s*-?\d{1,16}(\.\d{1,17})?([Ee][+-]?\d+)?\s*$/;
function jsonParseTransform(key, value) {
  if (key === "__proto__" || key === "constructor" && value && typeof value === "object" && "prototype" in value) {
    warnKeyDropped(key);
    return;
  }
  return value;
}
function warnKeyDropped(key) {
  console.warn(`[destr] Dropping "${key}" key to prevent prototype pollution.`);
}
function destr(value, options = {}) {
  if (typeof value !== "string") {
    return value;
  }
  if (value[0] === '"' && value[value.length - 1] === '"' && value.indexOf("\\") === -1) {
    return value.slice(1, -1);
  }
  const _value = value.trim();
  if (_value.length <= 9) {
    switch (_value.toLowerCase()) {
      case "true": {
        return true;
      }
      case "false": {
        return false;
      }
      case "undefined": {
        return void 0;
      }
      case "null": {
        return null;
      }
      case "nan": {
        return Number.NaN;
      }
      case "infinity": {
        return Number.POSITIVE_INFINITY;
      }
      case "-infinity": {
        return Number.NEGATIVE_INFINITY;
      }
    }
  }
  if (!JsonSigRx.test(value)) {
    if (options.strict) {
      throw new SyntaxError("[destr] Invalid JSON");
    }
    return value;
  }
  try {
    if (suspectProtoRx.test(value) || suspectConstructorRx.test(value)) {
      if (options.strict) {
        throw new Error("[destr] Possible prototype pollution");
      }
      return JSON.parse(value, jsonParseTransform);
    }
    return JSON.parse(value);
  } catch (error) {
    if (options.strict) {
      throw error;
    }
    return value;
  }
}

const HASH_RE = /#/g;
const AMPERSAND_RE = /&/g;
const SLASH_RE = /\//g;
const EQUAL_RE = /=/g;
const IM_RE = /\?/g;
const PLUS_RE = /\+/g;
const ENC_CARET_RE = /%5e/gi;
const ENC_BACKTICK_RE = /%60/gi;
const ENC_PIPE_RE = /%7c/gi;
const ENC_SPACE_RE = /%20/gi;
const ENC_SLASH_RE = /%2f/gi;
const ENC_ENC_SLASH_RE = /%252f/gi;
function encode(text) {
  return encodeURI("" + text).replace(ENC_PIPE_RE, "|");
}
function encodeQueryValue(input) {
  return encode(typeof input === "string" ? input : JSON.stringify(input)).replace(PLUS_RE, "%2B").replace(ENC_SPACE_RE, "+").replace(HASH_RE, "%23").replace(AMPERSAND_RE, "%26").replace(ENC_BACKTICK_RE, "`").replace(ENC_CARET_RE, "^").replace(SLASH_RE, "%2F");
}
function encodeQueryKey(text) {
  return encodeQueryValue(text).replace(EQUAL_RE, "%3D");
}
function encodePath(text) {
  return encode(text).replace(HASH_RE, "%23").replace(IM_RE, "%3F").replace(ENC_ENC_SLASH_RE, "%2F").replace(AMPERSAND_RE, "%26").replace(PLUS_RE, "%2B");
}
function encodeParam(text) {
  return encodePath(text).replace(SLASH_RE, "%2F");
}
function decode(text = "") {
  try {
    return decodeURIComponent("" + text);
  } catch {
    return "" + text;
  }
}
function decodePath(text) {
  return decode(text.replace(ENC_SLASH_RE, "%252F"));
}
function decodeQueryKey(text) {
  return decode(text.replace(PLUS_RE, " "));
}
function decodeQueryValue(text) {
  return decode(text.replace(PLUS_RE, " "));
}

function parseQuery(parametersString = "") {
  const object = /* @__PURE__ */ Object.create(null);
  if (parametersString[0] === "?") {
    parametersString = parametersString.slice(1);
  }
  for (const parameter of parametersString.split("&")) {
    const s = parameter.match(/([^=]+)=?(.*)/) || [];
    if (s.length < 2) {
      continue;
    }
    const key = decodeQueryKey(s[1]);
    if (key === "__proto__" || key === "constructor") {
      continue;
    }
    const value = decodeQueryValue(s[2] || "");
    if (object[key] === void 0) {
      object[key] = value;
    } else if (Array.isArray(object[key])) {
      object[key].push(value);
    } else {
      object[key] = [object[key], value];
    }
  }
  return object;
}
function encodeQueryItem(key, value) {
  if (typeof value === "number" || typeof value === "boolean") {
    value = String(value);
  }
  if (!value) {
    return encodeQueryKey(key);
  }
  if (Array.isArray(value)) {
    return value.map(
      (_value) => `${encodeQueryKey(key)}=${encodeQueryValue(_value)}`
    ).join("&");
  }
  return `${encodeQueryKey(key)}=${encodeQueryValue(value)}`;
}
function stringifyQuery(query) {
  return Object.keys(query).filter((k) => query[k] !== void 0).map((k) => encodeQueryItem(k, query[k])).filter(Boolean).join("&");
}

const PROTOCOL_STRICT_REGEX = /^[\s\w\0+.-]{2,}:([/\\]{1,2})/;
const PROTOCOL_REGEX = /^[\s\w\0+.-]{2,}:([/\\]{2})?/;
const PROTOCOL_RELATIVE_REGEX = /^([/\\]\s*){2,}[^/\\]/;
const PROTOCOL_SCRIPT_RE = /^[\s\0]*(blob|data|javascript|vbscript):$/i;
const TRAILING_SLASH_RE = /\/$|\/\?|\/#/;
const JOIN_LEADING_SLASH_RE = /^\.?\//;
function hasProtocol(inputString, opts = {}) {
  if (typeof opts === "boolean") {
    opts = { acceptRelative: opts };
  }
  if (opts.strict) {
    return PROTOCOL_STRICT_REGEX.test(inputString);
  }
  return PROTOCOL_REGEX.test(inputString) || (opts.acceptRelative ? PROTOCOL_RELATIVE_REGEX.test(inputString) : false);
}
function isScriptProtocol(protocol) {
  return !!protocol && PROTOCOL_SCRIPT_RE.test(protocol);
}
function hasTrailingSlash(input = "", respectQueryAndFragment) {
  if (!respectQueryAndFragment) {
    return input.endsWith("/");
  }
  return TRAILING_SLASH_RE.test(input);
}
function withoutTrailingSlash(input = "", respectQueryAndFragment) {
  if (!respectQueryAndFragment) {
    return (hasTrailingSlash(input) ? input.slice(0, -1) : input) || "/";
  }
  if (!hasTrailingSlash(input, true)) {
    return input || "/";
  }
  let path = input;
  let fragment = "";
  const fragmentIndex = input.indexOf("#");
  if (fragmentIndex !== -1) {
    path = input.slice(0, fragmentIndex);
    fragment = input.slice(fragmentIndex);
  }
  const [s0, ...s] = path.split("?");
  const cleanPath = s0.endsWith("/") ? s0.slice(0, -1) : s0;
  return (cleanPath || "/") + (s.length > 0 ? `?${s.join("?")}` : "") + fragment;
}
function withTrailingSlash(input = "", respectQueryAndFragment) {
  if (!respectQueryAndFragment) {
    return input.endsWith("/") ? input : input + "/";
  }
  if (hasTrailingSlash(input, true)) {
    return input || "/";
  }
  let path = input;
  let fragment = "";
  const fragmentIndex = input.indexOf("#");
  if (fragmentIndex !== -1) {
    path = input.slice(0, fragmentIndex);
    fragment = input.slice(fragmentIndex);
    if (!path) {
      return fragment;
    }
  }
  const [s0, ...s] = path.split("?");
  return s0 + "/" + (s.length > 0 ? `?${s.join("?")}` : "") + fragment;
}
function hasLeadingSlash(input = "") {
  return input.startsWith("/");
}
function withLeadingSlash(input = "") {
  return hasLeadingSlash(input) ? input : "/" + input;
}
function withBase(input, base) {
  if (isEmptyURL(base) || hasProtocol(input)) {
    return input;
  }
  const _base = withoutTrailingSlash(base);
  if (input.startsWith(_base)) {
    const nextChar = input[_base.length];
    if (!nextChar || nextChar === "/" || nextChar === "?") {
      return input;
    }
  }
  return joinURL(_base, input);
}
function withoutBase(input, base) {
  if (isEmptyURL(base)) {
    return input;
  }
  const _base = withoutTrailingSlash(base);
  if (!input.startsWith(_base)) {
    return input;
  }
  const nextChar = input[_base.length];
  if (nextChar && nextChar !== "/" && nextChar !== "?") {
    return input;
  }
  const trimmed = input.slice(_base.length).replace(/^\/+/, "");
  return "/" + trimmed;
}
function withQuery(input, query) {
  const parsed = parseURL(input);
  const mergedQuery = { ...parseQuery(parsed.search), ...query };
  parsed.search = stringifyQuery(mergedQuery);
  return stringifyParsedURL(parsed);
}
function getQuery$1(input) {
  return parseQuery(parseURL(input).search);
}
function isEmptyURL(url) {
  return !url || url === "/";
}
function isNonEmptyURL(url) {
  return url && url !== "/";
}
function joinURL(base, ...input) {
  let url = base || "";
  for (const segment of input.filter((url2) => isNonEmptyURL(url2))) {
    if (url) {
      const _segment = segment.replace(JOIN_LEADING_SLASH_RE, "");
      url = withTrailingSlash(url) + _segment;
    } else {
      url = segment;
    }
  }
  return url;
}
function joinRelativeURL(..._input) {
  const JOIN_SEGMENT_SPLIT_RE = /\/(?!\/)/;
  const input = _input.filter(Boolean);
  const segments = [];
  let segmentsDepth = 0;
  for (const i of input) {
    if (!i || i === "/") {
      continue;
    }
    for (const [sindex, s] of i.split(JOIN_SEGMENT_SPLIT_RE).entries()) {
      if (!s || s === ".") {
        continue;
      }
      if (s === "..") {
        if (segments.length === 1 && hasProtocol(segments[0])) {
          continue;
        }
        segments.pop();
        segmentsDepth--;
        continue;
      }
      if (sindex === 1 && segments[segments.length - 1]?.endsWith(":/")) {
        segments[segments.length - 1] += "/" + s;
        continue;
      }
      segments.push(s);
      segmentsDepth++;
    }
  }
  let url = segments.join("/");
  if (segmentsDepth >= 0) {
    if (input[0]?.startsWith("/") && !url.startsWith("/")) {
      url = "/" + url;
    } else if (input[0]?.startsWith("./") && !url.startsWith("./")) {
      url = "./" + url;
    }
  } else {
    url = "../".repeat(-1 * segmentsDepth) + url;
  }
  if (input[input.length - 1]?.endsWith("/") && !url.endsWith("/")) {
    url += "/";
  }
  return url;
}

const protocolRelative = Symbol.for("ufo:protocolRelative");
function parseURL(input = "", defaultProto) {
  const _specialProtoMatch = input.match(
    /^[\s\0]*(blob:|data:|javascript:|vbscript:)(.*)/i
  );
  if (_specialProtoMatch) {
    const [, _proto, _pathname = ""] = _specialProtoMatch;
    return {
      protocol: _proto.toLowerCase(),
      pathname: _pathname,
      href: _proto + _pathname,
      auth: "",
      host: "",
      search: "",
      hash: ""
    };
  }
  if (!hasProtocol(input, { acceptRelative: true })) {
    return parsePath(input);
  }
  const [, protocol = "", auth, hostAndPath = ""] = input.replace(/\\/g, "/").match(/^[\s\0]*([\w+.-]{2,}:)?\/\/([^/@]+@)?(.*)/) || [];
  let [, host = "", path = ""] = hostAndPath.match(/([^#/?]*)(.*)?/) || [];
  if (protocol === "file:") {
    path = path.replace(/\/(?=[A-Za-z]:)/, "");
  }
  const { pathname, search, hash } = parsePath(path);
  return {
    protocol: protocol.toLowerCase(),
    auth: auth ? auth.slice(0, Math.max(0, auth.length - 1)) : "",
    host,
    pathname,
    search,
    hash,
    [protocolRelative]: !protocol
  };
}
function parsePath(input = "") {
  const [pathname = "", search = "", hash = ""] = (input.match(/([^#?]*)(\?[^#]*)?(#.*)?/) || []).splice(1);
  return {
    pathname,
    search,
    hash
  };
}
function stringifyParsedURL(parsed) {
  const pathname = parsed.pathname || "";
  const search = parsed.search ? (parsed.search.startsWith("?") ? "" : "?") + parsed.search : "";
  const hash = parsed.hash || "";
  const auth = parsed.auth ? parsed.auth + "@" : "";
  const host = parsed.host || "";
  const proto = parsed.protocol || parsed[protocolRelative] ? (parsed.protocol || "") + "//" : "";
  return proto + auth + host + pathname + search + hash;
}

const NODE_TYPES = {
  NORMAL: 0,
  WILDCARD: 1,
  PLACEHOLDER: 2
};

function createRouter$1(options = {}) {
  const ctx = {
    options,
    rootNode: createRadixNode(),
    staticRoutesMap: {}
  };
  const normalizeTrailingSlash = (p) => options.strictTrailingSlash ? p : p.replace(/\/$/, "") || "/";
  if (options.routes) {
    for (const path in options.routes) {
      insert(ctx, normalizeTrailingSlash(path), options.routes[path]);
    }
  }
  return {
    ctx,
    lookup: (path) => lookup(ctx, normalizeTrailingSlash(path)),
    insert: (path, data) => insert(ctx, normalizeTrailingSlash(path), data),
    remove: (path) => remove(ctx, normalizeTrailingSlash(path))
  };
}
function lookup(ctx, path) {
  const staticPathNode = ctx.staticRoutesMap[path];
  if (staticPathNode) {
    return staticPathNode.data;
  }
  const sections = path.split("/");
  const params = {};
  let paramsFound = false;
  let wildcardNode = null;
  let node = ctx.rootNode;
  let wildCardParam = null;
  for (let i = 0; i < sections.length; i++) {
    const section = sections[i];
    if (node.wildcardChildNode !== null) {
      wildcardNode = node.wildcardChildNode;
      wildCardParam = sections.slice(i).join("/");
    }
    const nextNode = node.children.get(section);
    if (nextNode === void 0) {
      if (node && node.placeholderChildren.length > 1) {
        const remaining = sections.length - i;
        node = node.placeholderChildren.find((c) => c.maxDepth === remaining) || null;
      } else {
        node = node.placeholderChildren[0] || null;
      }
      if (!node) {
        break;
      }
      if (node.paramName) {
        params[node.paramName] = section;
      }
      paramsFound = true;
    } else {
      node = nextNode;
    }
  }
  if ((node === null || node.data === null) && wildcardNode !== null) {
    node = wildcardNode;
    params[node.paramName || "_"] = wildCardParam;
    paramsFound = true;
  }
  if (!node) {
    return null;
  }
  if (paramsFound) {
    return {
      ...node.data,
      params: paramsFound ? params : void 0
    };
  }
  return node.data;
}
function insert(ctx, path, data) {
  let isStaticRoute = true;
  const sections = path.split("/");
  let node = ctx.rootNode;
  let _unnamedPlaceholderCtr = 0;
  const matchedNodes = [node];
  for (const section of sections) {
    let childNode;
    if (childNode = node.children.get(section)) {
      node = childNode;
    } else {
      const type = getNodeType(section);
      childNode = createRadixNode({ type, parent: node });
      node.children.set(section, childNode);
      if (type === NODE_TYPES.PLACEHOLDER) {
        childNode.paramName = section === "*" ? `_${_unnamedPlaceholderCtr++}` : section.slice(1);
        node.placeholderChildren.push(childNode);
        isStaticRoute = false;
      } else if (type === NODE_TYPES.WILDCARD) {
        node.wildcardChildNode = childNode;
        childNode.paramName = section.slice(
          3
          /* "**:" */
        ) || "_";
        isStaticRoute = false;
      }
      matchedNodes.push(childNode);
      node = childNode;
    }
  }
  for (const [depth, node2] of matchedNodes.entries()) {
    node2.maxDepth = Math.max(matchedNodes.length - depth, node2.maxDepth || 0);
  }
  node.data = data;
  if (isStaticRoute === true) {
    ctx.staticRoutesMap[path] = node;
  }
  return node;
}
function remove(ctx, path) {
  let success = false;
  const sections = path.split("/");
  let node = ctx.rootNode;
  for (const section of sections) {
    node = node.children.get(section);
    if (!node) {
      return success;
    }
  }
  if (node.data) {
    const lastSection = sections.at(-1) || "";
    node.data = null;
    if (Object.keys(node.children).length === 0 && node.parent) {
      node.parent.children.delete(lastSection);
      node.parent.wildcardChildNode = null;
      node.parent.placeholderChildren = [];
    }
    success = true;
  }
  return success;
}
function createRadixNode(options = {}) {
  return {
    type: options.type || NODE_TYPES.NORMAL,
    maxDepth: 0,
    parent: options.parent || null,
    children: /* @__PURE__ */ new Map(),
    data: options.data || null,
    paramName: options.paramName || null,
    wildcardChildNode: null,
    placeholderChildren: []
  };
}
function getNodeType(str) {
  if (str.startsWith("**")) {
    return NODE_TYPES.WILDCARD;
  }
  if (str[0] === ":" || str === "*") {
    return NODE_TYPES.PLACEHOLDER;
  }
  return NODE_TYPES.NORMAL;
}

function toRouteMatcher(router) {
  const table = _routerNodeToTable("", router.ctx.rootNode);
  return _createMatcher(table, router.ctx.options.strictTrailingSlash);
}
function _createMatcher(table, strictTrailingSlash) {
  return {
    ctx: { table },
    matchAll: (path) => _matchRoutes(path, table, strictTrailingSlash)
  };
}
function _createRouteTable() {
  return {
    static: /* @__PURE__ */ new Map(),
    wildcard: /* @__PURE__ */ new Map(),
    dynamic: /* @__PURE__ */ new Map()
  };
}
function _matchRoutes(path, table, strictTrailingSlash) {
  if (strictTrailingSlash !== true && path.endsWith("/")) {
    path = path.slice(0, -1) || "/";
  }
  const matches = [];
  for (const [key, value] of _sortRoutesMap(table.wildcard)) {
    if (path === key || path.startsWith(key + "/")) {
      matches.push(value);
    }
  }
  for (const [key, value] of _sortRoutesMap(table.dynamic)) {
    if (path.startsWith(key + "/")) {
      const subPath = "/" + path.slice(key.length).split("/").splice(2).join("/");
      matches.push(..._matchRoutes(subPath, value));
    }
  }
  const staticMatch = table.static.get(path);
  if (staticMatch) {
    matches.push(staticMatch);
  }
  return matches.filter(Boolean);
}
function _sortRoutesMap(m) {
  return [...m.entries()].sort((a, b) => a[0].length - b[0].length);
}
function _routerNodeToTable(initialPath, initialNode) {
  const table = _createRouteTable();
  function _addNode(path, node) {
    if (path) {
      if (node.type === NODE_TYPES.NORMAL && !(path.includes("*") || path.includes(":"))) {
        if (node.data) {
          table.static.set(path, node.data);
        }
      } else if (node.type === NODE_TYPES.WILDCARD) {
        table.wildcard.set(path.replace("/**", ""), node.data);
      } else if (node.type === NODE_TYPES.PLACEHOLDER) {
        const subTable = _routerNodeToTable("", node);
        if (node.data) {
          subTable.static.set("/", node.data);
        }
        table.dynamic.set(path.replace(/\/\*|\/:\w+/, ""), subTable);
        return;
      }
    }
    for (const [childPath, child] of node.children.entries()) {
      _addNode(`${path}/${childPath}`.replace("//", "/"), child);
    }
  }
  _addNode(initialPath, initialNode);
  return table;
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== null && prototype !== Object.prototype && Object.getPrototypeOf(prototype) !== null) {
    return false;
  }
  if (Symbol.iterator in value) {
    return false;
  }
  if (Symbol.toStringTag in value) {
    return Object.prototype.toString.call(value) === "[object Module]";
  }
  return true;
}

function _defu(baseObject, defaults, namespace = ".", merger) {
  if (!isPlainObject(defaults)) {
    return _defu(baseObject, {}, namespace, merger);
  }
  const object = { ...defaults };
  for (const key of Object.keys(baseObject)) {
    if (key === "__proto__" || key === "constructor") {
      continue;
    }
    const value = baseObject[key];
    if (value === null || value === void 0) {
      continue;
    }
    if (merger && merger(object, key, value, namespace)) {
      continue;
    }
    if (Array.isArray(value) && Array.isArray(object[key])) {
      object[key] = [...value, ...object[key]];
    } else if (isPlainObject(value) && isPlainObject(object[key])) {
      object[key] = _defu(
        value,
        object[key],
        (namespace ? `${namespace}.` : "") + key.toString(),
        merger
      );
    } else {
      object[key] = value;
    }
  }
  return object;
}
function createDefu(merger) {
  return (...arguments_) => (
    // eslint-disable-next-line unicorn/no-array-reduce
    arguments_.reduce((p, c) => _defu(p, c, "", merger), {})
  );
}
const defu = createDefu();
const defuFn = createDefu((object, key, currentValue) => {
  if (object[key] !== void 0 && typeof currentValue === "function") {
    object[key] = currentValue(object[key]);
    return true;
  }
});

function o(n){throw new Error(`${n} is not implemented yet!`)}let i$1 = class i extends EventEmitter{__unenv__={};readableEncoding=null;readableEnded=true;readableFlowing=false;readableHighWaterMark=0;readableLength=0;readableObjectMode=false;readableAborted=false;readableDidRead=false;closed=false;errored=null;readable=false;destroyed=false;static from(e,t){return new i(t)}constructor(e){super();}_read(e){}read(e){}setEncoding(e){return this}pause(){return this}resume(){return this}isPaused(){return  true}unpipe(e){return this}unshift(e,t){}wrap(e){return this}push(e,t){return  false}_destroy(e,t){this.removeAllListeners();}destroy(e){return this.destroyed=true,this._destroy(e),this}pipe(e,t){return {}}compose(e,t){throw new Error("Method not implemented.")}[Symbol.asyncDispose](){return this.destroy(),Promise.resolve()}async*[Symbol.asyncIterator](){throw o("Readable.asyncIterator")}iterator(e){throw o("Readable.iterator")}map(e,t){throw o("Readable.map")}filter(e,t){throw o("Readable.filter")}forEach(e,t){throw o("Readable.forEach")}reduce(e,t,r){throw o("Readable.reduce")}find(e,t){throw o("Readable.find")}findIndex(e,t){throw o("Readable.findIndex")}some(e,t){throw o("Readable.some")}toArray(e){throw o("Readable.toArray")}every(e,t){throw o("Readable.every")}flatMap(e,t){throw o("Readable.flatMap")}drop(e,t){throw o("Readable.drop")}take(e,t){throw o("Readable.take")}asIndexedPairs(e){throw o("Readable.asIndexedPairs")}};let l$1 = class l extends EventEmitter{__unenv__={};writable=true;writableEnded=false;writableFinished=false;writableHighWaterMark=0;writableLength=0;writableObjectMode=false;writableCorked=0;closed=false;errored=null;writableNeedDrain=false;writableAborted=false;destroyed=false;_data;_encoding="utf8";constructor(e){super();}pipe(e,t){return {}}_write(e,t,r){if(this.writableEnded){r&&r();return}if(this._data===void 0)this._data=e;else {const s=typeof this._data=="string"?Buffer$1.from(this._data,this._encoding||t||"utf8"):this._data,a=typeof e=="string"?Buffer$1.from(e,t||this._encoding||"utf8"):e;this._data=Buffer$1.concat([s,a]);}this._encoding=t,r&&r();}_writev(e,t){}_destroy(e,t){}_final(e){}write(e,t,r){const s=typeof t=="string"?this._encoding:"utf8",a=typeof t=="function"?t:typeof r=="function"?r:void 0;return this._write(e,s,a),true}setDefaultEncoding(e){return this}end(e,t,r){const s=typeof e=="function"?e:typeof t=="function"?t:typeof r=="function"?r:void 0;if(this.writableEnded)return s&&s(),this;const a=e===s?void 0:e;if(a){const u=t===s?void 0:t;this.write(a,u,s);}return this.writableEnded=true,this.writableFinished=true,this.emit("close"),this.emit("finish"),this}cork(){}uncork(){}destroy(e){return this.destroyed=true,delete this._data,this.removeAllListeners(),this}compose(e,t){throw new Error("Method not implemented.")}[Symbol.asyncDispose](){return Promise.resolve()}};const c=class{allowHalfOpen=true;_destroy;constructor(e=new i$1,t=new l$1){Object.assign(this,e),Object.assign(this,t),this._destroy=m(e._destroy,t._destroy);}};function _(){return Object.assign(c.prototype,i$1.prototype),Object.assign(c.prototype,l$1.prototype),c}function m(...n){return function(...e){for(const t of n)t(...e);}}const g=_();class A extends g{__unenv__={};bufferSize=0;bytesRead=0;bytesWritten=0;connecting=false;destroyed=false;pending=false;localAddress="";localPort=0;remoteAddress="";remoteFamily="";remotePort=0;autoSelectFamilyAttemptedAddresses=[];readyState="readOnly";constructor(e){super();}write(e,t,r){return  false}connect(e,t,r){return this}end(e,t,r){return this}setEncoding(e){return this}pause(){return this}resume(){return this}setTimeout(e,t){return this}setNoDelay(e){return this}setKeepAlive(e,t){return this}address(){return {}}unref(){return this}ref(){return this}destroySoon(){this.destroy();}resetAndDestroy(){const e=new Error("ERR_SOCKET_CLOSED");return e.code="ERR_SOCKET_CLOSED",this.destroy(e),this}}class y extends i$1{aborted=false;httpVersion="1.1";httpVersionMajor=1;httpVersionMinor=1;complete=true;connection;socket;headers={};trailers={};method="GET";url="/";statusCode=200;statusMessage="";closed=false;errored=null;readable=false;constructor(e){super(),this.socket=this.connection=e||new A;}get rawHeaders(){const e=this.headers,t=[];for(const r in e)if(Array.isArray(e[r]))for(const s of e[r])t.push(r,s);else t.push(r,e[r]);return t}get rawTrailers(){return []}setTimeout(e,t){return this}get headersDistinct(){return p(this.headers)}get trailersDistinct(){return p(this.trailers)}}function p(n){const e={};for(const[t,r]of Object.entries(n))t&&(e[t]=(Array.isArray(r)?r:[r]).filter(Boolean));return e}class w extends l$1{statusCode=200;statusMessage="";upgrading=false;chunkedEncoding=false;shouldKeepAlive=false;useChunkedEncodingByDefault=false;sendDate=false;finished=false;headersSent=false;strictContentLength=false;connection=null;socket=null;req;_headers={};constructor(e){super(),this.req=e;}assignSocket(e){e._httpMessage=this,this.socket=e,this.connection=e,this.emit("socket",e),this._flush();}_flush(){this.flushHeaders();}detachSocket(e){}writeContinue(e){}writeHead(e,t,r){e&&(this.statusCode=e),typeof t=="string"&&(this.statusMessage=t,t=void 0);const s=r||t;if(s&&!Array.isArray(s))for(const a in s)this.setHeader(a,s[a]);return this.headersSent=true,this}writeProcessing(){}setTimeout(e,t){return this}appendHeader(e,t){e=e.toLowerCase();const r=this._headers[e],s=[...Array.isArray(r)?r:[r],...Array.isArray(t)?t:[t]].filter(Boolean);return this._headers[e]=s.length>1?s:s[0],this}setHeader(e,t){return this._headers[e.toLowerCase()]=t,this}setHeaders(e){for(const[t,r]of Object.entries(e))this.setHeader(t,r);return this}getHeader(e){return this._headers[e.toLowerCase()]}getHeaders(){return this._headers}getHeaderNames(){return Object.keys(this._headers)}hasHeader(e){return e.toLowerCase()in this._headers}removeHeader(e){delete this._headers[e.toLowerCase()];}addTrailers(e){}flushHeaders(){}writeEarlyHints(e,t){typeof t=="function"&&t();}}const E=(()=>{const n=function(){};return n.prototype=Object.create(null),n})();function R(n={}){const e=new E,t=Array.isArray(n)||H(n)?n:Object.entries(n);for(const[r,s]of t)if(s){if(e[r]===void 0){e[r]=s;continue}e[r]=[...Array.isArray(e[r])?e[r]:[e[r]],...Array.isArray(s)?s:[s]];}return e}function H(n){return typeof n?.entries=="function"}function v(n={}){if(n instanceof Headers)return n;const e=new Headers;for(const[t,r]of Object.entries(n))if(r!==void 0){if(Array.isArray(r)){for(const s of r)e.append(t,String(s));continue}e.set(t,String(r));}return e}const S=new Set([101,204,205,304]);async function b(n,e){const t=new y,r=new w(t);t.url=e.url?.toString()||"/";let s;if(!t.url.startsWith("/")){const d=new URL(t.url);s=d.host,t.url=d.pathname+d.search+d.hash;}t.method=e.method||"GET",t.headers=R(e.headers||{}),t.headers.host||(t.headers.host=e.host||s||"localhost"),t.connection.encrypted=t.connection.encrypted||e.protocol==="https",t.body=e.body||null,t.__unenv__=e.context,await n(t,r);let a=r._data;(S.has(r.statusCode)||t.method.toUpperCase()==="HEAD")&&(a=null,delete r._headers["content-length"]);const u={status:r.statusCode,statusText:r.statusMessage,headers:r._headers,body:a};return t.destroy(),r.destroy(),u}async function C(n,e,t={}){try{const r=await b(n,{url:e,...t});return new Response(r.body,{status:r.status,statusText:r.statusText,headers:v(r.headers)})}catch(r){return new Response(r.toString(),{status:Number.parseInt(r.statusCode||r.code)||500,statusText:r.statusText})}}

function useBase(base, handler) {
  base = withoutTrailingSlash(base);
  if (!base || base === "/") {
    return handler;
  }
  return eventHandler(async (event) => {
    event.node.req.originalUrl = event.node.req.originalUrl || event.node.req.url || "/";
    const _path = event._path || event.node.req.url || "/";
    event._path = withoutBase(event.path || "/", base);
    event.node.req.url = event._path;
    try {
      return await handler(event);
    } finally {
      event._path = event.node.req.url = _path;
    }
  });
}

function hasProp(obj, prop) {
  try {
    return prop in obj;
  } catch {
    return false;
  }
}

class H3Error extends Error {
  static __h3_error__ = true;
  statusCode = 500;
  fatal = false;
  unhandled = false;
  statusMessage;
  data;
  cause;
  constructor(message, opts = {}) {
    super(message, opts);
    if (opts.cause && !this.cause) {
      this.cause = opts.cause;
    }
  }
  toJSON() {
    const obj = {
      message: this.message,
      statusCode: sanitizeStatusCode(this.statusCode, 500)
    };
    if (this.statusMessage) {
      obj.statusMessage = sanitizeStatusMessage(this.statusMessage);
    }
    if (this.data !== void 0) {
      obj.data = this.data;
    }
    return obj;
  }
}
function createError$1(input) {
  if (typeof input === "string") {
    return new H3Error(input);
  }
  if (isError(input)) {
    return input;
  }
  const err = new H3Error(input.message ?? input.statusMessage ?? "", {
    cause: input.cause || input
  });
  if (hasProp(input, "stack")) {
    try {
      Object.defineProperty(err, "stack", {
        get() {
          return input.stack;
        }
      });
    } catch {
      try {
        err.stack = input.stack;
      } catch {
      }
    }
  }
  if (input.data) {
    err.data = input.data;
  }
  if (input.statusCode) {
    err.statusCode = sanitizeStatusCode(input.statusCode, err.statusCode);
  } else if (input.status) {
    err.statusCode = sanitizeStatusCode(input.status, err.statusCode);
  }
  if (input.statusMessage) {
    err.statusMessage = input.statusMessage;
  } else if (input.statusText) {
    err.statusMessage = input.statusText;
  }
  if (err.statusMessage) {
    const originalMessage = err.statusMessage;
    const sanitizedMessage = sanitizeStatusMessage(err.statusMessage);
    if (sanitizedMessage !== originalMessage) {
      console.warn(
        "[h3] Please prefer using `message` for longer error messages instead of `statusMessage`. In the future, `statusMessage` will be sanitized by default."
      );
    }
  }
  if (input.fatal !== void 0) {
    err.fatal = input.fatal;
  }
  if (input.unhandled !== void 0) {
    err.unhandled = input.unhandled;
  }
  return err;
}
function sendError(event, error, debug) {
  if (event.handled) {
    return;
  }
  const h3Error = isError(error) ? error : createError$1(error);
  const responseBody = {
    statusCode: h3Error.statusCode,
    statusMessage: h3Error.statusMessage,
    stack: [],
    data: h3Error.data
  };
  if (debug) {
    responseBody.stack = (h3Error.stack || "").split("\n").map((l) => l.trim());
  }
  if (event.handled) {
    return;
  }
  const _code = Number.parseInt(h3Error.statusCode);
  setResponseStatus(event, _code, h3Error.statusMessage);
  event.node.res.setHeader("content-type", MIMES.json);
  event.node.res.end(JSON.stringify(responseBody, void 0, 2));
}
function isError(input) {
  return input?.constructor?.__h3_error__ === true;
}

function getQuery(event) {
  return getQuery$1(event.path || "");
}
function isMethod(event, expected, allowHead) {
  if (typeof expected === "string") {
    if (event.method === expected) {
      return true;
    }
  } else if (expected.includes(event.method)) {
    return true;
  }
  return false;
}
function assertMethod(event, expected, allowHead) {
  if (!isMethod(event, expected)) {
    throw createError$1({
      statusCode: 405,
      statusMessage: "HTTP method is not allowed."
    });
  }
}
function getRequestHeaders(event) {
  const _headers = {};
  for (const key in event.node.req.headers) {
    const val = event.node.req.headers[key];
    _headers[key] = Array.isArray(val) ? val.filter(Boolean).join(", ") : val;
  }
  return _headers;
}
function getRequestHeader(event, name) {
  const headers = getRequestHeaders(event);
  const value = headers[name.toLowerCase()];
  return value;
}
function getRequestHost(event, opts = {}) {
  if (opts.xForwardedHost) {
    const _header = event.node.req.headers["x-forwarded-host"];
    const xForwardedHost = (_header || "").split(",").shift()?.trim();
    if (xForwardedHost) {
      return xForwardedHost;
    }
  }
  return event.node.req.headers.host || "localhost";
}
function getRequestProtocol(event, opts = {}) {
  if (opts.xForwardedProto !== false && event.node.req.headers["x-forwarded-proto"] === "https") {
    return "https";
  }
  return event.node.req.connection?.encrypted ? "https" : "http";
}
function getRequestURL(event, opts = {}) {
  const host = getRequestHost(event, opts);
  const protocol = getRequestProtocol(event, opts);
  const path = (event.node.req.originalUrl || event.path).replace(
    /^[/\\]+/g,
    "/"
  );
  return new URL(path, `${protocol}://${host}`);
}

const RawBodySymbol = Symbol.for("h3RawBody");
const PayloadMethods$1 = ["PATCH", "POST", "PUT", "DELETE"];
function readRawBody(event, encoding = "utf8") {
  assertMethod(event, PayloadMethods$1);
  const _rawBody = event._requestBody || event.web?.request?.body || event.node.req[RawBodySymbol] || event.node.req.rawBody || event.node.req.body;
  if (_rawBody) {
    const promise2 = Promise.resolve(_rawBody).then((_resolved) => {
      if (Buffer.isBuffer(_resolved)) {
        return _resolved;
      }
      if (typeof _resolved.pipeTo === "function") {
        return new Promise((resolve, reject) => {
          const chunks = [];
          _resolved.pipeTo(
            new WritableStream({
              write(chunk) {
                chunks.push(chunk);
              },
              close() {
                resolve(Buffer.concat(chunks));
              },
              abort(reason) {
                reject(reason);
              }
            })
          ).catch(reject);
        });
      } else if (typeof _resolved.pipe === "function") {
        return new Promise((resolve, reject) => {
          const chunks = [];
          _resolved.on("data", (chunk) => {
            chunks.push(chunk);
          }).on("end", () => {
            resolve(Buffer.concat(chunks));
          }).on("error", reject);
        });
      }
      if (_resolved.constructor === Object) {
        return Buffer.from(JSON.stringify(_resolved));
      }
      if (_resolved instanceof URLSearchParams) {
        return Buffer.from(_resolved.toString());
      }
      if (_resolved instanceof FormData) {
        return new Response(_resolved).bytes().then((uint8arr) => Buffer.from(uint8arr));
      }
      return Buffer.from(_resolved);
    });
    return encoding ? promise2.then((buff) => buff.toString(encoding)) : promise2;
  }
  if (!Number.parseInt(event.node.req.headers["content-length"] || "") && !/\bchunked\b/i.test(
    String(event.node.req.headers["transfer-encoding"] ?? "")
  )) {
    return Promise.resolve(void 0);
  }
  const promise = event.node.req[RawBodySymbol] = new Promise(
    (resolve, reject) => {
      const bodyData = [];
      event.node.req.on("error", (err) => {
        reject(err);
      }).on("data", (chunk) => {
        bodyData.push(chunk);
      }).on("end", () => {
        resolve(Buffer.concat(bodyData));
      });
    }
  );
  const result = encoding ? promise.then((buff) => buff.toString(encoding)) : promise;
  return result;
}
function getRequestWebStream(event) {
  if (!PayloadMethods$1.includes(event.method)) {
    return;
  }
  const bodyStream = event.web?.request?.body || event._requestBody;
  if (bodyStream) {
    return bodyStream;
  }
  const _hasRawBody = RawBodySymbol in event.node.req || "rawBody" in event.node.req || "body" in event.node.req || "__unenv__" in event.node.req;
  if (_hasRawBody) {
    return new ReadableStream({
      async start(controller) {
        const _rawBody = await readRawBody(event, false);
        if (_rawBody) {
          controller.enqueue(_rawBody);
        }
        controller.close();
      }
    });
  }
  return new ReadableStream({
    start: (controller) => {
      event.node.req.on("data", (chunk) => {
        controller.enqueue(chunk);
      });
      event.node.req.on("end", () => {
        controller.close();
      });
      event.node.req.on("error", (err) => {
        controller.error(err);
      });
    }
  });
}

function handleCacheHeaders(event, opts) {
  const cacheControls = ["public", ...opts.cacheControls || []];
  let cacheMatched = false;
  if (opts.maxAge !== void 0) {
    cacheControls.push(`max-age=${+opts.maxAge}`, `s-maxage=${+opts.maxAge}`);
  }
  if (opts.modifiedTime) {
    const modifiedTime = new Date(opts.modifiedTime);
    const ifModifiedSince = event.node.req.headers["if-modified-since"];
    event.node.res.setHeader("last-modified", modifiedTime.toUTCString());
    if (ifModifiedSince && new Date(ifModifiedSince) >= modifiedTime) {
      cacheMatched = true;
    }
  }
  if (opts.etag) {
    event.node.res.setHeader("etag", opts.etag);
    const ifNonMatch = event.node.req.headers["if-none-match"];
    if (ifNonMatch === opts.etag) {
      cacheMatched = true;
    }
  }
  event.node.res.setHeader("cache-control", cacheControls.join(", "));
  if (cacheMatched) {
    event.node.res.statusCode = 304;
    if (!event.handled) {
      event.node.res.end();
    }
    return true;
  }
  return false;
}

const MIMES = {
  html: "text/html",
  json: "application/json"
};

const DISALLOWED_STATUS_CHARS = /[^\u0009\u0020-\u007E]/g;
function sanitizeStatusMessage(statusMessage = "") {
  return statusMessage.replace(DISALLOWED_STATUS_CHARS, "");
}
function sanitizeStatusCode(statusCode, defaultStatusCode = 200) {
  if (!statusCode) {
    return defaultStatusCode;
  }
  if (typeof statusCode === "string") {
    statusCode = Number.parseInt(statusCode, 10);
  }
  if (statusCode < 100 || statusCode > 999) {
    return defaultStatusCode;
  }
  return statusCode;
}
function splitCookiesString(cookiesString) {
  if (Array.isArray(cookiesString)) {
    return cookiesString.flatMap((c) => splitCookiesString(c));
  }
  if (typeof cookiesString !== "string") {
    return [];
  }
  const cookiesStrings = [];
  let pos = 0;
  let start;
  let ch;
  let lastComma;
  let nextStart;
  let cookiesSeparatorFound;
  const skipWhitespace = () => {
    while (pos < cookiesString.length && /\s/.test(cookiesString.charAt(pos))) {
      pos += 1;
    }
    return pos < cookiesString.length;
  };
  const notSpecialChar = () => {
    ch = cookiesString.charAt(pos);
    return ch !== "=" && ch !== ";" && ch !== ",";
  };
  while (pos < cookiesString.length) {
    start = pos;
    cookiesSeparatorFound = false;
    while (skipWhitespace()) {
      ch = cookiesString.charAt(pos);
      if (ch === ",") {
        lastComma = pos;
        pos += 1;
        skipWhitespace();
        nextStart = pos;
        while (pos < cookiesString.length && notSpecialChar()) {
          pos += 1;
        }
        if (pos < cookiesString.length && cookiesString.charAt(pos) === "=") {
          cookiesSeparatorFound = true;
          pos = nextStart;
          cookiesStrings.push(cookiesString.slice(start, lastComma));
          start = pos;
        } else {
          pos = lastComma + 1;
        }
      } else {
        pos += 1;
      }
    }
    if (!cookiesSeparatorFound || pos >= cookiesString.length) {
      cookiesStrings.push(cookiesString.slice(start));
    }
  }
  return cookiesStrings;
}

const defer = typeof setImmediate === "undefined" ? (fn) => fn() : setImmediate;
function send(event, data, type) {
  if (type) {
    defaultContentType(event, type);
  }
  return new Promise((resolve) => {
    defer(() => {
      if (!event.handled) {
        event.node.res.end(data);
      }
      resolve();
    });
  });
}
function sendNoContent(event, code) {
  if (event.handled) {
    return;
  }
  if (!code && event.node.res.statusCode !== 200) {
    code = event.node.res.statusCode;
  }
  const _code = sanitizeStatusCode(code, 204);
  if (_code === 204) {
    event.node.res.removeHeader("content-length");
  }
  event.node.res.writeHead(_code);
  event.node.res.end();
}
function setResponseStatus(event, code, text) {
  if (code) {
    event.node.res.statusCode = sanitizeStatusCode(
      code,
      event.node.res.statusCode
    );
  }
  if (text) {
    event.node.res.statusMessage = sanitizeStatusMessage(text);
  }
}
function getResponseStatus(event) {
  return event.node.res.statusCode;
}
function getResponseStatusText(event) {
  return event.node.res.statusMessage;
}
function defaultContentType(event, type) {
  if (type && event.node.res.statusCode !== 304 && !event.node.res.getHeader("content-type")) {
    event.node.res.setHeader("content-type", type);
  }
}
function sendRedirect(event, location, code = 302) {
  event.node.res.statusCode = sanitizeStatusCode(
    code,
    event.node.res.statusCode
  );
  event.node.res.setHeader("location", location);
  const encodedLoc = location.replace(/"/g, "%22");
  const html = `<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0; url=${encodedLoc}"></head></html>`;
  return send(event, html, MIMES.html);
}
function getResponseHeader(event, name) {
  return event.node.res.getHeader(name);
}
function setResponseHeaders(event, headers) {
  for (const [name, value] of Object.entries(headers)) {
    event.node.res.setHeader(
      name,
      value
    );
  }
}
const setHeaders = setResponseHeaders;
function setResponseHeader(event, name, value) {
  event.node.res.setHeader(name, value);
}
function appendResponseHeader(event, name, value) {
  let current = event.node.res.getHeader(name);
  if (!current) {
    event.node.res.setHeader(name, value);
    return;
  }
  if (!Array.isArray(current)) {
    current = [current.toString()];
  }
  event.node.res.setHeader(name, [...current, value]);
}
function removeResponseHeader(event, name) {
  return event.node.res.removeHeader(name);
}
function isStream(data) {
  if (!data || typeof data !== "object") {
    return false;
  }
  if (typeof data.pipe === "function") {
    if (typeof data._read === "function") {
      return true;
    }
    if (typeof data.abort === "function") {
      return true;
    }
  }
  if (typeof data.pipeTo === "function") {
    return true;
  }
  return false;
}
function isWebResponse(data) {
  return typeof Response !== "undefined" && data instanceof Response;
}
function sendStream(event, stream) {
  if (!stream || typeof stream !== "object") {
    throw new Error("[h3] Invalid stream provided.");
  }
  event.node.res._data = stream;
  if (!event.node.res.socket) {
    event._handled = true;
    return Promise.resolve();
  }
  if (hasProp(stream, "pipeTo") && typeof stream.pipeTo === "function") {
    return stream.pipeTo(
      new WritableStream({
        write(chunk) {
          event.node.res.write(chunk);
        }
      })
    ).then(() => {
      event.node.res.end();
    });
  }
  if (hasProp(stream, "pipe") && typeof stream.pipe === "function") {
    return new Promise((resolve, reject) => {
      stream.pipe(event.node.res);
      if (stream.on) {
        stream.on("end", () => {
          event.node.res.end();
          resolve();
        });
        stream.on("error", (error) => {
          reject(error);
        });
      }
      event.node.res.on("close", () => {
        if (stream.abort) {
          stream.abort();
        }
      });
    });
  }
  throw new Error("[h3] Invalid or incompatible stream provided.");
}
function sendWebResponse(event, response) {
  for (const [key, value] of response.headers) {
    if (key === "set-cookie") {
      event.node.res.appendHeader(key, splitCookiesString(value));
    } else {
      event.node.res.setHeader(key, value);
    }
  }
  if (response.status) {
    event.node.res.statusCode = sanitizeStatusCode(
      response.status,
      event.node.res.statusCode
    );
  }
  if (response.statusText) {
    event.node.res.statusMessage = sanitizeStatusMessage(response.statusText);
  }
  if (response.redirected) {
    event.node.res.setHeader("location", response.url);
  }
  if (!response.body) {
    event.node.res.end();
    return;
  }
  return sendStream(event, response.body);
}

const PayloadMethods = /* @__PURE__ */ new Set(["PATCH", "POST", "PUT", "DELETE"]);
const ignoredHeaders = /* @__PURE__ */ new Set([
  "transfer-encoding",
  "accept-encoding",
  "connection",
  "keep-alive",
  "upgrade",
  "expect",
  "host",
  "accept"
]);
async function proxyRequest(event, target, opts = {}) {
  let body;
  let duplex;
  if (PayloadMethods.has(event.method)) {
    if (opts.streamRequest) {
      body = getRequestWebStream(event);
      duplex = "half";
    } else {
      body = await readRawBody(event, false).catch(() => void 0);
    }
  }
  const method = opts.fetchOptions?.method || event.method;
  const fetchHeaders = mergeHeaders$1(
    getProxyRequestHeaders(event, { host: target.startsWith("/") }),
    opts.fetchOptions?.headers,
    opts.headers
  );
  return sendProxy(event, target, {
    ...opts,
    fetchOptions: {
      method,
      body,
      duplex,
      ...opts.fetchOptions,
      headers: fetchHeaders
    }
  });
}
async function sendProxy(event, target, opts = {}) {
  let response;
  try {
    response = await _getFetch(opts.fetch)(target, {
      headers: opts.headers,
      ignoreResponseError: true,
      // make $ofetch.raw transparent
      ...opts.fetchOptions
    });
  } catch (error) {
    throw createError$1({
      status: 502,
      statusMessage: "Bad Gateway",
      cause: error
    });
  }
  event.node.res.statusCode = sanitizeStatusCode(
    response.status,
    event.node.res.statusCode
  );
  event.node.res.statusMessage = sanitizeStatusMessage(response.statusText);
  const cookies = [];
  for (const [key, value] of response.headers.entries()) {
    if (key === "content-encoding") {
      continue;
    }
    if (key === "content-length") {
      continue;
    }
    if (key === "set-cookie") {
      cookies.push(...splitCookiesString(value));
      continue;
    }
    event.node.res.setHeader(key, value);
  }
  if (cookies.length > 0) {
    event.node.res.setHeader(
      "set-cookie",
      cookies.map((cookie) => {
        if (opts.cookieDomainRewrite) {
          cookie = rewriteCookieProperty(
            cookie,
            opts.cookieDomainRewrite,
            "domain"
          );
        }
        if (opts.cookiePathRewrite) {
          cookie = rewriteCookieProperty(
            cookie,
            opts.cookiePathRewrite,
            "path"
          );
        }
        return cookie;
      })
    );
  }
  if (opts.onResponse) {
    await opts.onResponse(event, response);
  }
  if (response._data !== void 0) {
    return response._data;
  }
  if (event.handled) {
    return;
  }
  if (opts.sendStream === false) {
    const data = new Uint8Array(await response.arrayBuffer());
    return event.node.res.end(data);
  }
  if (response.body) {
    for await (const chunk of response.body) {
      event.node.res.write(chunk);
    }
  }
  return event.node.res.end();
}
function getProxyRequestHeaders(event, opts) {
  const headers = /* @__PURE__ */ Object.create(null);
  const reqHeaders = getRequestHeaders(event);
  for (const name in reqHeaders) {
    if (!ignoredHeaders.has(name) || name === "host" && opts?.host) {
      headers[name] = reqHeaders[name];
    }
  }
  return headers;
}
function fetchWithEvent(event, req, init, options) {
  return _getFetch(options?.fetch)(req, {
    ...init,
    context: init?.context || event.context,
    headers: {
      ...getProxyRequestHeaders(event, {
        host: typeof req === "string" && req.startsWith("/")
      }),
      ...init?.headers
    }
  });
}
function _getFetch(_fetch) {
  if (_fetch) {
    return _fetch;
  }
  if (globalThis.fetch) {
    return globalThis.fetch;
  }
  throw new Error(
    "fetch is not available. Try importing `node-fetch-native/polyfill` for Node.js."
  );
}
function rewriteCookieProperty(header, map, property) {
  const _map = typeof map === "string" ? { "*": map } : map;
  return header.replace(
    new RegExp(`(;\\s*${property}=)([^;]+)`, "gi"),
    (match, prefix, previousValue) => {
      let newValue;
      if (previousValue in _map) {
        newValue = _map[previousValue];
      } else if ("*" in _map) {
        newValue = _map["*"];
      } else {
        return match;
      }
      return newValue ? prefix + newValue : "";
    }
  );
}
function mergeHeaders$1(defaults, ...inputs) {
  const _inputs = inputs.filter(Boolean);
  if (_inputs.length === 0) {
    return defaults;
  }
  const merged = new Headers(defaults);
  for (const input of _inputs) {
    const entries = Array.isArray(input) ? input : typeof input.entries === "function" ? input.entries() : Object.entries(input);
    for (const [key, value] of entries) {
      if (value !== void 0) {
        merged.set(key, value);
      }
    }
  }
  return merged;
}

class H3Event {
  "__is_event__" = true;
  // Context
  node;
  // Node
  web;
  // Web
  context = {};
  // Shared
  // Request
  _method;
  _path;
  _headers;
  _requestBody;
  // Response
  _handled = false;
  // Hooks
  _onBeforeResponseCalled;
  _onAfterResponseCalled;
  constructor(req, res) {
    this.node = { req, res };
  }
  // --- Request ---
  get method() {
    if (!this._method) {
      this._method = (this.node.req.method || "GET").toUpperCase();
    }
    return this._method;
  }
  get path() {
    return this._path || this.node.req.url || "/";
  }
  get headers() {
    if (!this._headers) {
      this._headers = _normalizeNodeHeaders(this.node.req.headers);
    }
    return this._headers;
  }
  // --- Respoonse ---
  get handled() {
    return this._handled || this.node.res.writableEnded || this.node.res.headersSent;
  }
  respondWith(response) {
    return Promise.resolve(response).then(
      (_response) => sendWebResponse(this, _response)
    );
  }
  // --- Utils ---
  toString() {
    return `[${this.method}] ${this.path}`;
  }
  toJSON() {
    return this.toString();
  }
  // --- Deprecated ---
  /** @deprecated Please use `event.node.req` instead. */
  get req() {
    return this.node.req;
  }
  /** @deprecated Please use `event.node.res` instead. */
  get res() {
    return this.node.res;
  }
}
function isEvent(input) {
  return hasProp(input, "__is_event__");
}
function createEvent(req, res) {
  return new H3Event(req, res);
}
function _normalizeNodeHeaders(nodeHeaders) {
  const headers = new Headers();
  for (const [name, value] of Object.entries(nodeHeaders)) {
    if (Array.isArray(value)) {
      for (const item of value) {
        headers.append(name, item);
      }
    } else if (value) {
      headers.set(name, value);
    }
  }
  return headers;
}

function defineEventHandler(handler) {
  if (typeof handler === "function") {
    handler.__is_handler__ = true;
    return handler;
  }
  const _hooks = {
    onRequest: _normalizeArray(handler.onRequest),
    onBeforeResponse: _normalizeArray(handler.onBeforeResponse)
  };
  const _handler = (event) => {
    return _callHandler(event, handler.handler, _hooks);
  };
  _handler.__is_handler__ = true;
  _handler.__resolve__ = handler.handler.__resolve__;
  _handler.__websocket__ = handler.websocket;
  return _handler;
}
function _normalizeArray(input) {
  return input ? Array.isArray(input) ? input : [input] : void 0;
}
async function _callHandler(event, handler, hooks) {
  if (hooks.onRequest) {
    for (const hook of hooks.onRequest) {
      await hook(event);
      if (event.handled) {
        return;
      }
    }
  }
  const body = await handler(event);
  const response = { body };
  if (hooks.onBeforeResponse) {
    for (const hook of hooks.onBeforeResponse) {
      await hook(event, response);
    }
  }
  return response.body;
}
const eventHandler = defineEventHandler;
function isEventHandler(input) {
  return hasProp(input, "__is_handler__");
}
function toEventHandler(input, _, _route) {
  return input;
}
function defineLazyEventHandler(factory) {
  let _promise;
  let _resolved;
  const resolveHandler = () => {
    if (_resolved) {
      return Promise.resolve(_resolved);
    }
    if (!_promise) {
      _promise = Promise.resolve(factory()).then((r) => {
        const handler2 = r.default || r;
        if (typeof handler2 !== "function") {
          throw new TypeError(
            "Invalid lazy handler result. It should be a function:",
            handler2
          );
        }
        _resolved = { handler: toEventHandler(r.default || r) };
        return _resolved;
      });
    }
    return _promise;
  };
  const handler = eventHandler((event) => {
    if (_resolved) {
      return _resolved.handler(event);
    }
    return resolveHandler().then((r) => r.handler(event));
  });
  handler.__resolve__ = resolveHandler;
  return handler;
}
const lazyEventHandler = defineLazyEventHandler;

function createApp(options = {}) {
  const stack = [];
  const handler = createAppEventHandler(stack, options);
  const resolve = createResolver(stack);
  handler.__resolve__ = resolve;
  const getWebsocket = cachedFn(() => websocketOptions(resolve, options));
  const app = {
    // @ts-expect-error
    use: (arg1, arg2, arg3) => use(app, arg1, arg2, arg3),
    resolve,
    handler,
    stack,
    options,
    get websocket() {
      return getWebsocket();
    }
  };
  return app;
}
function use(app, arg1, arg2, arg3) {
  if (Array.isArray(arg1)) {
    for (const i of arg1) {
      use(app, i, arg2, arg3);
    }
  } else if (Array.isArray(arg2)) {
    for (const i of arg2) {
      use(app, arg1, i, arg3);
    }
  } else if (typeof arg1 === "string") {
    app.stack.push(
      normalizeLayer({ ...arg3, route: arg1, handler: arg2 })
    );
  } else if (typeof arg1 === "function") {
    app.stack.push(normalizeLayer({ ...arg2, handler: arg1 }));
  } else {
    app.stack.push(normalizeLayer({ ...arg1 }));
  }
  return app;
}
function createAppEventHandler(stack, options) {
  const spacing = options.debug ? 2 : void 0;
  return eventHandler(async (event) => {
    event.node.req.originalUrl = event.node.req.originalUrl || event.node.req.url || "/";
    const _rawReqUrl = event.node.req.url || "/";
    const _reqPath = _decodePath(event._path || _rawReqUrl);
    event._path = _reqPath;
    const _needsRawUrl = _reqPath !== _rawReqUrl;
    let _layerPath;
    if (options.onRequest) {
      await options.onRequest(event);
    }
    for (const layer of stack) {
      if (layer.route.length > 1) {
        if (!_reqPath.startsWith(layer.route)) {
          continue;
        }
        _layerPath = _reqPath.slice(layer.route.length) || "/";
      } else {
        _layerPath = _reqPath;
      }
      if (layer.match && !layer.match(_layerPath, event)) {
        continue;
      }
      event._path = _layerPath;
      event.node.req.url = _needsRawUrl ? layer.route.length > 1 ? _rawReqUrl.slice(layer.route.length) || "/" : _rawReqUrl : _layerPath;
      const val = await layer.handler(event);
      const _body = val === void 0 ? void 0 : await val;
      if (_body !== void 0) {
        const _response = { body: _body };
        if (options.onBeforeResponse) {
          event._onBeforeResponseCalled = true;
          await options.onBeforeResponse(event, _response);
        }
        await handleHandlerResponse(event, _response.body, spacing);
        if (options.onAfterResponse) {
          event._onAfterResponseCalled = true;
          await options.onAfterResponse(event, _response);
        }
        return;
      }
      if (event.handled) {
        if (options.onAfterResponse) {
          event._onAfterResponseCalled = true;
          await options.onAfterResponse(event, void 0);
        }
        return;
      }
    }
    if (!event.handled) {
      throw createError$1({
        statusCode: 404,
        statusMessage: `Cannot find any path matching ${event.path || "/"}.`
      });
    }
    if (options.onAfterResponse) {
      event._onAfterResponseCalled = true;
      await options.onAfterResponse(event, void 0);
    }
  });
}
function createResolver(stack) {
  return async (path) => {
    let _layerPath;
    for (const layer of stack) {
      if (layer.route === "/" && !layer.handler.__resolve__) {
        continue;
      }
      if (!path.startsWith(layer.route)) {
        continue;
      }
      _layerPath = path.slice(layer.route.length) || "/";
      if (layer.match && !layer.match(_layerPath, void 0)) {
        continue;
      }
      let res = { route: layer.route, handler: layer.handler };
      if (res.handler.__resolve__) {
        const _res = await res.handler.__resolve__(_layerPath);
        if (!_res) {
          continue;
        }
        res = {
          ...res,
          ..._res,
          route: joinURL(res.route || "/", _res.route || "/")
        };
      }
      return res;
    }
  };
}
function normalizeLayer(input) {
  let handler = input.handler;
  if (handler.handler) {
    handler = handler.handler;
  }
  if (input.lazy) {
    handler = lazyEventHandler(handler);
  } else if (!isEventHandler(handler)) {
    handler = toEventHandler(handler, void 0, input.route);
  }
  return {
    route: withoutTrailingSlash(input.route),
    match: input.match,
    handler
  };
}
function handleHandlerResponse(event, val, jsonSpace) {
  if (val === null) {
    return sendNoContent(event);
  }
  if (val) {
    if (isWebResponse(val)) {
      return sendWebResponse(event, val);
    }
    if (isStream(val)) {
      return sendStream(event, val);
    }
    if (val.buffer) {
      return send(event, val);
    }
    if (val.arrayBuffer && typeof val.arrayBuffer === "function") {
      return val.arrayBuffer().then((arrayBuffer) => {
        return send(event, Buffer.from(arrayBuffer), val.type);
      });
    }
    if (val instanceof Error) {
      throw createError$1(val);
    }
    if (typeof val.end === "function") {
      return true;
    }
  }
  const valType = typeof val;
  if (valType === "string") {
    return send(event, val, MIMES.html);
  }
  if (valType === "object" || valType === "boolean" || valType === "number") {
    return send(event, JSON.stringify(val, void 0, jsonSpace), MIMES.json);
  }
  if (valType === "bigint") {
    return send(event, val.toString(), MIMES.json);
  }
  throw createError$1({
    statusCode: 500,
    statusMessage: `[h3] Cannot send ${valType} as response.`
  });
}
function cachedFn(fn) {
  let cache;
  return () => {
    if (!cache) {
      cache = fn();
    }
    return cache;
  };
}
function _decodePath(url) {
  const qIndex = url.indexOf("?");
  const path = qIndex === -1 ? url : url.slice(0, qIndex);
  const query = qIndex === -1 ? "" : url.slice(qIndex);
  const decodedPath = path.includes("%25") ? decodePath(path.replace(/%25/g, "%2525")) : decodePath(path);
  return decodedPath + query;
}
function websocketOptions(evResolver, appOptions) {
  return {
    ...appOptions.websocket,
    async resolve(info) {
      const url = info.request?.url || info.url || "/";
      const { pathname } = typeof url === "string" ? parseURL(url) : url;
      const resolved = await evResolver(pathname);
      return resolved?.handler?.__websocket__ || {};
    }
  };
}

const RouterMethods = [
  "connect",
  "delete",
  "get",
  "head",
  "options",
  "post",
  "put",
  "trace",
  "patch"
];
function createRouter(opts = {}) {
  const _router = createRouter$1({});
  const routes = {};
  let _matcher;
  const router = {};
  const addRoute = (path, handler, method) => {
    let route = routes[path];
    if (!route) {
      routes[path] = route = { path, handlers: {} };
      _router.insert(path, route);
    }
    if (Array.isArray(method)) {
      for (const m of method) {
        addRoute(path, handler, m);
      }
    } else {
      route.handlers[method] = toEventHandler(handler);
    }
    return router;
  };
  router.use = router.add = (path, handler, method) => addRoute(path, handler, method || "all");
  for (const method of RouterMethods) {
    router[method] = (path, handle) => router.add(path, handle, method);
  }
  const matchHandler = (path = "/", method = "get") => {
    const qIndex = path.indexOf("?");
    if (qIndex !== -1) {
      path = path.slice(0, Math.max(0, qIndex));
    }
    const matched = _router.lookup(path);
    if (!matched || !matched.handlers) {
      return {
        error: createError$1({
          statusCode: 404,
          name: "Not Found",
          statusMessage: `Cannot find any route matching ${path || "/"}.`
        })
      };
    }
    let handler = matched.handlers[method] || matched.handlers.all;
    if (!handler) {
      if (!_matcher) {
        _matcher = toRouteMatcher(_router);
      }
      const _matches = _matcher.matchAll(path).reverse();
      for (const _match of _matches) {
        if (_match.handlers[method]) {
          handler = _match.handlers[method];
          matched.handlers[method] = matched.handlers[method] || handler;
          break;
        }
        if (_match.handlers.all) {
          handler = _match.handlers.all;
          matched.handlers.all = matched.handlers.all || handler;
          break;
        }
      }
    }
    if (!handler) {
      return {
        error: createError$1({
          statusCode: 405,
          name: "Method Not Allowed",
          statusMessage: `Method ${method} is not allowed on this route.`
        })
      };
    }
    return { matched, handler };
  };
  const isPreemptive = opts.preemptive || opts.preemtive;
  router.handler = eventHandler((event) => {
    const match = matchHandler(
      event.path,
      event.method.toLowerCase()
    );
    if ("error" in match) {
      if (isPreemptive) {
        throw match.error;
      } else {
        return;
      }
    }
    event.context.matchedRoute = match.matched;
    const params = match.matched.params || {};
    event.context.params = params;
    return Promise.resolve(match.handler(event)).then((res) => {
      if (res === void 0 && isPreemptive) {
        return null;
      }
      return res;
    });
  });
  router.handler.__resolve__ = async (path) => {
    path = withLeadingSlash(path);
    const match = matchHandler(path);
    if ("error" in match) {
      return;
    }
    let res = {
      route: match.matched.path,
      handler: match.handler
    };
    if (match.handler.__resolve__) {
      const _res = await match.handler.__resolve__(path);
      if (!_res) {
        return;
      }
      res = { ...res, ..._res };
    }
    return res;
  };
  return router;
}
function toNodeListener(app) {
  const toNodeHandle = async function(req, res) {
    const event = createEvent(req, res);
    try {
      await app.handler(event);
    } catch (_error) {
      const error = createError$1(_error);
      if (!isError(_error)) {
        error.unhandled = true;
      }
      setResponseStatus(event, error.statusCode, error.statusMessage);
      if (app.options.onError) {
        await app.options.onError(error, event);
      }
      if (event.handled) {
        return;
      }
      if (error.unhandled || error.fatal) {
        console.error("[h3]", error.fatal ? "[fatal]" : "[unhandled]", error);
      }
      if (app.options.onBeforeResponse && !event._onBeforeResponseCalled) {
        await app.options.onBeforeResponse(event, { body: error });
      }
      await sendError(event, error, !!app.options.debug);
      if (app.options.onAfterResponse && !event._onAfterResponseCalled) {
        await app.options.onAfterResponse(event, { body: error });
      }
    }
  };
  return toNodeHandle;
}

function flatHooks(configHooks, hooks = {}, parentName) {
  for (const key in configHooks) {
    const subHook = configHooks[key];
    const name = parentName ? `${parentName}:${key}` : key;
    if (typeof subHook === "object" && subHook !== null) {
      flatHooks(subHook, hooks, name);
    } else if (typeof subHook === "function") {
      hooks[name] = subHook;
    }
  }
  return hooks;
}
const defaultTask = { run: (function_) => function_() };
const _createTask = () => defaultTask;
const createTask = typeof console.createTask !== "undefined" ? console.createTask : _createTask;
function serialTaskCaller(hooks, args) {
  const name = args.shift();
  const task = createTask(name);
  return hooks.reduce(
    (promise, hookFunction) => promise.then(() => task.run(() => hookFunction(...args))),
    Promise.resolve()
  );
}
function parallelTaskCaller(hooks, args) {
  const name = args.shift();
  const task = createTask(name);
  return Promise.all(hooks.map((hook) => task.run(() => hook(...args))));
}
function callEachWith(callbacks, arg0) {
  for (const callback of [...callbacks]) {
    callback(arg0);
  }
}

class Hookable {
  constructor() {
    this._hooks = {};
    this._before = void 0;
    this._after = void 0;
    this._deprecatedMessages = void 0;
    this._deprecatedHooks = {};
    this.hook = this.hook.bind(this);
    this.callHook = this.callHook.bind(this);
    this.callHookWith = this.callHookWith.bind(this);
  }
  hook(name, function_, options = {}) {
    if (!name || typeof function_ !== "function") {
      return () => {
      };
    }
    const originalName = name;
    let dep;
    while (this._deprecatedHooks[name]) {
      dep = this._deprecatedHooks[name];
      name = dep.to;
    }
    if (dep && !options.allowDeprecated) {
      let message = dep.message;
      if (!message) {
        message = `${originalName} hook has been deprecated` + (dep.to ? `, please use ${dep.to}` : "");
      }
      if (!this._deprecatedMessages) {
        this._deprecatedMessages = /* @__PURE__ */ new Set();
      }
      if (!this._deprecatedMessages.has(message)) {
        console.warn(message);
        this._deprecatedMessages.add(message);
      }
    }
    if (!function_.name) {
      try {
        Object.defineProperty(function_, "name", {
          get: () => "_" + name.replace(/\W+/g, "_") + "_hook_cb",
          configurable: true
        });
      } catch {
      }
    }
    this._hooks[name] = this._hooks[name] || [];
    this._hooks[name].push(function_);
    return () => {
      if (function_) {
        this.removeHook(name, function_);
        function_ = void 0;
      }
    };
  }
  hookOnce(name, function_) {
    let _unreg;
    let _function = (...arguments_) => {
      if (typeof _unreg === "function") {
        _unreg();
      }
      _unreg = void 0;
      _function = void 0;
      return function_(...arguments_);
    };
    _unreg = this.hook(name, _function);
    return _unreg;
  }
  removeHook(name, function_) {
    if (this._hooks[name]) {
      const index = this._hooks[name].indexOf(function_);
      if (index !== -1) {
        this._hooks[name].splice(index, 1);
      }
      if (this._hooks[name].length === 0) {
        delete this._hooks[name];
      }
    }
  }
  deprecateHook(name, deprecated) {
    this._deprecatedHooks[name] = typeof deprecated === "string" ? { to: deprecated } : deprecated;
    const _hooks = this._hooks[name] || [];
    delete this._hooks[name];
    for (const hook of _hooks) {
      this.hook(name, hook);
    }
  }
  deprecateHooks(deprecatedHooks) {
    Object.assign(this._deprecatedHooks, deprecatedHooks);
    for (const name in deprecatedHooks) {
      this.deprecateHook(name, deprecatedHooks[name]);
    }
  }
  addHooks(configHooks) {
    const hooks = flatHooks(configHooks);
    const removeFns = Object.keys(hooks).map(
      (key) => this.hook(key, hooks[key])
    );
    return () => {
      for (const unreg of removeFns.splice(0, removeFns.length)) {
        unreg();
      }
    };
  }
  removeHooks(configHooks) {
    const hooks = flatHooks(configHooks);
    for (const key in hooks) {
      this.removeHook(key, hooks[key]);
    }
  }
  removeAllHooks() {
    for (const key in this._hooks) {
      delete this._hooks[key];
    }
  }
  callHook(name, ...arguments_) {
    arguments_.unshift(name);
    return this.callHookWith(serialTaskCaller, name, ...arguments_);
  }
  callHookParallel(name, ...arguments_) {
    arguments_.unshift(name);
    return this.callHookWith(parallelTaskCaller, name, ...arguments_);
  }
  callHookWith(caller, name, ...arguments_) {
    const event = this._before || this._after ? { name, args: arguments_, context: {} } : void 0;
    if (this._before) {
      callEachWith(this._before, event);
    }
    const result = caller(
      name in this._hooks ? [...this._hooks[name]] : [],
      arguments_
    );
    if (result instanceof Promise) {
      return result.finally(() => {
        if (this._after && event) {
          callEachWith(this._after, event);
        }
      });
    }
    if (this._after && event) {
      callEachWith(this._after, event);
    }
    return result;
  }
  beforeEach(function_) {
    this._before = this._before || [];
    this._before.push(function_);
    return () => {
      if (this._before !== void 0) {
        const index = this._before.indexOf(function_);
        if (index !== -1) {
          this._before.splice(index, 1);
        }
      }
    };
  }
  afterEach(function_) {
    this._after = this._after || [];
    this._after.push(function_);
    return () => {
      if (this._after !== void 0) {
        const index = this._after.indexOf(function_);
        if (index !== -1) {
          this._after.splice(index, 1);
        }
      }
    };
  }
}
function createHooks() {
  return new Hookable();
}

const s$1=globalThis.Headers,i=globalThis.AbortController,l=globalThis.fetch||(()=>{throw new Error("[node-fetch-native] Failed to fetch: `globalThis.fetch` is not available!")});

class FetchError extends Error {
  constructor(message, opts) {
    super(message, opts);
    this.name = "FetchError";
    if (opts?.cause && !this.cause) {
      this.cause = opts.cause;
    }
  }
}
function createFetchError(ctx) {
  const errorMessage = ctx.error?.message || ctx.error?.toString() || "";
  const method = ctx.request?.method || ctx.options?.method || "GET";
  const url = ctx.request?.url || String(ctx.request) || "/";
  const requestStr = `[${method}] ${JSON.stringify(url)}`;
  const statusStr = ctx.response ? `${ctx.response.status} ${ctx.response.statusText}` : "<no response>";
  const message = `${requestStr}: ${statusStr}${errorMessage ? ` ${errorMessage}` : ""}`;
  const fetchError = new FetchError(
    message,
    ctx.error ? { cause: ctx.error } : void 0
  );
  for (const key of ["request", "options", "response"]) {
    Object.defineProperty(fetchError, key, {
      get() {
        return ctx[key];
      }
    });
  }
  for (const [key, refKey] of [
    ["data", "_data"],
    ["status", "status"],
    ["statusCode", "status"],
    ["statusText", "statusText"],
    ["statusMessage", "statusText"]
  ]) {
    Object.defineProperty(fetchError, key, {
      get() {
        return ctx.response && ctx.response[refKey];
      }
    });
  }
  return fetchError;
}

const payloadMethods = new Set(
  Object.freeze(["PATCH", "POST", "PUT", "DELETE"])
);
function isPayloadMethod(method = "GET") {
  return payloadMethods.has(method.toUpperCase());
}
function isJSONSerializable(value) {
  if (value === void 0) {
    return false;
  }
  const t = typeof value;
  if (t === "string" || t === "number" || t === "boolean" || t === null) {
    return true;
  }
  if (t !== "object") {
    return false;
  }
  if (Array.isArray(value)) {
    return true;
  }
  if (value.buffer) {
    return false;
  }
  if (value instanceof FormData || value instanceof URLSearchParams) {
    return false;
  }
  return value.constructor && value.constructor.name === "Object" || typeof value.toJSON === "function";
}
const textTypes = /* @__PURE__ */ new Set([
  "image/svg",
  "application/xml",
  "application/xhtml",
  "application/html"
]);
const JSON_RE = /^application\/(?:[\w!#$%&*.^`~-]*\+)?json(;.+)?$/i;
function detectResponseType(_contentType = "") {
  if (!_contentType) {
    return "json";
  }
  const contentType = _contentType.split(";").shift() || "";
  if (JSON_RE.test(contentType)) {
    return "json";
  }
  if (contentType === "text/event-stream") {
    return "stream";
  }
  if (textTypes.has(contentType) || contentType.startsWith("text/")) {
    return "text";
  }
  return "blob";
}
function resolveFetchOptions(request, input, defaults, Headers) {
  const headers = mergeHeaders(
    input?.headers ?? request?.headers,
    defaults?.headers,
    Headers
  );
  let query;
  if (defaults?.query || defaults?.params || input?.params || input?.query) {
    query = {
      ...defaults?.params,
      ...defaults?.query,
      ...input?.params,
      ...input?.query
    };
  }
  return {
    ...defaults,
    ...input,
    query,
    params: query,
    headers
  };
}
function mergeHeaders(input, defaults, Headers) {
  if (!defaults) {
    return new Headers(input);
  }
  const headers = new Headers(defaults);
  if (input) {
    for (const [key, value] of Symbol.iterator in input || Array.isArray(input) ? input : new Headers(input)) {
      headers.set(key, value);
    }
  }
  return headers;
}
async function callHooks(context, hooks) {
  if (hooks) {
    if (Array.isArray(hooks)) {
      for (const hook of hooks) {
        await hook(context);
      }
    } else {
      await hooks(context);
    }
  }
}

const retryStatusCodes = /* @__PURE__ */ new Set([
  408,
  // Request Timeout
  409,
  // Conflict
  425,
  // Too Early (Experimental)
  429,
  // Too Many Requests
  500,
  // Internal Server Error
  502,
  // Bad Gateway
  503,
  // Service Unavailable
  504
  // Gateway Timeout
]);
const nullBodyResponses = /* @__PURE__ */ new Set([101, 204, 205, 304]);
function createFetch(globalOptions = {}) {
  const {
    fetch = globalThis.fetch,
    Headers = globalThis.Headers,
    AbortController = globalThis.AbortController
  } = globalOptions;
  async function onError(context) {
    const isAbort = context.error && context.error.name === "AbortError" && !context.options.timeout || false;
    if (context.options.retry !== false && !isAbort) {
      let retries;
      if (typeof context.options.retry === "number") {
        retries = context.options.retry;
      } else {
        retries = isPayloadMethod(context.options.method) ? 0 : 1;
      }
      const responseCode = context.response && context.response.status || 500;
      if (retries > 0 && (Array.isArray(context.options.retryStatusCodes) ? context.options.retryStatusCodes.includes(responseCode) : retryStatusCodes.has(responseCode))) {
        const retryDelay = typeof context.options.retryDelay === "function" ? context.options.retryDelay(context) : context.options.retryDelay || 0;
        if (retryDelay > 0) {
          await new Promise((resolve) => setTimeout(resolve, retryDelay));
        }
        return $fetchRaw(context.request, {
          ...context.options,
          retry: retries - 1
        });
      }
    }
    const error = createFetchError(context);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(error, $fetchRaw);
    }
    throw error;
  }
  const $fetchRaw = async function $fetchRaw2(_request, _options = {}) {
    const context = {
      request: _request,
      options: resolveFetchOptions(
        _request,
        _options,
        globalOptions.defaults,
        Headers
      ),
      response: void 0,
      error: void 0
    };
    if (context.options.method) {
      context.options.method = context.options.method.toUpperCase();
    }
    if (context.options.onRequest) {
      await callHooks(context, context.options.onRequest);
      if (!(context.options.headers instanceof Headers)) {
        context.options.headers = new Headers(
          context.options.headers || {}
          /* compat */
        );
      }
    }
    if (typeof context.request === "string") {
      if (context.options.baseURL) {
        context.request = withBase(context.request, context.options.baseURL);
      }
      if (context.options.query) {
        context.request = withQuery(context.request, context.options.query);
        delete context.options.query;
      }
      if ("query" in context.options) {
        delete context.options.query;
      }
      if ("params" in context.options) {
        delete context.options.params;
      }
    }
    if (context.options.body && isPayloadMethod(context.options.method)) {
      if (isJSONSerializable(context.options.body)) {
        const contentType = context.options.headers.get("content-type");
        if (typeof context.options.body !== "string") {
          context.options.body = contentType === "application/x-www-form-urlencoded" ? new URLSearchParams(
            context.options.body
          ).toString() : JSON.stringify(context.options.body);
        }
        if (!contentType) {
          context.options.headers.set("content-type", "application/json");
        }
        if (!context.options.headers.has("accept")) {
          context.options.headers.set("accept", "application/json");
        }
      } else if (
        // ReadableStream Body
        "pipeTo" in context.options.body && typeof context.options.body.pipeTo === "function" || // Node.js Stream Body
        typeof context.options.body.pipe === "function"
      ) {
        if (!("duplex" in context.options)) {
          context.options.duplex = "half";
        }
      }
    }
    let abortTimeout;
    if (!context.options.signal && context.options.timeout) {
      const controller = new AbortController();
      abortTimeout = setTimeout(() => {
        const error = new Error(
          "[TimeoutError]: The operation was aborted due to timeout"
        );
        error.name = "TimeoutError";
        error.code = 23;
        controller.abort(error);
      }, context.options.timeout);
      context.options.signal = controller.signal;
    }
    try {
      context.response = await fetch(
        context.request,
        context.options
      );
    } catch (error) {
      context.error = error;
      if (context.options.onRequestError) {
        await callHooks(
          context,
          context.options.onRequestError
        );
      }
      return await onError(context);
    } finally {
      if (abortTimeout) {
        clearTimeout(abortTimeout);
      }
    }
    const hasBody = (context.response.body || // https://github.com/unjs/ofetch/issues/324
    // https://github.com/unjs/ofetch/issues/294
    // https://github.com/JakeChampion/fetch/issues/1454
    context.response._bodyInit) && !nullBodyResponses.has(context.response.status) && context.options.method !== "HEAD";
    if (hasBody) {
      const responseType = (context.options.parseResponse ? "json" : context.options.responseType) || detectResponseType(context.response.headers.get("content-type") || "");
      switch (responseType) {
        case "json": {
          const data = await context.response.text();
          const parseFunction = context.options.parseResponse || destr;
          context.response._data = parseFunction(data);
          break;
        }
        case "stream": {
          context.response._data = context.response.body || context.response._bodyInit;
          break;
        }
        default: {
          context.response._data = await context.response[responseType]();
        }
      }
    }
    if (context.options.onResponse) {
      await callHooks(
        context,
        context.options.onResponse
      );
    }
    if (!context.options.ignoreResponseError && context.response.status >= 400 && context.response.status < 600) {
      if (context.options.onResponseError) {
        await callHooks(
          context,
          context.options.onResponseError
        );
      }
      return await onError(context);
    }
    return context.response;
  };
  const $fetch = async function $fetch2(request, options) {
    const r = await $fetchRaw(request, options);
    return r._data;
  };
  $fetch.raw = $fetchRaw;
  $fetch.native = (...args) => fetch(...args);
  $fetch.create = (defaultOptions = {}, customGlobalOptions = {}) => createFetch({
    ...globalOptions,
    ...customGlobalOptions,
    defaults: {
      ...globalOptions.defaults,
      ...customGlobalOptions.defaults,
      ...defaultOptions
    }
  });
  return $fetch;
}

function createNodeFetch() {
  const useKeepAlive = JSON.parse(process.env.FETCH_KEEP_ALIVE || "false");
  if (!useKeepAlive) {
    return l;
  }
  const agentOptions = { keepAlive: true };
  const httpAgent = new http.Agent(agentOptions);
  const httpsAgent = new https.Agent(agentOptions);
  const nodeFetchOptions = {
    agent(parsedURL) {
      return parsedURL.protocol === "http:" ? httpAgent : httpsAgent;
    }
  };
  return function nodeFetchWithKeepAlive(input, init) {
    return l(input, { ...nodeFetchOptions, ...init });
  };
}
const fetch$1 = globalThis.fetch ? (...args) => globalThis.fetch(...args) : createNodeFetch();
const Headers$1 = globalThis.Headers || s$1;
const AbortController = globalThis.AbortController || i;
const ofetch = createFetch({ fetch: fetch$1, Headers: Headers$1, AbortController });
const $fetch = ofetch;

function wrapToPromise(value) {
  if (!value || typeof value.then !== "function") {
    return Promise.resolve(value);
  }
  return value;
}
function asyncCall(function_, ...arguments_) {
  try {
    return wrapToPromise(function_(...arguments_));
  } catch (error) {
    return Promise.reject(error);
  }
}
function isPrimitive(value) {
  const type = typeof value;
  return value === null || type !== "object" && type !== "function";
}
function isPureObject(value) {
  const proto = Object.getPrototypeOf(value);
  return !proto || proto.isPrototypeOf(Object);
}
function stringify(value) {
  if (isPrimitive(value)) {
    return String(value);
  }
  if (isPureObject(value) || Array.isArray(value)) {
    return JSON.stringify(value);
  }
  if (typeof value.toJSON === "function") {
    return stringify(value.toJSON());
  }
  throw new Error("[unstorage] Cannot stringify value!");
}
const BASE64_PREFIX = "base64:";
function serializeRaw(value) {
  if (typeof value === "string") {
    return value;
  }
  return BASE64_PREFIX + base64Encode(value);
}
function deserializeRaw(value) {
  if (typeof value !== "string") {
    return value;
  }
  if (!value.startsWith(BASE64_PREFIX)) {
    return value;
  }
  return base64Decode(value.slice(BASE64_PREFIX.length));
}
function base64Decode(input) {
  if (globalThis.Buffer) {
    return Buffer.from(input, "base64");
  }
  return Uint8Array.from(
    globalThis.atob(input),
    (c) => c.codePointAt(0)
  );
}
function base64Encode(input) {
  if (globalThis.Buffer) {
    return Buffer.from(input).toString("base64");
  }
  return globalThis.btoa(String.fromCodePoint(...input));
}

const storageKeyProperties = [
  "has",
  "hasItem",
  "get",
  "getItem",
  "getItemRaw",
  "set",
  "setItem",
  "setItemRaw",
  "del",
  "remove",
  "removeItem",
  "getMeta",
  "setMeta",
  "removeMeta",
  "getKeys",
  "clear",
  "mount",
  "unmount"
];
function prefixStorage(storage, base) {
  base = normalizeBaseKey(base);
  if (!base) {
    return storage;
  }
  const nsStorage = { ...storage };
  for (const property of storageKeyProperties) {
    nsStorage[property] = (key = "", ...args) => (
      // @ts-ignore
      storage[property](base + key, ...args)
    );
  }
  nsStorage.getKeys = (key = "", ...arguments_) => storage.getKeys(base + key, ...arguments_).then((keys) => keys.map((key2) => key2.slice(base.length)));
  nsStorage.keys = nsStorage.getKeys;
  nsStorage.getItems = async (items, commonOptions) => {
    const prefixedItems = items.map(
      (item) => typeof item === "string" ? base + item : { ...item, key: base + item.key }
    );
    const results = await storage.getItems(prefixedItems, commonOptions);
    return results.map((entry) => ({
      key: entry.key.slice(base.length),
      value: entry.value
    }));
  };
  nsStorage.setItems = async (items, commonOptions) => {
    const prefixedItems = items.map((item) => ({
      key: base + item.key,
      value: item.value,
      options: item.options
    }));
    return storage.setItems(prefixedItems, commonOptions);
  };
  return nsStorage;
}
function normalizeKey$1(key) {
  if (!key) {
    return "";
  }
  return key.split("?")[0]?.replace(/[/\\]/g, ":").replace(/:+/g, ":").replace(/^:|:$/g, "") || "";
}
function joinKeys(...keys) {
  return normalizeKey$1(keys.join(":"));
}
function normalizeBaseKey(base) {
  base = normalizeKey$1(base);
  return base ? base + ":" : "";
}
function filterKeyByDepth(key, depth) {
  if (depth === void 0) {
    return true;
  }
  let substrCount = 0;
  let index = key.indexOf(":");
  while (index > -1) {
    substrCount++;
    index = key.indexOf(":", index + 1);
  }
  return substrCount <= depth;
}
function filterKeyByBase(key, base) {
  if (base) {
    return key.startsWith(base) && key[key.length - 1] !== "$";
  }
  return key[key.length - 1] !== "$";
}

function defineDriver$1(factory) {
  return factory;
}

const DRIVER_NAME$1 = "memory";
const memory = defineDriver$1(() => {
  const data = /* @__PURE__ */ new Map();
  return {
    name: DRIVER_NAME$1,
    getInstance: () => data,
    hasItem(key) {
      return data.has(key);
    },
    getItem(key) {
      return data.get(key) ?? null;
    },
    getItemRaw(key) {
      return data.get(key) ?? null;
    },
    setItem(key, value) {
      data.set(key, value);
    },
    setItemRaw(key, value) {
      data.set(key, value);
    },
    removeItem(key) {
      data.delete(key);
    },
    getKeys() {
      return [...data.keys()];
    },
    clear() {
      data.clear();
    },
    dispose() {
      data.clear();
    }
  };
});

function createStorage(options = {}) {
  const context = {
    mounts: { "": options.driver || memory() },
    mountpoints: [""],
    watching: false,
    watchListeners: [],
    unwatch: {}
  };
  const getMount = (key) => {
    for (const base of context.mountpoints) {
      if (key.startsWith(base)) {
        return {
          base,
          relativeKey: key.slice(base.length),
          driver: context.mounts[base]
        };
      }
    }
    return {
      base: "",
      relativeKey: key,
      driver: context.mounts[""]
    };
  };
  const getMounts = (base, includeParent) => {
    return context.mountpoints.filter(
      (mountpoint) => mountpoint.startsWith(base) || includeParent && base.startsWith(mountpoint)
    ).map((mountpoint) => ({
      relativeBase: base.length > mountpoint.length ? base.slice(mountpoint.length) : void 0,
      mountpoint,
      driver: context.mounts[mountpoint]
    }));
  };
  const onChange = (event, key) => {
    if (!context.watching) {
      return;
    }
    key = normalizeKey$1(key);
    for (const listener of context.watchListeners) {
      listener(event, key);
    }
  };
  const startWatch = async () => {
    if (context.watching) {
      return;
    }
    context.watching = true;
    for (const mountpoint in context.mounts) {
      context.unwatch[mountpoint] = await watch(
        context.mounts[mountpoint],
        onChange,
        mountpoint
      );
    }
  };
  const stopWatch = async () => {
    if (!context.watching) {
      return;
    }
    for (const mountpoint in context.unwatch) {
      await context.unwatch[mountpoint]();
    }
    context.unwatch = {};
    context.watching = false;
  };
  const runBatch = (items, commonOptions, cb) => {
    const batches = /* @__PURE__ */ new Map();
    const getBatch = (mount) => {
      let batch = batches.get(mount.base);
      if (!batch) {
        batch = {
          driver: mount.driver,
          base: mount.base,
          items: []
        };
        batches.set(mount.base, batch);
      }
      return batch;
    };
    for (const item of items) {
      const isStringItem = typeof item === "string";
      const key = normalizeKey$1(isStringItem ? item : item.key);
      const value = isStringItem ? void 0 : item.value;
      const options2 = isStringItem || !item.options ? commonOptions : { ...commonOptions, ...item.options };
      const mount = getMount(key);
      getBatch(mount).items.push({
        key,
        value,
        relativeKey: mount.relativeKey,
        options: options2
      });
    }
    return Promise.all([...batches.values()].map((batch) => cb(batch))).then(
      (r) => r.flat()
    );
  };
  const storage = {
    // Item
    hasItem(key, opts = {}) {
      key = normalizeKey$1(key);
      const { relativeKey, driver } = getMount(key);
      return asyncCall(driver.hasItem, relativeKey, opts);
    },
    getItem(key, opts = {}) {
      key = normalizeKey$1(key);
      const { relativeKey, driver } = getMount(key);
      return asyncCall(driver.getItem, relativeKey, opts).then(
        (value) => destr(value)
      );
    },
    getItems(items, commonOptions = {}) {
      return runBatch(items, commonOptions, (batch) => {
        if (batch.driver.getItems) {
          return asyncCall(
            batch.driver.getItems,
            batch.items.map((item) => ({
              key: item.relativeKey,
              options: item.options
            })),
            commonOptions
          ).then(
            (r) => r.map((item) => ({
              key: joinKeys(batch.base, item.key),
              value: destr(item.value)
            }))
          );
        }
        return Promise.all(
          batch.items.map((item) => {
            return asyncCall(
              batch.driver.getItem,
              item.relativeKey,
              item.options
            ).then((value) => ({
              key: item.key,
              value: destr(value)
            }));
          })
        );
      });
    },
    getItemRaw(key, opts = {}) {
      key = normalizeKey$1(key);
      const { relativeKey, driver } = getMount(key);
      if (driver.getItemRaw) {
        return asyncCall(driver.getItemRaw, relativeKey, opts);
      }
      return asyncCall(driver.getItem, relativeKey, opts).then(
        (value) => deserializeRaw(value)
      );
    },
    async setItem(key, value, opts = {}) {
      if (value === void 0) {
        return storage.removeItem(key);
      }
      key = normalizeKey$1(key);
      const { relativeKey, driver } = getMount(key);
      if (!driver.setItem) {
        return;
      }
      await asyncCall(driver.setItem, relativeKey, stringify(value), opts);
      if (!driver.watch) {
        onChange("update", key);
      }
    },
    async setItems(items, commonOptions) {
      await runBatch(items, commonOptions, async (batch) => {
        if (batch.driver.setItems) {
          return asyncCall(
            batch.driver.setItems,
            batch.items.map((item) => ({
              key: item.relativeKey,
              value: stringify(item.value),
              options: item.options
            })),
            commonOptions
          );
        }
        if (!batch.driver.setItem) {
          return;
        }
        await Promise.all(
          batch.items.map((item) => {
            return asyncCall(
              batch.driver.setItem,
              item.relativeKey,
              stringify(item.value),
              item.options
            );
          })
        );
      });
    },
    async setItemRaw(key, value, opts = {}) {
      if (value === void 0) {
        return storage.removeItem(key, opts);
      }
      key = normalizeKey$1(key);
      const { relativeKey, driver } = getMount(key);
      if (driver.setItemRaw) {
        await asyncCall(driver.setItemRaw, relativeKey, value, opts);
      } else if (driver.setItem) {
        await asyncCall(driver.setItem, relativeKey, serializeRaw(value), opts);
      } else {
        return;
      }
      if (!driver.watch) {
        onChange("update", key);
      }
    },
    async removeItem(key, opts = {}) {
      if (typeof opts === "boolean") {
        opts = { removeMeta: opts };
      }
      key = normalizeKey$1(key);
      const { relativeKey, driver } = getMount(key);
      if (!driver.removeItem) {
        return;
      }
      await asyncCall(driver.removeItem, relativeKey, opts);
      if (opts.removeMeta || opts.removeMata) {
        await asyncCall(driver.removeItem, relativeKey + "$", opts);
      }
      if (!driver.watch) {
        onChange("remove", key);
      }
    },
    // Meta
    async getMeta(key, opts = {}) {
      if (typeof opts === "boolean") {
        opts = { nativeOnly: opts };
      }
      key = normalizeKey$1(key);
      const { relativeKey, driver } = getMount(key);
      const meta = /* @__PURE__ */ Object.create(null);
      if (driver.getMeta) {
        Object.assign(meta, await asyncCall(driver.getMeta, relativeKey, opts));
      }
      if (!opts.nativeOnly) {
        const value = await asyncCall(
          driver.getItem,
          relativeKey + "$",
          opts
        ).then((value_) => destr(value_));
        if (value && typeof value === "object") {
          if (typeof value.atime === "string") {
            value.atime = new Date(value.atime);
          }
          if (typeof value.mtime === "string") {
            value.mtime = new Date(value.mtime);
          }
          Object.assign(meta, value);
        }
      }
      return meta;
    },
    setMeta(key, value, opts = {}) {
      return this.setItem(key + "$", value, opts);
    },
    removeMeta(key, opts = {}) {
      return this.removeItem(key + "$", opts);
    },
    // Keys
    async getKeys(base, opts = {}) {
      base = normalizeBaseKey(base);
      const mounts = getMounts(base, true);
      let maskedMounts = [];
      const allKeys = [];
      let allMountsSupportMaxDepth = true;
      for (const mount of mounts) {
        if (!mount.driver.flags?.maxDepth) {
          allMountsSupportMaxDepth = false;
        }
        const rawKeys = await asyncCall(
          mount.driver.getKeys,
          mount.relativeBase,
          opts
        );
        for (const key of rawKeys) {
          const fullKey = mount.mountpoint + normalizeKey$1(key);
          if (!maskedMounts.some((p) => fullKey.startsWith(p))) {
            allKeys.push(fullKey);
          }
        }
        maskedMounts = [
          mount.mountpoint,
          ...maskedMounts.filter((p) => !p.startsWith(mount.mountpoint))
        ];
      }
      const shouldFilterByDepth = opts.maxDepth !== void 0 && !allMountsSupportMaxDepth;
      return allKeys.filter(
        (key) => (!shouldFilterByDepth || filterKeyByDepth(key, opts.maxDepth)) && filterKeyByBase(key, base)
      );
    },
    // Utils
    async clear(base, opts = {}) {
      base = normalizeBaseKey(base);
      await Promise.all(
        getMounts(base, false).map(async (m) => {
          if (m.driver.clear) {
            return asyncCall(m.driver.clear, m.relativeBase, opts);
          }
          if (m.driver.removeItem) {
            const keys = await m.driver.getKeys(m.relativeBase || "", opts);
            return Promise.all(
              keys.map((key) => m.driver.removeItem(key, opts))
            );
          }
        })
      );
    },
    async dispose() {
      await Promise.all(
        Object.values(context.mounts).map((driver) => dispose(driver))
      );
    },
    async watch(callback) {
      await startWatch();
      context.watchListeners.push(callback);
      return async () => {
        context.watchListeners = context.watchListeners.filter(
          (listener) => listener !== callback
        );
        if (context.watchListeners.length === 0) {
          await stopWatch();
        }
      };
    },
    async unwatch() {
      context.watchListeners = [];
      await stopWatch();
    },
    // Mount
    mount(base, driver) {
      base = normalizeBaseKey(base);
      if (base && context.mounts[base]) {
        throw new Error(`already mounted at ${base}`);
      }
      if (base) {
        context.mountpoints.push(base);
        context.mountpoints.sort((a, b) => b.length - a.length);
      }
      context.mounts[base] = driver;
      if (context.watching) {
        Promise.resolve(watch(driver, onChange, base)).then((unwatcher) => {
          context.unwatch[base] = unwatcher;
        }).catch(console.error);
      }
      return storage;
    },
    async unmount(base, _dispose = true) {
      base = normalizeBaseKey(base);
      if (!base || !context.mounts[base]) {
        return;
      }
      if (context.watching && base in context.unwatch) {
        context.unwatch[base]?.();
        delete context.unwatch[base];
      }
      if (_dispose) {
        await dispose(context.mounts[base]);
      }
      context.mountpoints = context.mountpoints.filter((key) => key !== base);
      delete context.mounts[base];
    },
    getMount(key = "") {
      key = normalizeKey$1(key) + ":";
      const m = getMount(key);
      return {
        driver: m.driver,
        base: m.base
      };
    },
    getMounts(base = "", opts = {}) {
      base = normalizeKey$1(base);
      const mounts = getMounts(base, opts.parents);
      return mounts.map((m) => ({
        driver: m.driver,
        base: m.mountpoint
      }));
    },
    // Aliases
    keys: (base, opts = {}) => storage.getKeys(base, opts),
    get: (key, opts = {}) => storage.getItem(key, opts),
    set: (key, value, opts = {}) => storage.setItem(key, value, opts),
    has: (key, opts = {}) => storage.hasItem(key, opts),
    del: (key, opts = {}) => storage.removeItem(key, opts),
    remove: (key, opts = {}) => storage.removeItem(key, opts)
  };
  return storage;
}
function watch(driver, onChange, base) {
  return driver.watch ? driver.watch((event, key) => onChange(event, base + key)) : () => {
  };
}
async function dispose(driver) {
  if (typeof driver.dispose === "function") {
    await asyncCall(driver.dispose);
  }
}

const _assets = {

};

const normalizeKey = function normalizeKey(key) {
  if (!key) {
    return "";
  }
  return key.split("?")[0]?.replace(/[/\\]/g, ":").replace(/:+/g, ":").replace(/^:|:$/g, "") || "";
};

const assets$1 = {
  getKeys() {
    return Promise.resolve(Object.keys(_assets))
  },
  hasItem (id) {
    id = normalizeKey(id);
    return Promise.resolve(id in _assets)
  },
  getItem (id) {
    id = normalizeKey(id);
    return Promise.resolve(_assets[id] ? _assets[id].import() : null)
  },
  getMeta (id) {
    id = normalizeKey(id);
    return Promise.resolve(_assets[id] ? _assets[id].meta : {})
  }
};

function defineDriver(factory) {
  return factory;
}
function createError(driver, message, opts) {
  const err = new Error(`[unstorage] [${driver}] ${message}`, opts);
  if (Error.captureStackTrace) {
    Error.captureStackTrace(err, createError);
  }
  return err;
}
function createRequiredError(driver, name) {
  if (Array.isArray(name)) {
    return createError(
      driver,
      `Missing some of the required options ${name.map((n) => "`" + n + "`").join(", ")}`
    );
  }
  return createError(driver, `Missing required option \`${name}\`.`);
}

function ignoreNotfound(err) {
  return err.code === "ENOENT" || err.code === "EISDIR" ? null : err;
}
function ignoreExists(err) {
  return err.code === "EEXIST" ? null : err;
}
async function writeFile(path, data, encoding) {
  await ensuredir(dirname$1(path));
  return promises.writeFile(path, data, encoding);
}
function readFile(path, encoding) {
  return promises.readFile(path, encoding).catch(ignoreNotfound);
}
function unlink(path) {
  return promises.unlink(path).catch(ignoreNotfound);
}
function readdir(dir) {
  return promises.readdir(dir, { withFileTypes: true }).catch(ignoreNotfound).then((r) => r || []);
}
async function ensuredir(dir) {
  if (existsSync(dir)) {
    return;
  }
  await ensuredir(dirname$1(dir)).catch(ignoreExists);
  await promises.mkdir(dir).catch(ignoreExists);
}
async function readdirRecursive(dir, ignore, maxDepth) {
  if (ignore && ignore(dir)) {
    return [];
  }
  const entries = await readdir(dir);
  const files = [];
  await Promise.all(
    entries.map(async (entry) => {
      const entryPath = resolve$1(dir, entry.name);
      if (entry.isDirectory()) {
        if (maxDepth === void 0 || maxDepth > 0) {
          const dirFiles = await readdirRecursive(
            entryPath,
            ignore,
            maxDepth === void 0 ? void 0 : maxDepth - 1
          );
          files.push(...dirFiles.map((f) => entry.name + "/" + f));
        }
      } else {
        if (!(ignore && ignore(entry.name))) {
          files.push(entry.name);
        }
      }
    })
  );
  return files;
}
async function rmRecursive(dir) {
  const entries = await readdir(dir);
  await Promise.all(
    entries.map((entry) => {
      const entryPath = resolve$1(dir, entry.name);
      if (entry.isDirectory()) {
        return rmRecursive(entryPath).then(() => promises.rmdir(entryPath));
      } else {
        return promises.unlink(entryPath);
      }
    })
  );
}

const PATH_TRAVERSE_RE = /\.\.:|\.\.$/;
const DRIVER_NAME = "fs-lite";
const unstorage_47drivers_47fs_45lite = defineDriver((opts = {}) => {
  if (!opts.base) {
    throw createRequiredError(DRIVER_NAME, "base");
  }
  opts.base = resolve$1(opts.base);
  const r = (key) => {
    if (PATH_TRAVERSE_RE.test(key)) {
      throw createError(
        DRIVER_NAME,
        `Invalid key: ${JSON.stringify(key)}. It should not contain .. segments`
      );
    }
    const resolved = join(opts.base, key.replace(/:/g, "/"));
    return resolved;
  };
  return {
    name: DRIVER_NAME,
    options: opts,
    flags: {
      maxDepth: true
    },
    hasItem(key) {
      return existsSync(r(key));
    },
    getItem(key) {
      return readFile(r(key), "utf8");
    },
    getItemRaw(key) {
      return readFile(r(key));
    },
    async getMeta(key) {
      const { atime, mtime, size, birthtime, ctime } = await promises.stat(r(key)).catch(() => ({}));
      return { atime, mtime, size, birthtime, ctime };
    },
    setItem(key, value) {
      if (opts.readOnly) {
        return;
      }
      return writeFile(r(key), value, "utf8");
    },
    setItemRaw(key, value) {
      if (opts.readOnly) {
        return;
      }
      return writeFile(r(key), value);
    },
    removeItem(key) {
      if (opts.readOnly) {
        return;
      }
      return unlink(r(key));
    },
    getKeys(_base, topts) {
      return readdirRecursive(r("."), opts.ignore, topts?.maxDepth);
    },
    async clear() {
      if (opts.readOnly || opts.noClear) {
        return;
      }
      await rmRecursive(r("."));
    }
  };
});

const storage = createStorage({});

storage.mount('/assets', assets$1);

storage.mount('data', unstorage_47drivers_47fs_45lite({"driver":"fsLite","base":"./.data/kv"}));

function useStorage(base = "") {
  return base ? prefixStorage(storage, base) : storage;
}

const e=globalThis.process?.getBuiltinModule?.("crypto")?.hash,r="sha256",s="base64url";function digest(t){if(e)return e(r,t,s);const o=createHash(r).update(t);return globalThis.process?.versions?.webcontainer?o.digest().toString(s):o.digest(s)}

const Hasher = /* @__PURE__ */ (() => {
  class Hasher2 {
    buff = "";
    #context = /* @__PURE__ */ new Map();
    write(str) {
      this.buff += str;
    }
    dispatch(value) {
      const type = value === null ? "null" : typeof value;
      return this[type](value);
    }
    object(object) {
      if (object && typeof object.toJSON === "function") {
        return this.object(object.toJSON());
      }
      const objString = Object.prototype.toString.call(object);
      let objType = "";
      const objectLength = objString.length;
      objType = objectLength < 10 ? "unknown:[" + objString + "]" : objString.slice(8, objectLength - 1);
      objType = objType.toLowerCase();
      let objectNumber = null;
      if ((objectNumber = this.#context.get(object)) === void 0) {
        this.#context.set(object, this.#context.size);
      } else {
        return this.dispatch("[CIRCULAR:" + objectNumber + "]");
      }
      if (typeof Buffer !== "undefined" && Buffer.isBuffer && Buffer.isBuffer(object)) {
        this.write("buffer:");
        return this.write(object.toString("utf8"));
      }
      if (objType !== "object" && objType !== "function" && objType !== "asyncfunction") {
        if (this[objType]) {
          this[objType](object);
        } else {
          this.unknown(object, objType);
        }
      } else {
        const keys = Object.keys(object).sort();
        const extraKeys = [];
        this.write("object:" + (keys.length + extraKeys.length) + ":");
        const dispatchForKey = (key) => {
          this.dispatch(key);
          this.write(":");
          this.dispatch(object[key]);
          this.write(",");
        };
        for (const key of keys) {
          dispatchForKey(key);
        }
        for (const key of extraKeys) {
          dispatchForKey(key);
        }
      }
    }
    array(arr, unordered) {
      unordered = unordered === void 0 ? false : unordered;
      this.write("array:" + arr.length + ":");
      if (!unordered || arr.length <= 1) {
        for (const entry of arr) {
          this.dispatch(entry);
        }
        return;
      }
      const contextAdditions = /* @__PURE__ */ new Map();
      const entries = arr.map((entry) => {
        const hasher = new Hasher2();
        hasher.dispatch(entry);
        for (const [key, value] of hasher.#context) {
          contextAdditions.set(key, value);
        }
        return hasher.toString();
      });
      this.#context = contextAdditions;
      entries.sort();
      return this.array(entries, false);
    }
    date(date) {
      return this.write("date:" + date.toJSON());
    }
    symbol(sym) {
      return this.write("symbol:" + sym.toString());
    }
    unknown(value, type) {
      this.write(type);
      if (!value) {
        return;
      }
      this.write(":");
      if (value && typeof value.entries === "function") {
        return this.array(
          [...value.entries()],
          true
          /* ordered */
        );
      }
    }
    error(err) {
      return this.write("error:" + err.toString());
    }
    boolean(bool) {
      return this.write("bool:" + bool);
    }
    string(string) {
      this.write("string:" + string.length + ":");
      this.write(string);
    }
    function(fn) {
      this.write("fn:");
      if (isNativeFunction(fn)) {
        this.dispatch("[native]");
      } else {
        this.dispatch(fn.toString());
      }
    }
    number(number) {
      return this.write("number:" + number);
    }
    null() {
      return this.write("Null");
    }
    undefined() {
      return this.write("Undefined");
    }
    regexp(regex) {
      return this.write("regex:" + regex.toString());
    }
    arraybuffer(arr) {
      this.write("arraybuffer:");
      return this.dispatch(new Uint8Array(arr));
    }
    url(url) {
      return this.write("url:" + url.toString());
    }
    map(map) {
      this.write("map:");
      const arr = [...map];
      return this.array(arr, false);
    }
    set(set) {
      this.write("set:");
      const arr = [...set];
      return this.array(arr, false);
    }
    bigint(number) {
      return this.write("bigint:" + number.toString());
    }
  }
  for (const type of [
    "uint8array",
    "uint8clampedarray",
    "unt8array",
    "uint16array",
    "unt16array",
    "uint32array",
    "unt32array",
    "float32array",
    "float64array"
  ]) {
    Hasher2.prototype[type] = function(arr) {
      this.write(type + ":");
      return this.array([...arr], false);
    };
  }
  function isNativeFunction(f) {
    if (typeof f !== "function") {
      return false;
    }
    return Function.prototype.toString.call(f).slice(
      -15
      /* "[native code] }".length */
    ) === "[native code] }";
  }
  return Hasher2;
})();
function serialize(object) {
  const hasher = new Hasher();
  hasher.dispatch(object);
  return hasher.buff;
}
function hash(value) {
  return digest(typeof value === "string" ? value : serialize(value)).replace(/[-_]/g, "").slice(0, 10);
}

function defaultCacheOptions() {
  return {
    name: "_",
    base: "/cache",
    swr: true,
    maxAge: 1
  };
}
function defineCachedFunction(fn, opts = {}) {
  opts = { ...defaultCacheOptions(), ...opts };
  const pending = {};
  const group = opts.group || "nitro/functions";
  const name = opts.name || fn.name || "_";
  const integrity = opts.integrity || hash([fn, opts]);
  const validate = opts.validate || ((entry) => entry.value !== void 0);
  async function get(key, resolver, shouldInvalidateCache, event) {
    const cacheKey = [opts.base, group, name, key + ".json"].filter(Boolean).join(":").replace(/:\/$/, ":index");
    let entry = await useStorage().getItem(cacheKey).catch((error) => {
      console.error(`[cache] Cache read error.`, error);
      useNitroApp().captureError(error, { event, tags: ["cache"] });
    }) || {};
    if (typeof entry !== "object") {
      entry = {};
      const error = new Error("Malformed data read from cache.");
      console.error("[cache]", error);
      useNitroApp().captureError(error, { event, tags: ["cache"] });
    }
    const ttl = (opts.maxAge ?? 0) * 1e3;
    if (ttl) {
      entry.expires = Date.now() + ttl;
    }
    const expired = shouldInvalidateCache || entry.integrity !== integrity || ttl && Date.now() - (entry.mtime || 0) > ttl || validate(entry) === false;
    const _resolve = async () => {
      const isPending = pending[key];
      if (!isPending) {
        if (entry.value !== void 0 && (opts.staleMaxAge || 0) >= 0 && opts.swr === false) {
          entry.value = void 0;
          entry.integrity = void 0;
          entry.mtime = void 0;
          entry.expires = void 0;
        }
        pending[key] = Promise.resolve(resolver());
      }
      try {
        entry.value = await pending[key];
      } catch (error) {
        if (!isPending) {
          delete pending[key];
        }
        throw error;
      }
      if (!isPending) {
        entry.mtime = Date.now();
        entry.integrity = integrity;
        delete pending[key];
        if (validate(entry) !== false) {
          let setOpts;
          if (opts.maxAge && !opts.swr) {
            setOpts = { ttl: opts.maxAge };
          }
          const promise = useStorage().setItem(cacheKey, entry, setOpts).catch((error) => {
            console.error(`[cache] Cache write error.`, error);
            useNitroApp().captureError(error, { event, tags: ["cache"] });
          });
          if (event?.waitUntil) {
            event.waitUntil(promise);
          }
        }
      }
    };
    const _resolvePromise = expired ? _resolve() : Promise.resolve();
    if (entry.value === void 0) {
      await _resolvePromise;
    } else if (expired && event && event.waitUntil) {
      event.waitUntil(_resolvePromise);
    }
    if (opts.swr && validate(entry) !== false) {
      _resolvePromise.catch((error) => {
        console.error(`[cache] SWR handler error.`, error);
        useNitroApp().captureError(error, { event, tags: ["cache"] });
      });
      return entry;
    }
    return _resolvePromise.then(() => entry);
  }
  return async (...args) => {
    const shouldBypassCache = await opts.shouldBypassCache?.(...args);
    if (shouldBypassCache) {
      return fn(...args);
    }
    const key = await (opts.getKey || getKey)(...args);
    const shouldInvalidateCache = await opts.shouldInvalidateCache?.(...args);
    const entry = await get(
      key,
      () => fn(...args),
      shouldInvalidateCache,
      args[0] && isEvent(args[0]) ? args[0] : void 0
    );
    let value = entry.value;
    if (opts.transform) {
      value = await opts.transform(entry, ...args) || value;
    }
    return value;
  };
}
function cachedFunction(fn, opts = {}) {
  return defineCachedFunction(fn, opts);
}
function getKey(...args) {
  return args.length > 0 ? hash(args) : "";
}
function escapeKey(key) {
  return String(key).replace(/\W/g, "");
}
function defineCachedEventHandler(handler, opts = defaultCacheOptions()) {
  const variableHeaderNames = (opts.varies || []).filter(Boolean).map((h) => h.toLowerCase()).sort();
  const _opts = {
    ...opts,
    getKey: async (event) => {
      const customKey = await opts.getKey?.(event);
      if (customKey) {
        return escapeKey(customKey);
      }
      const _path = event.node.req.originalUrl || event.node.req.url || event.path;
      let _pathname;
      try {
        _pathname = escapeKey(decodeURI(parseURL(_path).pathname)).slice(0, 16) || "index";
      } catch {
        _pathname = "-";
      }
      const _hashedPath = `${_pathname}.${hash(_path)}`;
      const _headers = variableHeaderNames.map((header) => [header, event.node.req.headers[header]]).map(([name, value]) => `${escapeKey(name)}.${hash(value)}`);
      return [_hashedPath, ..._headers].join(":");
    },
    validate: (entry) => {
      if (!entry.value) {
        return false;
      }
      if (entry.value.code >= 400) {
        return false;
      }
      if (entry.value.body === void 0) {
        return false;
      }
      if (entry.value.headers.etag === "undefined" || entry.value.headers["last-modified"] === "undefined") {
        return false;
      }
      return true;
    },
    group: opts.group || "nitro/handlers",
    integrity: opts.integrity || hash([handler, opts])
  };
  const _cachedHandler = cachedFunction(
    async (incomingEvent) => {
      const variableHeaders = {};
      for (const header of variableHeaderNames) {
        const value = incomingEvent.node.req.headers[header];
        if (value !== void 0) {
          variableHeaders[header] = value;
        }
      }
      const reqProxy = cloneWithProxy(incomingEvent.node.req, {
        headers: variableHeaders
      });
      const resHeaders = {};
      let _resSendBody;
      const resProxy = cloneWithProxy(incomingEvent.node.res, {
        statusCode: 200,
        writableEnded: false,
        writableFinished: false,
        headersSent: false,
        closed: false,
        getHeader(name) {
          return resHeaders[name];
        },
        setHeader(name, value) {
          resHeaders[name] = value;
          return this;
        },
        getHeaderNames() {
          return Object.keys(resHeaders);
        },
        hasHeader(name) {
          return name in resHeaders;
        },
        removeHeader(name) {
          delete resHeaders[name];
        },
        getHeaders() {
          return resHeaders;
        },
        end(chunk, arg2, arg3) {
          if (typeof chunk === "string") {
            _resSendBody = chunk;
          }
          if (typeof arg2 === "function") {
            arg2();
          }
          if (typeof arg3 === "function") {
            arg3();
          }
          return this;
        },
        write(chunk, arg2, arg3) {
          if (typeof chunk === "string") {
            _resSendBody = chunk;
          }
          if (typeof arg2 === "function") {
            arg2(void 0);
          }
          if (typeof arg3 === "function") {
            arg3();
          }
          return true;
        },
        writeHead(statusCode, headers2) {
          this.statusCode = statusCode;
          if (headers2) {
            if (Array.isArray(headers2) || typeof headers2 === "string") {
              throw new TypeError("Raw headers  is not supported.");
            }
            for (const header in headers2) {
              const value = headers2[header];
              if (value !== void 0) {
                this.setHeader(
                  header,
                  value
                );
              }
            }
          }
          return this;
        }
      });
      const event = createEvent(reqProxy, resProxy);
      event.fetch = (url, fetchOptions) => fetchWithEvent(event, url, fetchOptions, {
        fetch: useNitroApp().localFetch
      });
      event.$fetch = (url, fetchOptions) => fetchWithEvent(event, url, fetchOptions, {
        fetch: globalThis.$fetch
      });
      event.waitUntil = incomingEvent.waitUntil;
      event.context = incomingEvent.context;
      event.context.cache = {
        options: _opts
      };
      const body = await handler(event) || _resSendBody;
      const headers = event.node.res.getHeaders();
      headers.etag = String(
        headers.Etag || headers.etag || `W/"${hash(body)}"`
      );
      headers["last-modified"] = String(
        headers["Last-Modified"] || headers["last-modified"] || (/* @__PURE__ */ new Date()).toUTCString()
      );
      const cacheControl = [];
      if (opts.swr) {
        if (opts.maxAge) {
          cacheControl.push(`s-maxage=${opts.maxAge}`);
        }
        if (opts.staleMaxAge) {
          cacheControl.push(`stale-while-revalidate=${opts.staleMaxAge}`);
        } else {
          cacheControl.push("stale-while-revalidate");
        }
      } else if (opts.maxAge) {
        cacheControl.push(`max-age=${opts.maxAge}`);
      }
      if (cacheControl.length > 0) {
        headers["cache-control"] = cacheControl.join(", ");
      }
      const cacheEntry = {
        code: event.node.res.statusCode,
        headers,
        body
      };
      return cacheEntry;
    },
    _opts
  );
  return defineEventHandler(async (event) => {
    if (opts.headersOnly) {
      if (handleCacheHeaders(event, { maxAge: opts.maxAge })) {
        return;
      }
      return handler(event);
    }
    const response = await _cachedHandler(
      event
    );
    if (event.node.res.headersSent || event.node.res.writableEnded) {
      return response.body;
    }
    if (handleCacheHeaders(event, {
      modifiedTime: new Date(response.headers["last-modified"]),
      etag: response.headers.etag,
      maxAge: opts.maxAge
    })) {
      return;
    }
    event.node.res.statusCode = response.code;
    for (const name in response.headers) {
      const value = response.headers[name];
      if (name === "set-cookie") {
        event.node.res.appendHeader(
          name,
          splitCookiesString(value)
        );
      } else {
        if (value !== void 0) {
          event.node.res.setHeader(name, value);
        }
      }
    }
    return response.body;
  });
}
function cloneWithProxy(obj, overrides) {
  return new Proxy(obj, {
    get(target, property, receiver) {
      if (property in overrides) {
        return overrides[property];
      }
      return Reflect.get(target, property, receiver);
    },
    set(target, property, value, receiver) {
      if (property in overrides) {
        overrides[property] = value;
        return true;
      }
      return Reflect.set(target, property, value, receiver);
    }
  });
}
const cachedEventHandler = defineCachedEventHandler;

function klona(x) {
	if (typeof x !== 'object') return x;

	var k, tmp, str=Object.prototype.toString.call(x);

	if (str === '[object Object]') {
		if (x.constructor !== Object && typeof x.constructor === 'function') {
			tmp = new x.constructor();
			for (k in x) {
				if (x.hasOwnProperty(k) && tmp[k] !== x[k]) {
					tmp[k] = klona(x[k]);
				}
			}
		} else {
			tmp = {}; // null
			for (k in x) {
				if (k === '__proto__') {
					Object.defineProperty(tmp, k, {
						value: klona(x[k]),
						configurable: true,
						enumerable: true,
						writable: true,
					});
				} else {
					tmp[k] = klona(x[k]);
				}
			}
		}
		return tmp;
	}

	if (str === '[object Array]') {
		k = x.length;
		for (tmp=Array(k); k--;) {
			tmp[k] = klona(x[k]);
		}
		return tmp;
	}

	if (str === '[object Set]') {
		tmp = new Set;
		x.forEach(function (val) {
			tmp.add(klona(val));
		});
		return tmp;
	}

	if (str === '[object Map]') {
		tmp = new Map;
		x.forEach(function (val, key) {
			tmp.set(klona(key), klona(val));
		});
		return tmp;
	}

	if (str === '[object Date]') {
		return new Date(+x);
	}

	if (str === '[object RegExp]') {
		tmp = new RegExp(x.source, x.flags);
		tmp.lastIndex = x.lastIndex;
		return tmp;
	}

	if (str === '[object DataView]') {
		return new x.constructor( klona(x.buffer) );
	}

	if (str === '[object ArrayBuffer]') {
		return x.slice(0);
	}

	// ArrayBuffer.isView(x)
	// ~> `new` bcuz `Buffer.slice` => ref
	if (str.slice(-6) === 'Array]') {
		return new x.constructor(x);
	}

	return x;
}

const inlineAppConfig = {
  "nuxt": {}
};



const appConfig = defuFn(inlineAppConfig);

const NUMBER_CHAR_RE = /\d/;
const STR_SPLITTERS = ["-", "_", "/", "."];
function isUppercase(char = "") {
  if (NUMBER_CHAR_RE.test(char)) {
    return void 0;
  }
  return char !== char.toLowerCase();
}
function splitByCase(str, separators) {
  const splitters = STR_SPLITTERS;
  const parts = [];
  if (!str || typeof str !== "string") {
    return parts;
  }
  let buff = "";
  let previousUpper;
  let previousSplitter;
  for (const char of str) {
    const isSplitter = splitters.includes(char);
    if (isSplitter === true) {
      parts.push(buff);
      buff = "";
      previousUpper = void 0;
      continue;
    }
    const isUpper = isUppercase(char);
    if (previousSplitter === false) {
      if (previousUpper === false && isUpper === true) {
        parts.push(buff);
        buff = char;
        previousUpper = isUpper;
        continue;
      }
      if (previousUpper === true && isUpper === false && buff.length > 1) {
        const lastChar = buff.at(-1);
        parts.push(buff.slice(0, Math.max(0, buff.length - 1)));
        buff = lastChar + char;
        previousUpper = isUpper;
        continue;
      }
    }
    buff += char;
    previousUpper = isUpper;
    previousSplitter = isSplitter;
  }
  parts.push(buff);
  return parts;
}
function kebabCase(str, joiner) {
  return str ? (Array.isArray(str) ? str : splitByCase(str)).map((p) => p.toLowerCase()).join(joiner) : "";
}
function snakeCase(str) {
  return kebabCase(str || "", "_");
}

function getEnv(key, opts) {
  const envKey = snakeCase(key).toUpperCase();
  return destr(
    process.env[opts.prefix + envKey] ?? process.env[opts.altPrefix + envKey]
  );
}
function _isObject(input) {
  return typeof input === "object" && !Array.isArray(input);
}
function applyEnv(obj, opts, parentKey = "") {
  for (const key in obj) {
    const subKey = parentKey ? `${parentKey}_${key}` : key;
    const envValue = getEnv(subKey, opts);
    if (_isObject(obj[key])) {
      if (_isObject(envValue)) {
        obj[key] = { ...obj[key], ...envValue };
        applyEnv(obj[key], opts, subKey);
      } else if (envValue === void 0) {
        applyEnv(obj[key], opts, subKey);
      } else {
        obj[key] = envValue ?? obj[key];
      }
    } else {
      obj[key] = envValue ?? obj[key];
    }
    if (opts.envExpansion && typeof obj[key] === "string") {
      obj[key] = _expandFromEnv(obj[key]);
    }
  }
  return obj;
}
const envExpandRx = /\{\{([^{}]*)\}\}/g;
function _expandFromEnv(value) {
  return value.replace(envExpandRx, (match, key) => {
    return process.env[key] || match;
  });
}

const _inlineRuntimeConfig = {
  "app": {
    "baseURL": "/",
    "buildId": "3d49e42d-c000-40ce-8521-d027c3c253fb",
    "buildAssetsDir": "/_nuxt/",
    "cdnURL": ""
  },
  "nitro": {
    "envPrefix": "NUXT_",
    "routeRules": {
      "/__nuxt_error": {
        "cache": false
      },
      "/_nuxt/**": {
        "headers": {
          "cache-control": "public, max-age=31536000, immutable"
        }
      }
    }
  },
  "public": {},
  "ipx": {
    "baseURL": "/_ipx",
    "alias": {},
    "fs": {
      "dir": "../public"
    },
    "http": {
      "domains": []
    }
  }
};
const envOptions = {
  prefix: "NITRO_",
  altPrefix: _inlineRuntimeConfig.nitro.envPrefix ?? process.env.NITRO_ENV_PREFIX ?? "_",
  envExpansion: _inlineRuntimeConfig.nitro.envExpansion ?? process.env.NITRO_ENV_EXPANSION ?? false
};
const _sharedRuntimeConfig = _deepFreeze(
  applyEnv(klona(_inlineRuntimeConfig), envOptions)
);
function useRuntimeConfig(event) {
  if (!event) {
    return _sharedRuntimeConfig;
  }
  if (event.context.nitro.runtimeConfig) {
    return event.context.nitro.runtimeConfig;
  }
  const runtimeConfig = klona(_inlineRuntimeConfig);
  applyEnv(runtimeConfig, envOptions);
  event.context.nitro.runtimeConfig = runtimeConfig;
  return runtimeConfig;
}
_deepFreeze(klona(appConfig));
function _deepFreeze(object) {
  const propNames = Object.getOwnPropertyNames(object);
  for (const name of propNames) {
    const value = object[name];
    if (value && typeof value === "object") {
      _deepFreeze(value);
    }
  }
  return Object.freeze(object);
}
new Proxy(/* @__PURE__ */ Object.create(null), {
  get: (_, prop) => {
    console.warn(
      "Please use `useRuntimeConfig()` instead of accessing config directly."
    );
    const runtimeConfig = useRuntimeConfig();
    if (prop in runtimeConfig) {
      return runtimeConfig[prop];
    }
    return void 0;
  }
});

function createContext(opts = {}) {
  let currentInstance;
  let isSingleton = false;
  const checkConflict = (instance) => {
    if (currentInstance && currentInstance !== instance) {
      throw new Error("Context conflict");
    }
  };
  let als;
  if (opts.asyncContext) {
    const _AsyncLocalStorage = opts.AsyncLocalStorage || globalThis.AsyncLocalStorage;
    if (_AsyncLocalStorage) {
      als = new _AsyncLocalStorage();
    } else {
      console.warn("[unctx] `AsyncLocalStorage` is not provided.");
    }
  }
  const _getCurrentInstance = () => {
    if (als) {
      const instance = als.getStore();
      if (instance !== void 0) {
        return instance;
      }
    }
    return currentInstance;
  };
  return {
    use: () => {
      const _instance = _getCurrentInstance();
      if (_instance === void 0) {
        throw new Error("Context is not available");
      }
      return _instance;
    },
    tryUse: () => {
      return _getCurrentInstance();
    },
    set: (instance, replace) => {
      if (!replace) {
        checkConflict(instance);
      }
      currentInstance = instance;
      isSingleton = true;
    },
    unset: () => {
      currentInstance = void 0;
      isSingleton = false;
    },
    call: (instance, callback) => {
      checkConflict(instance);
      currentInstance = instance;
      try {
        return als ? als.run(instance, callback) : callback();
      } finally {
        if (!isSingleton) {
          currentInstance = void 0;
        }
      }
    },
    async callAsync(instance, callback) {
      currentInstance = instance;
      const onRestore = () => {
        currentInstance = instance;
      };
      const onLeave = () => currentInstance === instance ? onRestore : void 0;
      asyncHandlers.add(onLeave);
      try {
        const r = als ? als.run(instance, callback) : callback();
        if (!isSingleton) {
          currentInstance = void 0;
        }
        return await r;
      } finally {
        asyncHandlers.delete(onLeave);
      }
    }
  };
}
function createNamespace(defaultOpts = {}) {
  const contexts = {};
  return {
    get(key, opts = {}) {
      if (!contexts[key]) {
        contexts[key] = createContext({ ...defaultOpts, ...opts });
      }
      return contexts[key];
    }
  };
}
const _globalThis = typeof globalThis !== "undefined" ? globalThis : typeof self !== "undefined" ? self : typeof global !== "undefined" ? global : {};
const globalKey = "__unctx__";
const defaultNamespace = _globalThis[globalKey] || (_globalThis[globalKey] = createNamespace());
const getContext = (key, opts = {}) => defaultNamespace.get(key, opts);
const asyncHandlersKey = "__unctx_async_handlers__";
const asyncHandlers = _globalThis[asyncHandlersKey] || (_globalThis[asyncHandlersKey] = /* @__PURE__ */ new Set());
function executeAsync(function_) {
  const restores = [];
  for (const leaveHandler of asyncHandlers) {
    const restore2 = leaveHandler();
    if (restore2) {
      restores.push(restore2);
    }
  }
  const restore = () => {
    for (const restore2 of restores) {
      restore2();
    }
  };
  let awaitable = function_();
  if (awaitable && typeof awaitable === "object" && "catch" in awaitable) {
    awaitable = awaitable.catch((error) => {
      restore();
      throw error;
    });
  }
  return [awaitable, restore];
}

function isPathInScope(pathname, base) {
  let canonical;
  try {
    const pre = pathname.replace(/%2f/gi, "/").replace(/%5c/gi, "\\");
    canonical = new URL(pre, "http://_").pathname;
  } catch {
    return false;
  }
  return !base || canonical === base || canonical.startsWith(base + "/");
}

const config = useRuntimeConfig();
const _routeRulesMatcher = toRouteMatcher(
  createRouter$1({ routes: config.nitro.routeRules })
);
function createRouteRulesHandler(ctx) {
  return eventHandler((event) => {
    const routeRules = getRouteRules(event);
    if (routeRules.headers) {
      setHeaders(event, routeRules.headers);
    }
    if (routeRules.redirect) {
      let target = routeRules.redirect.to;
      if (target.endsWith("/**")) {
        let targetPath = event.path;
        const strpBase = routeRules.redirect._redirectStripBase;
        if (strpBase) {
          if (!isPathInScope(event.path.split("?")[0], strpBase)) {
            throw createError$1({ statusCode: 400 });
          }
          targetPath = withoutBase(targetPath, strpBase);
        } else if (targetPath.startsWith("//")) {
          targetPath = targetPath.replace(/^\/+/, "/");
        }
        target = joinURL(target.slice(0, -3), targetPath);
      } else if (event.path.includes("?")) {
        const query = getQuery$1(event.path);
        target = withQuery(target, query);
      }
      return sendRedirect(event, target, routeRules.redirect.statusCode);
    }
    if (routeRules.proxy) {
      let target = routeRules.proxy.to;
      if (target.endsWith("/**")) {
        let targetPath = event.path;
        const strpBase = routeRules.proxy._proxyStripBase;
        if (strpBase) {
          if (!isPathInScope(event.path.split("?")[0], strpBase)) {
            throw createError$1({ statusCode: 400 });
          }
          targetPath = withoutBase(targetPath, strpBase);
        } else if (targetPath.startsWith("//")) {
          targetPath = targetPath.replace(/^\/+/, "/");
        }
        target = joinURL(target.slice(0, -3), targetPath);
      } else if (event.path.includes("?")) {
        const query = getQuery$1(event.path);
        target = withQuery(target, query);
      }
      return proxyRequest(event, target, {
        fetch: ctx.localFetch,
        ...routeRules.proxy
      });
    }
  });
}
function getRouteRules(event) {
  event.context._nitro = event.context._nitro || {};
  if (!event.context._nitro.routeRules) {
    event.context._nitro.routeRules = getRouteRulesForPath(
      withoutBase(event.path.split("?")[0], useRuntimeConfig().app.baseURL)
    );
  }
  return event.context._nitro.routeRules;
}
function getRouteRulesForPath(path) {
  return defu({}, ..._routeRulesMatcher.matchAll(path).reverse());
}

function _captureError(error, type) {
  console.error(`[${type}]`, error);
  useNitroApp().captureError(error, { tags: [type] });
}
function trapUnhandledNodeErrors() {
  process.on(
    "unhandledRejection",
    (error) => _captureError(error, "unhandledRejection")
  );
  process.on(
    "uncaughtException",
    (error) => _captureError(error, "uncaughtException")
  );
}
function joinHeaders(value) {
  return Array.isArray(value) ? value.join(", ") : String(value);
}
function normalizeFetchResponse(response) {
  if (!response.headers.has("set-cookie")) {
    return response;
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: normalizeCookieHeaders(response.headers)
  });
}
function normalizeCookieHeader(header = "") {
  return splitCookiesString(joinHeaders(header));
}
function normalizeCookieHeaders(headers) {
  const outgoingHeaders = new Headers();
  for (const [name, header] of headers) {
    if (name === "set-cookie") {
      for (const cookie of normalizeCookieHeader(header)) {
        outgoingHeaders.append("set-cookie", cookie);
      }
    } else {
      outgoingHeaders.set(name, joinHeaders(header));
    }
  }
  return outgoingHeaders;
}

function isJsonRequest(event) {
	
	if (hasReqHeader(event, "accept", "text/html")) {
		return false;
	}
	return hasReqHeader(event, "accept", "application/json") || hasReqHeader(event, "user-agent", "curl/") || hasReqHeader(event, "user-agent", "httpie/") || hasReqHeader(event, "sec-fetch-mode", "cors") || event.path.startsWith("/api/") || event.path.endsWith(".json");
}
function hasReqHeader(event, name, includes) {
	const value = getRequestHeader(event, name);
	return !!(value && typeof value === "string" && value.toLowerCase().includes(includes));
}

const errorHandler$0 = (async function errorhandler(error, event, { defaultHandler }) {
	if (event.handled || isJsonRequest(event)) {
		
		return;
	}
	
	const defaultRes = await defaultHandler(error, event, { json: true });
	
	const status = error.status || error.statusCode || 500;
	if (status === 404 && defaultRes.status === 302) {
		setResponseHeaders(event, defaultRes.headers);
		setResponseStatus(event, defaultRes.status, defaultRes.statusText);
		return send(event, JSON.stringify(defaultRes.body, null, 2));
	}
	const errorObject = defaultRes.body;
	
	const url = new URL(errorObject.url);
	errorObject.url = withoutBase(url.pathname, useRuntimeConfig(event).app.baseURL) + url.search + url.hash;
	
	errorObject.message = error.unhandled ? errorObject.message || "Server Error" : error.message || errorObject.message || "Server Error";
	
	errorObject.data ||= error.data;
	errorObject.statusText ||= error.statusText || error.statusMessage;
	delete defaultRes.headers["content-type"];
	delete defaultRes.headers["content-security-policy"];
	setResponseHeaders(event, defaultRes.headers);
	
	const reqHeaders = getRequestHeaders(event);
	
	const isRenderingError = event.path.startsWith("/__nuxt_error") || !!reqHeaders["x-nuxt-error"];
	
	const res = isRenderingError ? null : await useNitroApp().localFetch(withQuery(joinURL(useRuntimeConfig(event).app.baseURL, "/__nuxt_error"), errorObject), {
		headers: {
			...reqHeaders,
			"x-nuxt-error": "true"
		},
		redirect: "manual"
	}).catch(() => null);
	if (event.handled) {
		return;
	}
	
	if (!res) {
		const { template } = await import('./error-500.mjs');
		setResponseHeader(event, "Content-Type", "text/html;charset=UTF-8");
		return send(event, template(errorObject));
	}
	const html = await res.text();
	for (const [header, value] of res.headers.entries()) {
		if (header === "set-cookie") {
			appendResponseHeader(event, header, value);
			continue;
		}
		setResponseHeader(event, header, value);
	}
	setResponseStatus(event, res.status && res.status !== 200 ? res.status : defaultRes.status, res.statusText || defaultRes.statusText);
	return send(event, html);
});

function defineNitroErrorHandler(handler) {
  return handler;
}

const errorHandler$1 = defineNitroErrorHandler(
  function defaultNitroErrorHandler(error, event) {
    const res = defaultHandler(error, event);
    setResponseHeaders(event, res.headers);
    setResponseStatus(event, res.status, res.statusText);
    return send(event, JSON.stringify(res.body, null, 2));
  }
);
function defaultHandler(error, event, opts) {
  const isSensitive = error.unhandled || error.fatal;
  const statusCode = error.statusCode || 500;
  const statusMessage = error.statusMessage || "Server Error";
  const url = getRequestURL(event, { xForwardedHost: true, xForwardedProto: true });
  if (statusCode === 404) {
    const baseURL = "/";
    if (/^\/[^/]/.test(baseURL) && !url.pathname.startsWith(baseURL)) {
      const redirectTo = `${baseURL}${url.pathname.slice(1)}${url.search}`;
      return {
        status: 302,
        statusText: "Found",
        headers: { location: redirectTo },
        body: `Redirecting...`
      };
    }
  }
  if (isSensitive && !opts?.silent) {
    const tags = [error.unhandled && "[unhandled]", error.fatal && "[fatal]"].filter(Boolean).join(" ");
    console.error(`[request error] ${tags} [${event.method}] ${url}
`, error);
  }
  const headers = {
    "content-type": "application/json",
    // Prevent browser from guessing the MIME types of resources.
    "x-content-type-options": "nosniff",
    // Prevent error page from being embedded in an iframe
    "x-frame-options": "DENY",
    // Prevent browsers from sending the Referer header
    "referrer-policy": "no-referrer",
    // Disable the execution of any js
    "content-security-policy": "script-src 'none'; frame-ancestors 'none';"
  };
  setResponseStatus(event, statusCode, statusMessage);
  if (statusCode === 404 || !getResponseHeader(event, "cache-control")) {
    headers["cache-control"] = "no-cache";
  }
  const body = {
    error: true,
    url: url.href,
    statusCode,
    statusMessage,
    message: isSensitive ? "Server Error" : error.message,
    data: isSensitive ? void 0 : error.data
  };
  return {
    status: statusCode,
    statusText: statusMessage,
    headers,
    body
  };
}

const errorHandlers = [errorHandler$0, errorHandler$1];

async function errorHandler(error, event) {
  for (const handler of errorHandlers) {
    try {
      await handler(error, event, { defaultHandler });
      if (event.handled) {
        return; // Response handled
      }
    } catch(error) {
      // Handler itself thrown, log and continue
      console.error(error);
    }
  }
  // H3 will handle fallback
}

const plugins = [
  
];

const assets = {
  "/.nojekyll": {
    "type": "text/plain; charset=utf-8",
    "etag": "\"0-2jmj7l5rSw0yVb/vlWAYkK/YBwk\"",
    "mtime": "2026-05-04T18:04:24.777Z",
    "size": 0,
    "path": "../public/.nojekyll"
  },
  "/favicon.png": {
    "type": "image/png",
    "etag": "\"387-jmsKzII2xIOfh7uL4gpsQzjPGGY\"",
    "mtime": "2026-05-03T22:36:41.686Z",
    "size": 903,
    "path": "../public/favicon.png"
  },
  "/fonts/AmericanFavoriteScript.woff2": {
    "type": "font/woff2",
    "etag": "\"ad94-2gaBwO46yzar5icsyEWAm2sWWPM\"",
    "mtime": "2026-05-03T22:36:41.686Z",
    "size": 44436,
    "path": "../public/fonts/AmericanFavoriteScript.woff2"
  },
  "/_nuxt/-0GsY3MR.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6f-wI5XDckFIFAsnqfjneVRfsNfEZw\"",
    "mtime": "2026-05-26T18:57:58.711Z",
    "size": 111,
    "path": "../public/_nuxt/-0GsY3MR.js"
  },
  "/fonts/PowerGrotesk-Regular.woff2": {
    "type": "font/woff2",
    "etag": "\"53b4-3y3eUrmFI11SKzg4U8TvS0hSFf0\"",
    "mtime": "2026-05-03T22:36:41.686Z",
    "size": 21428,
    "path": "../public/fonts/PowerGrotesk-Regular.woff2"
  },
  "/_nuxt/-QlsAFep.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-qVy+ExnUHhIm1GMYVnYralI7L7I\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 110,
    "path": "../public/_nuxt/-QlsAFep.js"
  },
  "/_nuxt/02_03.Bz1jIBX2.webp": {
    "type": "image/webp",
    "etag": "\"762c6-SnXNZX0xmFIddCUQ8+OJWCa75Yo\"",
    "mtime": "2026-05-26T18:57:58.693Z",
    "size": 484038,
    "path": "../public/_nuxt/02_03.Bz1jIBX2.webp"
  },
  "/_nuxt/0d8eat_p.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-q2/dzyqzAHRQ3efzNRooA8aCw4I\"",
    "mtime": "2026-05-26T18:57:58.711Z",
    "size": 114,
    "path": "../public/_nuxt/0d8eat_p.js"
  },
  "/_nuxt/0ilj_XlX.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"76-nVWFTIY/0gTPwuOcpcCvd3ePRPw\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 118,
    "path": "../public/_nuxt/0ilj_XlX.js"
  },
  "/_nuxt/2nPMM8Py.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-Z7jVg8A0T2Bwi31uSRmNG226mKw\"",
    "mtime": "2026-05-26T18:57:58.710Z",
    "size": 122,
    "path": "../public/_nuxt/2nPMM8Py.js"
  },
  "/_nuxt/2ymsCIap.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-dcU0bNxlHBM07pPDCyn2QrqpHIY\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 120,
    "path": "../public/_nuxt/2ymsCIap.js"
  },
  "/_nuxt/493908234_section.D7-1RJV-.webp": {
    "type": "image/webp",
    "etag": "\"1d8c6-uyo64yVMIUO60W/eNNLNrjr7LkE\"",
    "mtime": "2026-05-26T18:57:58.693Z",
    "size": 121030,
    "path": "../public/_nuxt/493908234_section.D7-1RJV-.webp"
  },
  "/_nuxt/496368201.B4YfcjqO.webp": {
    "type": "image/webp",
    "etag": "\"2aeda-eI7oOUg01Te0EDZhSjNxkvMkdBw\"",
    "mtime": "2026-05-26T18:57:58.693Z",
    "size": 175834,
    "path": "../public/_nuxt/496368201.B4YfcjqO.webp"
  },
  "/_nuxt/5csDKuOE.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-Le8g4CqA/6h75rFWOn8LSk5fQ64\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 115,
    "path": "../public/_nuxt/5csDKuOE.js"
  },
  "/_nuxt/02_021.DJA8lALI.webp": {
    "type": "image/webp",
    "etag": "\"f76ba-pudWbTKN117ATKvqIsPG35otg8s\"",
    "mtime": "2026-05-26T18:57:58.718Z",
    "size": 1013434,
    "path": "../public/_nuxt/02_021.DJA8lALI.webp"
  },
  "/_nuxt/02_020.CC1ABNmI.webp": {
    "type": "image/webp",
    "etag": "\"b2d88-hjOCm4h7XCQZTljyJPsRjDxd8y0\"",
    "mtime": "2026-05-26T18:57:58.718Z",
    "size": 732552,
    "path": "../public/_nuxt/02_020.CC1ABNmI.webp"
  },
  "/_nuxt/02_06.CFvRicEn.webp": {
    "type": "image/webp",
    "etag": "\"deabc-zbeXmwtpwWbRVHtAPfRl+WBZ7XI\"",
    "mtime": "2026-05-26T18:57:58.718Z",
    "size": 912060,
    "path": "../public/_nuxt/02_06.CFvRicEn.webp"
  },
  "/_nuxt/49347758_section.DL0rpK0-.webp": {
    "type": "image/webp",
    "etag": "\"cd968-yE8lLgixleS3m8Sk0A16a3Ii9pg\"",
    "mtime": "2026-05-26T18:57:58.721Z",
    "size": 842088,
    "path": "../public/_nuxt/49347758_section.DL0rpK0-.webp"
  },
  "/_nuxt/49390834_section.DyJVvR96.webp": {
    "type": "image/webp",
    "etag": "\"b7cfc-Zt6F8ieI+I1fLBVV2y/qUp5dIfc\"",
    "mtime": "2026-05-26T18:57:58.720Z",
    "size": 752892,
    "path": "../public/_nuxt/49390834_section.DyJVvR96.webp"
  },
  "/about-bg.webp": {
    "type": "image/webp",
    "etag": "\"163972-GHCF3X6Jc85VNExDnr9wPlj3nZ8\"",
    "mtime": "2026-05-26T18:23:30.851Z",
    "size": 1456498,
    "path": "../public/about-bg.webp"
  },
  "/_nuxt/02_01.UzkPjOK8.webp": {
    "type": "image/webp",
    "etag": "\"16c9fa-q+HrLy/Q2RIaDV1BQebItuFcuqM\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1493498,
    "path": "../public/_nuxt/02_01.UzkPjOK8.webp"
  },
  "/_nuxt/02_04.fnJ9-MgU.webp": {
    "type": "image/webp",
    "etag": "\"1036a4-kfI6p0NDgWLNgtV2QKDdXQNUziE\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1062564,
    "path": "../public/_nuxt/02_04.fnJ9-MgU.webp"
  },
  "/_nuxt/02_05.CsQ5DQHF.webp": {
    "type": "image/webp",
    "etag": "\"100362-VH5l5OJBQFDoiVIPKtklirNgFc8\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1049442,
    "path": "../public/_nuxt/02_05.CsQ5DQHF.webp"
  },
  "/_nuxt/49347758.BH3jbzWS.webp": {
    "type": "image/webp",
    "etag": "\"12f182-TAIqHqqiVNA/56XxkLmL7ni+lks\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1241474,
    "path": "../public/_nuxt/49347758.BH3jbzWS.webp"
  },
  "/_nuxt/02_02.B9-_d6Xb.webp": {
    "type": "image/webp",
    "etag": "\"184bcc-H87O+loBNIoJJiWnBZUxMGR+xGA\"",
    "mtime": "2026-05-26T18:57:58.744Z",
    "size": 1592268,
    "path": "../public/_nuxt/02_02.B9-_d6Xb.webp"
  },
  "/_nuxt/5fq8sM58.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"2347-rbxk/S/+6bg0nluFKLENqKsl1E4\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 9031,
    "path": "../public/_nuxt/5fq8sM58.js"
  },
  "/_nuxt/5R2VqUwa.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-fdTEdv/ItqYkbyDpcblTO4mHtKQ\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 114,
    "path": "../public/_nuxt/5R2VqUwa.js"
  },
  "/_nuxt/7-B8tp1c.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-pbhJ9CB9J8jzizIc1isSnPaD9eU\"",
    "mtime": "2026-05-26T18:57:58.716Z",
    "size": 115,
    "path": "../public/_nuxt/7-B8tp1c.js"
  },
  "/_nuxt/7AlXMuC4.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-MoHgJ0tYB6a1xx9BmIM9ixrX3Sc\"",
    "mtime": "2026-05-26T18:57:58.711Z",
    "size": 119,
    "path": "../public/_nuxt/7AlXMuC4.js"
  },
  "/_nuxt/7jo1cR5L.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-7r3i//riRYr5n/6s2NdOvP55Fmc\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 114,
    "path": "../public/_nuxt/7jo1cR5L.js"
  },
  "/_nuxt/7gFlVaIw.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6c-Grjfhit/yA+tpR+jW8AMqG6I5Gc\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 108,
    "path": "../public/_nuxt/7gFlVaIw.js"
  },
  "/_nuxt/9uHzAAf3.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-Yq6755UCwTLsznLkH/bCMq8OGT8\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 113,
    "path": "../public/_nuxt/9uHzAAf3.js"
  },
  "/_nuxt/a31mQ9rC.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6d-IniRN3YaKl7OoC/A+/JJvCADOpg\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 109,
    "path": "../public/_nuxt/a31mQ9rC.js"
  },
  "/_nuxt/AmericanFavoriteScript.CHuQJG7O.woff2": {
    "type": "font/woff2",
    "etag": "\"ad94-2gaBwO46yzar5icsyEWAm2sWWPM\"",
    "mtime": "2026-05-26T18:57:58.557Z",
    "size": 44436,
    "path": "../public/_nuxt/AmericanFavoriteScript.CHuQJG7O.woff2"
  },
  "/_nuxt/a3_section.9OLzAvQX.webp": {
    "type": "image/webp",
    "etag": "\"5a54c-9YvynffO5zzRlV4Lr9xqE6YrLak\"",
    "mtime": "2026-05-26T18:57:58.694Z",
    "size": 369996,
    "path": "../public/_nuxt/a3_section.9OLzAvQX.webp"
  },
  "/_nuxt/Aover.dLy7wNUG.webp": {
    "type": "image/webp",
    "etag": "\"6cb84-2Tjl9hRdZ1AbD51LSZGeMAhL3+4\"",
    "mtime": "2026-05-26T18:57:58.693Z",
    "size": 445316,
    "path": "../public/_nuxt/Aover.dLy7wNUG.webp"
  },
  "/_nuxt/B-BxBHTu.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"79-cCn7SUDDMKfFWDXCsFNLcuDsgf0\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 121,
    "path": "../public/_nuxt/B-BxBHTu.js"
  },
  "/_nuxt/B-e22B2z.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-8rwfD74+6gnXSIxSUrPC+AdM0Y0\"",
    "mtime": "2026-05-26T18:57:58.716Z",
    "size": 120,
    "path": "../public/_nuxt/B-e22B2z.js"
  },
  "/_nuxt/B-kdNyRO.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-I409Cc09q5/S6uQxIBoRk0emb64\"",
    "mtime": "2026-05-26T18:57:58.711Z",
    "size": 107,
    "path": "../public/_nuxt/B-kdNyRO.js"
  },
  "/_nuxt/B-zMbQCP.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6c-KrnX0tTeON7JtTPDKd+UfEEAE1A\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 108,
    "path": "../public/_nuxt/B-zMbQCP.js"
  },
  "/_nuxt/B0c86zt0.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-7nYjnixQSEM8Aw3lMyLCnUJz7w0\"",
    "mtime": "2026-05-26T18:57:58.716Z",
    "size": 115,
    "path": "../public/_nuxt/B0c86zt0.js"
  },
  "/_nuxt/B0eADvfu.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-WHLX6QcOYIPuWLh1uyOrc5+bSd8\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 110,
    "path": "../public/_nuxt/B0eADvfu.js"
  },
  "/_nuxt/B0OBMLJL.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-iTM3nMMLAr4tNh9/J6nli0/L2KI\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 115,
    "path": "../public/_nuxt/B0OBMLJL.js"
  },
  "/_nuxt/B0pdxpe8.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-fxFcVFNYFtYLBQ33MomNEinvFbI\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 120,
    "path": "../public/_nuxt/B0pdxpe8.js"
  },
  "/_nuxt/a2.QqxxUXRR.webp": {
    "type": "image/webp",
    "etag": "\"10a220-KA4RnqrN6Lub8YPaz3YVr+Q2E64\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1090080,
    "path": "../public/_nuxt/a2.QqxxUXRR.webp"
  },
  "/_nuxt/B0t03ntF.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"95b5-ZF8sFAuBnaHbmmh39gAXty6Ol8g\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 38325,
    "path": "../public/_nuxt/B0t03ntF.js"
  },
  "/_nuxt/B0vHYmBE.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"2cefb-nEGyMCRmDxmZmEqohpF3k7MyjEs\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 184059,
    "path": "../public/_nuxt/B0vHYmBE.js"
  },
  "/_nuxt/B2bGg4Rl.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-QGTjWrv5WI20mCB+5YUisoSF8Eo\"",
    "mtime": "2026-05-26T18:57:58.716Z",
    "size": 115,
    "path": "../public/_nuxt/B2bGg4Rl.js"
  },
  "/_nuxt/B2tYD8jl.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-ByLblN94kfrANpK+tiQcUOoodgc\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 107,
    "path": "../public/_nuxt/B2tYD8jl.js"
  },
  "/_nuxt/ASMR-Gara.BehVu7bJ.mp4": {
    "type": "video/mp4",
    "etag": "\"18052d-rXgJ0YWp1nUsatulWp9j4eltSU8\"",
    "mtime": "2026-05-26T18:57:58.744Z",
    "size": 1574189,
    "path": "../public/_nuxt/ASMR-Gara.BehVu7bJ.mp4"
  },
  "/_nuxt/B3ApZJHZ.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-3FRAX50z2RNsugVZJnDu3fL6Fj8\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 122,
    "path": "../public/_nuxt/B3ApZJHZ.js"
  },
  "/_nuxt/B48Clqi-.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-maq+R3iQ4SJHr5XmGlOxhYyKxfo\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 122,
    "path": "../public/_nuxt/B48Clqi-.js"
  },
  "/_nuxt/B4HvILux.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-TrEe5F9zq+ODDxorQZ0rESgRIe4\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 113,
    "path": "../public/_nuxt/B4HvILux.js"
  },
  "/_nuxt/B5btWu9S.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-ZNNFVEb+IX4ZZgYHFp9dAp+Gbpc\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 119,
    "path": "../public/_nuxt/B5btWu9S.js"
  },
  "/_nuxt/B7sPEZnE.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"70-jOl5e/EH13itCiSVCDqmltD8NX0\"",
    "mtime": "2026-05-26T18:57:58.710Z",
    "size": 112,
    "path": "../public/_nuxt/B7sPEZnE.js"
  },
  "/_nuxt/B7XiqnKn.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-SYzXzgpFnBikFFRt8b2cgR9dnnQ\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 110,
    "path": "../public/_nuxt/B7XiqnKn.js"
  },
  "/_nuxt/B8XFqHda.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-0mJHnwyYdyD0d8jVi3Ufv26wE0c\"",
    "mtime": "2026-05-26T18:57:58.716Z",
    "size": 115,
    "path": "../public/_nuxt/B8XFqHda.js"
  },
  "/_nuxt/BA3VZRTG.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-8tWCNabjsppcet9+jT/XyYb5vos\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 119,
    "path": "../public/_nuxt/BA3VZRTG.js"
  },
  "/_nuxt/BavplkO2.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-5pFTZ+XewespLkFxocxlMjR3D4g\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 110,
    "path": "../public/_nuxt/BavplkO2.js"
  },
  "/_nuxt/BcX4kwII.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-mLuPVZ/uEu0MwPpaGVGu7Mohwmg\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 110,
    "path": "../public/_nuxt/BcX4kwII.js"
  },
  "/_nuxt/BC7wxvMb.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-yP6+cJnkzVSoAnM/RP8v3yiKXW8\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 114,
    "path": "../public/_nuxt/BC7wxvMb.js"
  },
  "/_nuxt/BD2zJTgt.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-2CMv1RIcB35qE5nDm5Yu6E0ifT0\"",
    "mtime": "2026-05-26T18:57:58.710Z",
    "size": 122,
    "path": "../public/_nuxt/BD2zJTgt.js"
  },
  "/_nuxt/BDlFao_c.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-9AjLjNIAp8TQalovs+9V6bKo/7I\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 119,
    "path": "../public/_nuxt/BDlFao_c.js"
  },
  "/_nuxt/BDNEwdxM.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-/QpR4Igr4qyBu8RHgASoc2xFvqQ\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 119,
    "path": "../public/_nuxt/BDNEwdxM.js"
  },
  "/_nuxt/BfMYq68m.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-AIXKRw1z4UJeEV4rax0rWRkI+6A\"",
    "mtime": "2026-05-26T18:57:58.716Z",
    "size": 114,
    "path": "../public/_nuxt/BfMYq68m.js"
  },
  "/_nuxt/BfpfN8Td.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-O8dOgHtXPb7DGjoqaEeLyhEkfUc\"",
    "mtime": "2026-05-26T18:57:58.716Z",
    "size": 120,
    "path": "../public/_nuxt/BfpfN8Td.js"
  },
  "/_nuxt/bGl94Oxi.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-pLpaaBqt6ygugzIQfh+zAp7tXkk\"",
    "mtime": "2026-05-26T18:57:58.716Z",
    "size": 120,
    "path": "../public/_nuxt/bGl94Oxi.js"
  },
  "/_nuxt/BgWm-a-i.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-yxCudrkoUSIVdJQk35iCW7gOCpg\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 107,
    "path": "../public/_nuxt/BgWm-a-i.js"
  },
  "/_nuxt/BHr-Tsqe.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-ybPQdTYRmGhEk1Ho98Zx17B8XPQ\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 122,
    "path": "../public/_nuxt/BHr-Tsqe.js"
  },
  "/_nuxt/BibeIC8f.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-QNZ6m1lcWc+jOCFjnUh2iBG8Ldw\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 119,
    "path": "../public/_nuxt/BibeIC8f.js"
  },
  "/_nuxt/Bii9gh5n.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6a-DUo69i9t+oFwfUR7wq3P+KPtl40\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 106,
    "path": "../public/_nuxt/Bii9gh5n.js"
  },
  "/_nuxt/BjAqdvtC.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-XGOQtYiOvdGID8uwFk1OJo15InE\"",
    "mtime": "2026-05-26T18:57:58.716Z",
    "size": 114,
    "path": "../public/_nuxt/BjAqdvtC.js"
  },
  "/_nuxt/BJr5QrXW.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-MbDVClguh1dqDvYYzV9XStWnt9s\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 120,
    "path": "../public/_nuxt/BJr5QrXW.js"
  },
  "/_nuxt/BjxUogsf.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-uG+vaoG785smz0XrYNMV7eXrNgM\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 110,
    "path": "../public/_nuxt/BjxUogsf.js"
  },
  "/_nuxt/BkRd_IUm.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-5b2C+U4IRhi5xydsRWT8t4YMUm8\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 107,
    "path": "../public/_nuxt/BkRd_IUm.js"
  },
  "/_nuxt/BKZNiG1r.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-v3s5zRxKhdiZmgij4LOepfGGx0Y\"",
    "mtime": "2026-05-26T18:57:58.711Z",
    "size": 110,
    "path": "../public/_nuxt/BKZNiG1r.js"
  },
  "/_nuxt/BLE8NDQc.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-3g9Y6yR9cwk4uKsectfNJ2QbZbA\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 107,
    "path": "../public/_nuxt/BLE8NDQc.js"
  },
  "/_nuxt/BMY1Uaod.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-9IQ3oLFLHFVX5pPi4rmANwPKVfs\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 119,
    "path": "../public/_nuxt/BMY1Uaod.js"
  },
  "/_nuxt/BMP3uhm1.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-zGz0v/L9YfIMJhnvkVLVvBttzSY\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 114,
    "path": "../public/_nuxt/BMP3uhm1.js"
  },
  "/_nuxt/BNn_7pFl.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-ZABnkYkfJQbz/adgLNQXTPGSdJg\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 122,
    "path": "../public/_nuxt/BNn_7pFl.js"
  },
  "/_nuxt/BNq-rBdb.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-MbDVClguh1dqDvYYzV9XStWnt9s\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 120,
    "path": "../public/_nuxt/BNq-rBdb.js"
  },
  "/_nuxt/BnS7F1jx.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-hm3EaQnP/Ti9YJU7TswplVB+exg\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 110,
    "path": "../public/_nuxt/BnS7F1jx.js"
  },
  "/_nuxt/BnSadxnr.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-BhweN6RRcyNKTjCr7o62cTfF2Qc\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 115,
    "path": "../public/_nuxt/BnSadxnr.js"
  },
  "/_nuxt/BntU8YNR.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-dcU0bNxlHBM07pPDCyn2QrqpHIY\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 120,
    "path": "../public/_nuxt/BntU8YNR.js"
  },
  "/_nuxt/BNZCH9_l.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-MvLYHkYO6CBziKEJY8trtGF9KdU\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 110,
    "path": "../public/_nuxt/BNZCH9_l.js"
  },
  "/_nuxt/BnYhx9fP.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"14e4-51X3W93n3lKPA/6clJX7M1i+GAM\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 5348,
    "path": "../public/_nuxt/BnYhx9fP.js"
  },
  "/_nuxt/BOHgfzHB.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-DXzBIkzfY50K2Kou1oLP5mY0LpU\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 110,
    "path": "../public/_nuxt/BOHgfzHB.js"
  },
  "/_nuxt/BOj-TjV2.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-UXm9lc+0ZBKAeAJMmKTz1LVrwz4\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 120,
    "path": "../public/_nuxt/BOj-TjV2.js"
  },
  "/_nuxt/Bp4EbG1_.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-Ymoj0Exl9Xy5TaVAiJ84EFc+to8\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 119,
    "path": "../public/_nuxt/Bp4EbG1_.js"
  },
  "/_nuxt/BP5kLDI4.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6f-qfb9wjEnpKiVbhG2H3E1MuWLXug\"",
    "mtime": "2026-05-26T18:57:58.711Z",
    "size": 111,
    "path": "../public/_nuxt/BP5kLDI4.js"
  },
  "/_nuxt/BP6-cm9c.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-Ft6nbRCgnx/5Jp1s+QY6oZ9YZRA\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 115,
    "path": "../public/_nuxt/BP6-cm9c.js"
  },
  "/_nuxt/BPhH6GGY.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"70-TcAyPwCZ468lmB7lmXvQaxY5mfM\"",
    "mtime": "2026-05-26T18:57:58.711Z",
    "size": 112,
    "path": "../public/_nuxt/BPhH6GGY.js"
  },
  "/_nuxt/BPHORVkE.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-ATTMiuC4OjIZ5WrXAcFQ/HRN2Zo\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 119,
    "path": "../public/_nuxt/BPHORVkE.js"
  },
  "/_nuxt/BpMs20xj.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"70-yeZU423opN/zUP1XgdWPMmWWV7g\"",
    "mtime": "2026-05-26T18:57:58.710Z",
    "size": 112,
    "path": "../public/_nuxt/BpMs20xj.js"
  },
  "/_nuxt/BpXzgfOm.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"eb2-BaTL22ZqY72B+KmXk9ZTOquIrV0\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 3762,
    "path": "../public/_nuxt/BpXzgfOm.js"
  },
  "/_nuxt/BQ6LhYOQ.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-2imaFH5kACX2Lq4ZooCUF0NZe8c\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 115,
    "path": "../public/_nuxt/BQ6LhYOQ.js"
  },
  "/_nuxt/Bq9hozpE.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-rehxLR2tSHPoDxG2VjhyiyR7wyQ\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 113,
    "path": "../public/_nuxt/Bq9hozpE.js"
  },
  "/_nuxt/BQOc3b2o.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-A6rl09S3VWnlwtLKSgu56MoFiXI\"",
    "mtime": "2026-05-26T18:57:58.710Z",
    "size": 122,
    "path": "../public/_nuxt/BQOc3b2o.js"
  },
  "/_nuxt/BRoqECy4.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-sZUY2MwFhmcFP5nw4g6C7xEEmv4\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 113,
    "path": "../public/_nuxt/BRoqECy4.js"
  },
  "/_nuxt/Bs7ytJJv.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-zw7+t7WvrcDrCMik3BhXb1iX5NQ\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 114,
    "path": "../public/_nuxt/Bs7ytJJv.js"
  },
  "/_nuxt/BsQQb2Lv.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6a-4lq0cne/G0KeZG8HdTk6qomKaE0\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 106,
    "path": "../public/_nuxt/BsQQb2Lv.js"
  },
  "/_nuxt/BTSsJp2s.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-Evz+eSiRrmNDXN/3GGKdY5dWY/I\"",
    "mtime": "2026-05-26T18:57:58.716Z",
    "size": 115,
    "path": "../public/_nuxt/BTSsJp2s.js"
  },
  "/_nuxt/BVrXa0_s.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-U/xNsttO4Gkh3fnf9sNpCHgdBeY\"",
    "mtime": "2026-05-26T18:57:58.710Z",
    "size": 122,
    "path": "../public/_nuxt/BVrXa0_s.js"
  },
  "/_nuxt/BVxC0sa7.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"770-cxj4a8xaOImjVak3iTAxmEAGHHg\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 1904,
    "path": "../public/_nuxt/BVxC0sa7.js"
  },
  "/_nuxt/BUwNyv6a.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-6qRhwU2HXbpbzO8Ku4Z1ECRM59s\"",
    "mtime": "2026-05-26T18:57:58.711Z",
    "size": 114,
    "path": "../public/_nuxt/BUwNyv6a.js"
  },
  "/_nuxt/BW7yo_U9.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-RO33lgq1BWe82uQCMZ29zpQXJro\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 114,
    "path": "../public/_nuxt/BW7yo_U9.js"
  },
  "/_nuxt/BWftqTAE.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-VN0owRhZ8Djyu1YVGoyTHKnnkjY\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 119,
    "path": "../public/_nuxt/BWftqTAE.js"
  },
  "/_nuxt/Bwi0ARgg.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-bPJmSzmbYdmCz89USDQ7LXR03No\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 115,
    "path": "../public/_nuxt/Bwi0ARgg.js"
  },
  "/_nuxt/BWp9zoF2.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-jQWOcK1+Rj3Yeyvys2cRhlAKhkc\"",
    "mtime": "2026-05-26T18:57:58.716Z",
    "size": 114,
    "path": "../public/_nuxt/BWp9zoF2.js"
  },
  "/_nuxt/BWYva6pP.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"70-JmHZVfVJC0K/dNz/5UGHHop2NdI\"",
    "mtime": "2026-05-26T18:57:58.711Z",
    "size": 112,
    "path": "../public/_nuxt/BWYva6pP.js"
  },
  "/_nuxt/Bx2EXt7C.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-WPtHEmeJjOR46bUNdqCP5/0we6g\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 110,
    "path": "../public/_nuxt/Bx2EXt7C.js"
  },
  "/_nuxt/BxITRBZF.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-c5Q2L+DQAOJYIjsp2AJLSV7Yikk\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 119,
    "path": "../public/_nuxt/BxITRBZF.js"
  },
  "/_nuxt/By0Csz2f.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"76-3itq+ZkgCLcy1FvFNuq7pLfUqtA\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 118,
    "path": "../public/_nuxt/By0Csz2f.js"
  },
  "/_nuxt/Byaavi5P.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"75-htOQNATfWxsiYvQTyn03r/RKuZw\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 117,
    "path": "../public/_nuxt/Byaavi5P.js"
  },
  "/_nuxt/BYqgCICw.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"70-sHJ6lp4mrYZ7k6vwWo4zv5OrC68\"",
    "mtime": "2026-05-26T18:57:58.710Z",
    "size": 112,
    "path": "../public/_nuxt/BYqgCICw.js"
  },
  "/_nuxt/byxFu_ir.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"70-p6xVMJ/6k+ARq2Kf19JOstvk1ZY\"",
    "mtime": "2026-05-26T18:57:58.710Z",
    "size": 112,
    "path": "../public/_nuxt/byxFu_ir.js"
  },
  "/_nuxt/BYynsHbk.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6a-SdXB+24aZXLQex+SbP92fLXROXY\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 106,
    "path": "../public/_nuxt/BYynsHbk.js"
  },
  "/_nuxt/Bz6rY7Yt.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-7CiCeRKo4QJ7lMm14fU5KpPbHPk\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 119,
    "path": "../public/_nuxt/Bz6rY7Yt.js"
  },
  "/_nuxt/bZBQbH96.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-8HXV3TYViHtRz0eHk6MzJCgf6Fw\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 119,
    "path": "../public/_nuxt/bZBQbH96.js"
  },
  "/_nuxt/BzEouGXA.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-TW5fDzlSgDqJ2YoLrT1XPGIeb9s\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 120,
    "path": "../public/_nuxt/BzEouGXA.js"
  },
  "/_nuxt/BZlQufaB.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-tFxSE2K2Mi8nWgjEcMkzEY+HW0s\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 113,
    "path": "../public/_nuxt/BZlQufaB.js"
  },
  "/_nuxt/BZWDGtZz.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"69-TpVHAuw+71AzqyJTfEgmjmYm1j0\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 105,
    "path": "../public/_nuxt/BZWDGtZz.js"
  },
  "/_nuxt/BzyxARud.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"68-tF1FtyDUsT2BEPLKCA+zHQ8vAEM\"",
    "mtime": "2026-05-26T18:57:58.711Z",
    "size": 104,
    "path": "../public/_nuxt/BzyxARud.js"
  },
  "/_nuxt/B_Fwiv06.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-DKJSVmI1a6EwvgH9C7CxSGf1nD0\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 114,
    "path": "../public/_nuxt/B_Fwiv06.js"
  },
  "/_nuxt/B__ii4hG.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-FPdaDwFivZvEDZUxRWtpXBZ/m6s\"",
    "mtime": "2026-05-26T18:57:58.710Z",
    "size": 122,
    "path": "../public/_nuxt/B__ii4hG.js"
  },
  "/_nuxt/C-0R9u8T.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"1905-jVUnDVSg260hDEYixOcTVGax9j8\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 6405,
    "path": "../public/_nuxt/C-0R9u8T.js"
  },
  "/_nuxt/C-n6ki5h.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"76-7hM0/5Fvm1T8eYcWF0U1xcP32lE\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 118,
    "path": "../public/_nuxt/C-n6ki5h.js"
  },
  "/_nuxt/C0Cml8Vp.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-shKEL58wVq4LYJ/93CtB0mmXA2I\"",
    "mtime": "2026-05-26T18:57:58.710Z",
    "size": 122,
    "path": "../public/_nuxt/C0Cml8Vp.js"
  },
  "/_nuxt/C-zOdOnz.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-m+JDrLphURpkkqmIkejpWihBwzA\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 122,
    "path": "../public/_nuxt/C-zOdOnz.js"
  },
  "/_nuxt/C0zeSIvy.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6c-RuKKO/M+sH+gaN9lGkrJ/gbsopo\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 108,
    "path": "../public/_nuxt/C0zeSIvy.js"
  },
  "/_nuxt/C0J9XFCq.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-TSJlYn1dvneZkkV49A03f2k+6pM\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 114,
    "path": "../public/_nuxt/C0J9XFCq.js"
  },
  "/_nuxt/C1Ak4DA3.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-CncE00dsjF3QpG0ZNUvyZ/3mTpo\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 115,
    "path": "../public/_nuxt/C1Ak4DA3.js"
  },
  "/_nuxt/C2sjUG_1.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-lG2760ED2fVxRhX6F48RNK53re4\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 119,
    "path": "../public/_nuxt/C2sjUG_1.js"
  },
  "/_nuxt/C33FoQpF.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6a-vdcI1pQwMZc4wRqc17AiC8L4CoE\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 106,
    "path": "../public/_nuxt/C33FoQpF.js"
  },
  "/_nuxt/C3INtpBN.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-9+UT0vyKb66bB0joRKkNqB+fY+o\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 120,
    "path": "../public/_nuxt/C3INtpBN.js"
  },
  "/_nuxt/C3jp5fUR.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-AK5oY00a9Iu6sTf96wAw9oq6w6k\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 122,
    "path": "../public/_nuxt/C3jp5fUR.js"
  },
  "/_nuxt/C46D1cq-.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-+D1PyLhMunusrVXwZi1B2RjAuZw\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 119,
    "path": "../public/_nuxt/C46D1cq-.js"
  },
  "/_nuxt/C4MhWhFS.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-iPs63L+KCxYotc6TEKdpWLKiCp8\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 113,
    "path": "../public/_nuxt/C4MhWhFS.js"
  },
  "/_nuxt/C4QBI_ws.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"d32-047aChN4aMk5Wx+ul1tiIkCa9tU\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 3378,
    "path": "../public/_nuxt/C4QBI_ws.js"
  },
  "/_nuxt/C62_F8SU.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6f-qGMEVaazNCOEpTIIr8NtF3UL0xg\"",
    "mtime": "2026-05-26T18:57:58.711Z",
    "size": 111,
    "path": "../public/_nuxt/C62_F8SU.js"
  },
  "/_nuxt/C65ahHHh.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-N8TksQzpueVY7Ht3nNiHwtBfh0g\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 119,
    "path": "../public/_nuxt/C65ahHHh.js"
  },
  "/_nuxt/C6SRnXv-.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-ghQVFtin9A2xJSHtnXy786eKovY\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 114,
    "path": "../public/_nuxt/C6SRnXv-.js"
  },
  "/_nuxt/C7qQxGRk.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-m2VAx75rsH5lafpnSCUhRlVXVZk\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 110,
    "path": "../public/_nuxt/C7qQxGRk.js"
  },
  "/_nuxt/C8vtLIVE.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-H6H2xYLm+BUjsZII2BSXQBA+p4Q\"",
    "mtime": "2026-05-26T18:57:58.716Z",
    "size": 120,
    "path": "../public/_nuxt/C8vtLIVE.js"
  },
  "/_nuxt/C9-_uxqz.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"70-pt7tN6YQpTYzkge/5NcJTDvPCng\"",
    "mtime": "2026-05-26T18:57:58.710Z",
    "size": 112,
    "path": "../public/_nuxt/C9-_uxqz.js"
  },
  "/_nuxt/C9cI9OuL.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-kSi91CEGhrFQjkTv5/QQQS+OV50\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 115,
    "path": "../public/_nuxt/C9cI9OuL.js"
  },
  "/_nuxt/C9x0MkKw.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"76-yM6u9YvzVrwfYsFyYfDFMcC/kDY\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 118,
    "path": "../public/_nuxt/C9x0MkKw.js"
  },
  "/_nuxt/CADerXb2.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6a-guZexQtrub4OIaaK4bXgepmW31k\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 106,
    "path": "../public/_nuxt/CADerXb2.js"
  },
  "/_nuxt/CCaTA4l1.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6f-PsRUXzmyAyQSQG8Y/3QR+QDboWM\"",
    "mtime": "2026-05-26T18:57:58.710Z",
    "size": 111,
    "path": "../public/_nuxt/CCaTA4l1.js"
  },
  "/_nuxt/CAR7.s6CL6QYq.webp": {
    "type": "image/webp",
    "etag": "\"69338-ND42OkRkYFIirLw4Y5ayu5zFWWI\"",
    "mtime": "2026-05-26T18:57:58.693Z",
    "size": 430904,
    "path": "../public/_nuxt/CAR7.s6CL6QYq.webp"
  },
  "/_nuxt/CcH_jcsk.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-ATTMiuC4OjIZ5WrXAcFQ/HRN2Zo\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 119,
    "path": "../public/_nuxt/CcH_jcsk.js"
  },
  "/_nuxt/Ccqqig6Y.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"70-PFa59/X2pN6hTVrJBElJFv+qfzs\"",
    "mtime": "2026-05-26T18:57:58.711Z",
    "size": 112,
    "path": "../public/_nuxt/Ccqqig6Y.js"
  },
  "/_nuxt/ccRHjFL0.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6c-oPTxuSO9np+UufudydhXdSvfaZE\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 108,
    "path": "../public/_nuxt/ccRHjFL0.js"
  },
  "/_nuxt/CDfK4Nnm.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-rHnCXwQyIz7gLuyyEfuB0sWpKs0\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 107,
    "path": "../public/_nuxt/CDfK4Nnm.js"
  },
  "/_nuxt/CDrnU4_Z.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-XnyUEisYJH5a4/aHfsjhws1hIcw\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 119,
    "path": "../public/_nuxt/CDrnU4_Z.js"
  },
  "/_nuxt/CEOWaayb.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-NTP6tQIXbSlWPas5M2He3Nqx+uM\"",
    "mtime": "2026-05-26T18:57:58.716Z",
    "size": 114,
    "path": "../public/_nuxt/CEOWaayb.js"
  },
  "/_nuxt/CEQUIwAq.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"76-NnVBjRRWzxql5pfxZwHkASqDTnY\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 118,
    "path": "../public/_nuxt/CEQUIwAq.js"
  },
  "/_nuxt/CER1b9Xi.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-/QpR4Igr4qyBu8RHgASoc2xFvqQ\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 119,
    "path": "../public/_nuxt/CER1b9Xi.js"
  },
  "/_nuxt/CeU5wQze.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"d45-bhJGaxlL40a5xwJyQkXT8wMMdgM\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 3397,
    "path": "../public/_nuxt/CeU5wQze.js"
  },
  "/_nuxt/CFidAJ_X.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6c-sFoMgSkjlT7ffsIOHNPq0YbwA6Y\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 108,
    "path": "../public/_nuxt/CFidAJ_X.js"
  },
  "/_nuxt/CAR1.CfAaLoK1.webp": {
    "type": "image/webp",
    "etag": "\"98c4a-xjLnLoJSThu5Fh2U4ODy+vCryZY\"",
    "mtime": "2026-05-26T18:57:58.718Z",
    "size": 625738,
    "path": "../public/_nuxt/CAR1.CfAaLoK1.webp"
  },
  "/_nuxt/CAR11.DIfiLRDk.webp": {
    "type": "image/webp",
    "etag": "\"fd6ac-LF9e40X8/r1XU6MTVnktGF2pDt4\"",
    "mtime": "2026-05-26T18:57:58.718Z",
    "size": 1037996,
    "path": "../public/_nuxt/CAR11.DIfiLRDk.webp"
  },
  "/_nuxt/CfQmjYIb.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-Ds22Rf+igBSM5kM9jWGAUVo+UIU\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 110,
    "path": "../public/_nuxt/CfQmjYIb.js"
  },
  "/_nuxt/CG9Pc21V.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-YBC/i5si177BeAWeJRaG6xnoqd8\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 119,
    "path": "../public/_nuxt/CG9Pc21V.js"
  },
  "/_nuxt/CghDNsqa.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-tXsE0eYNcLEIymbtCr1LM5eCBHs\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 107,
    "path": "../public/_nuxt/CghDNsqa.js"
  },
  "/_nuxt/CGQG3YRd.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-EMqMpsKChiIR51PGdZT4ipo/wdo\"",
    "mtime": "2026-05-26T18:57:58.710Z",
    "size": 122,
    "path": "../public/_nuxt/CGQG3YRd.js"
  },
  "/_nuxt/Ch79cymE.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-zEJOm/hvqOKrDdCyE7kG+54yH6g\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 115,
    "path": "../public/_nuxt/Ch79cymE.js"
  },
  "/_nuxt/ChaAmasQ.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-nYe/DSRJpkA3+ArIKHUixiDi2Sw\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 119,
    "path": "../public/_nuxt/ChaAmasQ.js"
  },
  "/_nuxt/CIB03jeO.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"74-HCJlwH9Hrcmq7m2dmCOqv7qv2jM\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 116,
    "path": "../public/_nuxt/CIB03jeO.js"
  },
  "/_nuxt/CiNqzIPK.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-9rkpjY2bEFcsrLqDv4TCnTMrSv8\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 115,
    "path": "../public/_nuxt/CiNqzIPK.js"
  },
  "/_nuxt/CjPtREO8.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-ZPh5FmsUJKdb2X7Y6cTtErDB2KA\"",
    "mtime": "2026-05-26T18:57:58.716Z",
    "size": 115,
    "path": "../public/_nuxt/CjPtREO8.js"
  },
  "/_nuxt/CJTASnNW.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-TGh7i92/+hT4AjvL4Bn9TZkT+dE\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 107,
    "path": "../public/_nuxt/CJTASnNW.js"
  },
  "/_nuxt/CK10gaXz.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-i1BA+mbC1E4W7bMivF5ns2ow79A\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 114,
    "path": "../public/_nuxt/CK10gaXz.js"
  },
  "/_nuxt/CK1C1fpP.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-bO124A6V8eov8+SprZeEkvAKVjY\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 107,
    "path": "../public/_nuxt/CK1C1fpP.js"
  },
  "/_nuxt/CkCQXCKZ.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-wiAa1WEfHfsN5+kgyjyZLFbNzC0\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 110,
    "path": "../public/_nuxt/CkCQXCKZ.js"
  },
  "/_nuxt/CkVFZxaU.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-OdWfbcAvBe2PIU2Tggp5YMfE6ng\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 120,
    "path": "../public/_nuxt/CkVFZxaU.js"
  },
  "/_nuxt/CldxKxqT.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-Gpkde6AhZq5jjMRTBsD56C4zoiA\"",
    "mtime": "2026-05-26T18:57:58.710Z",
    "size": 122,
    "path": "../public/_nuxt/CldxKxqT.js"
  },
  "/_nuxt/CLIlJB-X.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"76-wPIVzs563o4XXPrsSnzSoN3Zxfw\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 118,
    "path": "../public/_nuxt/CLIlJB-X.js"
  },
  "/_nuxt/Cm1tADED.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-9ZS+gX89UGnyGKS13LYPugl51fs\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 110,
    "path": "../public/_nuxt/Cm1tADED.js"
  },
  "/_nuxt/ClrLDe2y.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"70-9YWnqe7XcYp8eU9C+lfqeotveSk\"",
    "mtime": "2026-05-26T18:57:58.710Z",
    "size": 112,
    "path": "../public/_nuxt/ClrLDe2y.js"
  },
  "/_nuxt/cmaNktJA.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-FimIw0t2tUX4OgHS+CQXzQ3iqeY\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 114,
    "path": "../public/_nuxt/cmaNktJA.js"
  },
  "/_nuxt/CMEUhxSN.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6f-LSmatvqetpafYtKpxYvvXrNmQvA\"",
    "mtime": "2026-05-26T18:57:58.711Z",
    "size": 111,
    "path": "../public/_nuxt/CMEUhxSN.js"
  },
  "/_nuxt/CmfyeJ1J.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-IgoU1DduutNPbRrDf2xSziWctS0\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 113,
    "path": "../public/_nuxt/CmfyeJ1J.js"
  },
  "/_nuxt/CNHo1nsV.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-q13WRYv6xX+0LJIFyiHYtAtYlvA\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 107,
    "path": "../public/_nuxt/CNHo1nsV.js"
  },
  "/_nuxt/CoPSfGUg.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-RCGsrzusS5dGwCSeJFBcBqak99c\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 113,
    "path": "../public/_nuxt/CoPSfGUg.js"
  },
  "/_nuxt/CoT4fFeZ.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"74-Ej9EX9HioG/ibCkmRzO3ms462Ug\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 116,
    "path": "../public/_nuxt/CoT4fFeZ.js"
  },
  "/_nuxt/cover.ChTDDioM.webp": {
    "type": "image/webp",
    "etag": "\"16476-HR25Rgy/HZSeY4UAG0kye5yhGxs\"",
    "mtime": "2026-05-26T18:57:58.695Z",
    "size": 91254,
    "path": "../public/_nuxt/cover.ChTDDioM.webp"
  },
  "/_nuxt/cover.BsGVGjEy.webp": {
    "type": "image/webp",
    "etag": "\"896bc-IRPADobx7Pyhs8Flfjwh8p0jI7M\"",
    "mtime": "2026-05-26T18:57:58.721Z",
    "size": 562876,
    "path": "../public/_nuxt/cover.BsGVGjEy.webp"
  },
  "/_nuxt/cover.CxiBEX1E.jpg": {
    "type": "image/jpeg",
    "etag": "\"4b437-jloMA3Q2//01aAywFK0Z6BKgElA\"",
    "mtime": "2026-05-26T18:57:58.695Z",
    "size": 308279,
    "path": "../public/_nuxt/cover.CxiBEX1E.jpg"
  },
  "/_nuxt/cover.CaVQKLim.webp": {
    "type": "image/webp",
    "etag": "\"bae08-rHBo+2b6o2M3S3c7egKu2IeNNwU\"",
    "mtime": "2026-05-26T18:57:58.721Z",
    "size": 765448,
    "path": "../public/_nuxt/cover.CaVQKLim.webp"
  },
  "/_nuxt/cover.0yX1GJn1.mp4": {
    "type": "video/mp4",
    "etag": "\"1664b4-XUvsbLH+9TKo2Iil5Oz96EDmHeM\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1467572,
    "path": "../public/_nuxt/cover.0yX1GJn1.mp4"
  },
  "/_nuxt/cover.ClBGkUTF.jpg": {
    "type": "image/jpeg",
    "etag": "\"8df29-7BOY6jpgQSHNavDfldMtB7HttJA\"",
    "mtime": "2026-05-26T18:57:58.719Z",
    "size": 581417,
    "path": "../public/_nuxt/cover.ClBGkUTF.jpg"
  },
  "/_nuxt/cover.D38fduN5.webp": {
    "type": "image/webp",
    "etag": "\"bff88-kyi2i7/3CLJQ5qTZCmZMVPRANdg\"",
    "mtime": "2026-05-26T18:57:58.721Z",
    "size": 786312,
    "path": "../public/_nuxt/cover.D38fduN5.webp"
  },
  "/_nuxt/cover.DAQl52_n.jpg": {
    "type": "image/jpeg",
    "etag": "\"56bf3-1MBIlnBHmRcociziQHFOdythFlM\"",
    "mtime": "2026-05-26T18:57:58.694Z",
    "size": 355315,
    "path": "../public/_nuxt/cover.DAQl52_n.jpg"
  },
  "/_nuxt/cover.DxYdqjXM.webp": {
    "type": "image/webp",
    "etag": "\"79ffe-NLz/R73zQfnluvl45pHreeQcQVE\"",
    "mtime": "2026-05-26T18:57:58.695Z",
    "size": 499710,
    "path": "../public/_nuxt/cover.DxYdqjXM.webp"
  },
  "/_nuxt/CpBLsW8H.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-rr7cdRaumWoGPZ0FA++57B88now\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 107,
    "path": "../public/_nuxt/CpBLsW8H.js"
  },
  "/_nuxt/cQE8V3m4.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-TW5fDzlSgDqJ2YoLrT1XPGIeb9s\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 120,
    "path": "../public/_nuxt/cQE8V3m4.js"
  },
  "/_nuxt/CPHFU3r-.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-/9KmCS8ixGzHElM5Ewb5liIJvfU\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 113,
    "path": "../public/_nuxt/CPHFU3r-.js"
  },
  "/_nuxt/CQI-eKdu.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-2CjUC05/S+mF+zFxT5KRA2IN2FQ\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 115,
    "path": "../public/_nuxt/CQI-eKdu.js"
  },
  "/_nuxt/CQpj_WMH.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-lG7B4dXCp5a9910uqlUAo1E06Yc\"",
    "mtime": "2026-05-26T18:57:58.716Z",
    "size": 115,
    "path": "../public/_nuxt/CQpj_WMH.js"
  },
  "/_nuxt/CRqYvTlN.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-ocEsEdzrBPVN1TY7IeoHonFxngI\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 114,
    "path": "../public/_nuxt/CRqYvTlN.js"
  },
  "/_nuxt/CS9vfkfX.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-4Y60sGdWv/HWm1Pq6uvIzt1JKlE\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 119,
    "path": "../public/_nuxt/CS9vfkfX.js"
  },
  "/_nuxt/CShr4KRp.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-mMl/xyLgEiihJwTmZlxKnaKQ+NQ\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 110,
    "path": "../public/_nuxt/CShr4KRp.js"
  },
  "/_nuxt/cover.CRTP11wM.webp": {
    "type": "image/webp",
    "etag": "\"12fdc8-8jt/aFAMc7tOULQGr0RE1+AC/KE\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1244616,
    "path": "../public/_nuxt/cover.CRTP11wM.webp"
  },
  "/_nuxt/CTb_ysUe.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-3B9HrJ7DHmg2PVP5qIox2qlOE7U\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 115,
    "path": "../public/_nuxt/CTb_ysUe.js"
  },
  "/_nuxt/CTePOoQi.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"70-UNVmJHXxpalkLc1QtzCX4nTIhfc\"",
    "mtime": "2026-05-26T18:57:58.710Z",
    "size": 112,
    "path": "../public/_nuxt/CTePOoQi.js"
  },
  "/_nuxt/cover.D8RHNoUY.webp": {
    "type": "image/webp",
    "etag": "\"1dc830-I9bRpmxeCB3Ce5rbS5h3yqfMirI\"",
    "mtime": "2026-05-26T18:57:58.744Z",
    "size": 1951792,
    "path": "../public/_nuxt/cover.D8RHNoUY.webp"
  },
  "/_nuxt/CTl2ziT2.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-piMHQSYGpEdRevya6FWy4/OhimU\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 110,
    "path": "../public/_nuxt/CTl2ziT2.js"
  },
  "/_nuxt/cu6qKOki.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"69-bw9DNPHOrUnK/vkeG973rHsQaxE\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 105,
    "path": "../public/_nuxt/cu6qKOki.js"
  },
  "/_nuxt/cover.BATmarDZ.gif": {
    "type": "image/gif",
    "etag": "\"2c2109-ut9h0RcqfIxm6v7cKjFTP8MzLiY\"",
    "mtime": "2026-05-26T18:57:58.746Z",
    "size": 2892041,
    "path": "../public/_nuxt/cover.BATmarDZ.gif"
  },
  "/_nuxt/CUNLYpu9.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-Yf0armSW+Hi1kjByGcMzMa/aaR0\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 107,
    "path": "../public/_nuxt/CUNLYpu9.js"
  },
  "/_nuxt/CUqidFw2.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-hgwMvAltpOhn/ZyPTrqTXEc10y4\"",
    "mtime": "2026-05-26T18:57:58.716Z",
    "size": 114,
    "path": "../public/_nuxt/CUqidFw2.js"
  },
  "/_nuxt/CuXkmLfH.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"76-9bBkjmCh2/cBapZj0kIk402gd5Y\"",
    "mtime": "2026-05-26T18:57:58.711Z",
    "size": 118,
    "path": "../public/_nuxt/CuXkmLfH.js"
  },
  "/_nuxt/CviaL27e.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-kBnsq273c3MLzLUjuMnmv4dMpTg\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 113,
    "path": "../public/_nuxt/CviaL27e.js"
  },
  "/_nuxt/CVuqP43T.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"79-vmHklrLAN+mKasZ/fyUwHBorzYw\"",
    "mtime": "2026-05-26T18:57:58.710Z",
    "size": 121,
    "path": "../public/_nuxt/CVuqP43T.js"
  },
  "/_nuxt/CvVf-wav.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6f-auFNYaaem4+9Q/9E8bpk8BfVL/U\"",
    "mtime": "2026-05-26T18:57:58.711Z",
    "size": 111,
    "path": "../public/_nuxt/CvVf-wav.js"
  },
  "/_nuxt/CW3cqcAy.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-R0qCERtasNX2SZYxzxkRd6ISDrM\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 110,
    "path": "../public/_nuxt/CW3cqcAy.js"
  },
  "/_nuxt/CWQgObE5.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-z2dQh5JOBqClKxNIURGlcWxyR0w\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 122,
    "path": "../public/_nuxt/CWQgObE5.js"
  },
  "/_nuxt/CX1M5ZOi.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-In5IQGdUkuYLmxC2uwYge9hF7HE\"",
    "mtime": "2026-05-26T18:57:58.716Z",
    "size": 114,
    "path": "../public/_nuxt/CX1M5ZOi.js"
  },
  "/_nuxt/Cw_9H-6j.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-m2photcRs9dF7D91t7BQtY2OtMM\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 113,
    "path": "../public/_nuxt/Cw_9H-6j.js"
  },
  "/_nuxt/CvWn182M.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-zOlXtRvRQsKoCHzlVem7Z98SObU\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 119,
    "path": "../public/_nuxt/CvWn182M.js"
  },
  "/_nuxt/CX7R-QA-.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"70-PPQgZjQ0N1sDfX16zb+ij9uE8gI\"",
    "mtime": "2026-05-26T18:57:58.710Z",
    "size": 112,
    "path": "../public/_nuxt/CX7R-QA-.js"
  },
  "/_nuxt/CxDMTilo.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6a-3J6PYa7Yhq/Mw87twT/7fKJRo6U\"",
    "mtime": "2026-05-26T18:57:58.717Z",
    "size": 106,
    "path": "../public/_nuxt/CxDMTilo.js"
  },
  "/_nuxt/CxWkIORX.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-h/MFd/y3u1iNnGVKvRSh0X+9oQU\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 115,
    "path": "../public/_nuxt/CxWkIORX.js"
  },
  "/_nuxt/CyDpMojP.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-S+ZONku/RtYPl1zO8xB/HvoDs94\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 119,
    "path": "../public/_nuxt/CyDpMojP.js"
  },
  "/_nuxt/CXxsOKdr.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-qjSPrPlDqVJbWaDUsotoe5HJBDo\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 115,
    "path": "../public/_nuxt/CXxsOKdr.js"
  },
  "/_nuxt/C_G1A4C7.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-tUiicWOTomxOHToBsh9bY5TSkuY\"",
    "mtime": "2026-05-26T18:57:58.710Z",
    "size": 122,
    "path": "../public/_nuxt/C_G1A4C7.js"
  },
  "/_nuxt/cover.DeCBpyt9.mp4": {
    "type": "video/mp4",
    "etag": "\"194af1-Yb6hWIGQxrJUy5+kuQqeMykJftw\"",
    "mtime": "2026-05-26T18:57:58.744Z",
    "size": 1657585,
    "path": "../public/_nuxt/cover.DeCBpyt9.mp4"
  },
  "/_nuxt/C_oyR2cq.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-zgV3bvDmzXxCYw42lvmFiXSPg54\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 107,
    "path": "../public/_nuxt/C_oyR2cq.js"
  },
  "/_nuxt/D-iGbgFo.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-ZfGAY1dwgwuDTm5G+sbntCWQ8G0\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 114,
    "path": "../public/_nuxt/D-iGbgFo.js"
  },
  "/_nuxt/D-mUTCv1.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"74-b0FavwrCOjAeMgDromsyTLKFblE\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 116,
    "path": "../public/_nuxt/D-mUTCv1.js"
  },
  "/_nuxt/D-sWk-yF.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-pH0WdJdgnWZtLsVho9RDOLJy6nQ\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 115,
    "path": "../public/_nuxt/D-sWk-yF.js"
  },
  "/_nuxt/D0bpLfeK.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-Xjx26YDBLglgx/+CUUulMVMoT7Y\"",
    "mtime": "2026-05-26T18:57:58.716Z",
    "size": 114,
    "path": "../public/_nuxt/D0bpLfeK.js"
  },
  "/_nuxt/D1VadQ4T.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-+D1PyLhMunusrVXwZi1B2RjAuZw\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 119,
    "path": "../public/_nuxt/D1VadQ4T.js"
  },
  "/_nuxt/D3K7gptP.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"75-k80oIqkBe4zFVFZ/B2q5W1O8vFI\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 117,
    "path": "../public/_nuxt/D3K7gptP.js"
  },
  "/_nuxt/D3Zpq-Go.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-VNtX5yCGNfbIA3tqiTf+KYsnpi8\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 113,
    "path": "../public/_nuxt/D3Zpq-Go.js"
  },
  "/_nuxt/D4LUYpl2.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-+03jJmNbnof6KKbnCkkHGsVTSrY\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 114,
    "path": "../public/_nuxt/D4LUYpl2.js"
  },
  "/_nuxt/D6axku-G.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-dCVzeQSdQM/2aRQKDLmjL78gWqg\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 113,
    "path": "../public/_nuxt/D6axku-G.js"
  },
  "/_nuxt/D5j8wCAy.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-0HvMHd6CTxLIKhNGje630Ed2AGs\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 115,
    "path": "../public/_nuxt/D5j8wCAy.js"
  },
  "/_nuxt/DAM-t77l.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"79-EoHcZqbJZPo5edCOLgVcYvv/60g\"",
    "mtime": "2026-05-26T18:57:58.710Z",
    "size": 121,
    "path": "../public/_nuxt/DAM-t77l.js"
  },
  "/_nuxt/DaM8oJrr.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-omaHtvDj3Rxq/mmCIB0l9jhaTUQ\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 119,
    "path": "../public/_nuxt/DaM8oJrr.js"
  },
  "/_nuxt/DAN2-vzh.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-P9P2Dc7ZffUhu4YrJzvlRgA/zIU\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 113,
    "path": "../public/_nuxt/DAN2-vzh.js"
  },
  "/_nuxt/D8TL5Ww6.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-TeNruxwgYKRjk0aQv+xz36WOyIg\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 107,
    "path": "../public/_nuxt/D8TL5Ww6.js"
  },
  "/_nuxt/Daz6kgsj.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"75-eponhnmN62bKggo1LYMz3mELX3g\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 117,
    "path": "../public/_nuxt/Daz6kgsj.js"
  },
  "/_nuxt/Dc9BgT57.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-Yc5b7hvAbiZfk+944avHMmtuoFk\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 119,
    "path": "../public/_nuxt/Dc9BgT57.js"
  },
  "/_nuxt/Dcctrt3Z.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-B/e4I9oo6GK6nt4sYIvMtkC32zo\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 119,
    "path": "../public/_nuxt/Dcctrt3Z.js"
  },
  "/_nuxt/DCjy21IR.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-u9WMnztqFKUtHIZWIk45JnxjRIA\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 119,
    "path": "../public/_nuxt/DCjy21IR.js"
  },
  "/_nuxt/DdDh8ysO.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-Ng4fkQmufb4x4wORwlxJ4atPYhg\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 122,
    "path": "../public/_nuxt/DdDh8ysO.js"
  },
  "/_nuxt/DEA4COZl.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-vP/kvJuI15BjF5zCzewigTx9ZqI\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 114,
    "path": "../public/_nuxt/DEA4COZl.js"
  },
  "/_nuxt/Deh7GRup.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-/+ITnr7Nuqt9wKk2TCkd2O7l+2A\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 107,
    "path": "../public/_nuxt/Deh7GRup.js"
  },
  "/_nuxt/DFaiSY3C.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"76-gEMvWkdFCJ9uhXVxJOogUNDp4p8\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 118,
    "path": "../public/_nuxt/DFaiSY3C.js"
  },
  "/_nuxt/DfUHtcvA.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-I4WtYMfzv6wuNuQzK2QX682pPAU\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 107,
    "path": "../public/_nuxt/DfUHtcvA.js"
  },
  "/_nuxt/DGaNBCUl.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-M0RP0deKDI0SHqDkytbnnf980TU\"",
    "mtime": "2026-05-26T18:57:58.716Z",
    "size": 120,
    "path": "../public/_nuxt/DGaNBCUl.js"
  },
  "/_nuxt/DGVhXDkN.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-o/v5UBNYQ8oKIFYSFU5P9zihs/s\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 114,
    "path": "../public/_nuxt/DGVhXDkN.js"
  },
  "/_nuxt/DH3wWl8a.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-Dzcya1VzKqaX6RD/6SWWO5hHLMA\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 110,
    "path": "../public/_nuxt/DH3wWl8a.js"
  },
  "/_nuxt/DhcP9fLb.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-58zQA4jfSalWi1HhnCCg/pVPBT0\"",
    "mtime": "2026-05-26T18:57:58.716Z",
    "size": 120,
    "path": "../public/_nuxt/DhcP9fLb.js"
  },
  "/_nuxt/DhGtbICK.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-LLDkQI0U4kGysGsz4YotHHpdpGk\"",
    "mtime": "2026-05-26T18:57:58.716Z",
    "size": 120,
    "path": "../public/_nuxt/DhGtbICK.js"
  },
  "/_nuxt/DHRBDGGg.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-l3fBQ1i2cZJh7kuRS4pJDW8CWm0\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 122,
    "path": "../public/_nuxt/DHRBDGGg.js"
  },
  "/_nuxt/DI_MloYF.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-a8f02A3MZFwv38u0dHILNxJwkvQ\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 114,
    "path": "../public/_nuxt/DI_MloYF.js"
  },
  "/_nuxt/DjiLJu6p.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-lDlapXOZ8R5aTTTQGGkt6aoTDOA\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 110,
    "path": "../public/_nuxt/DjiLJu6p.js"
  },
  "/_nuxt/DJwiu7uB.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-rQP/8oy7EM80JYTnPp6vnQLTPnI\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 110,
    "path": "../public/_nuxt/DJwiu7uB.js"
  },
  "/_nuxt/Dj_BkQBv.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"75-pqEMkEIXDOVhcI3t22cvm+H87FI\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 117,
    "path": "../public/_nuxt/Dj_BkQBv.js"
  },
  "/_nuxt/DKgvVmde.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-W91fBL5v7pHCE7VdnlsfyONqZAM\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 115,
    "path": "../public/_nuxt/DKgvVmde.js"
  },
  "/_nuxt/DKtKO35o.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-ew+sf0K63io6e2qxOrCZl3qvoa8\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 110,
    "path": "../public/_nuxt/DKtKO35o.js"
  },
  "/_nuxt/DlAUqK2U.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"5b-eFCz/UrraTh721pgAl0VxBNR1es\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 91,
    "path": "../public/_nuxt/DlAUqK2U.js"
  },
  "/_nuxt/DLnNx09b.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-+gJ7XIlzTb/iSQsy4QdkVvuz5So\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 115,
    "path": "../public/_nuxt/DLnNx09b.js"
  },
  "/_nuxt/DMfsHtif.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6f-Dw12de3v+ZXRWmwWdAEdkad89pw\"",
    "mtime": "2026-05-26T18:57:58.711Z",
    "size": 111,
    "path": "../public/_nuxt/DMfsHtif.js"
  },
  "/_nuxt/DNavZXb2.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6f-uQJti6MI1zoY4mrzEygF+j9/pHE\"",
    "mtime": "2026-05-26T18:57:58.711Z",
    "size": 111,
    "path": "../public/_nuxt/DNavZXb2.js"
  },
  "/_nuxt/Dettagli-B2B-3.DdOoLmC8.mp4": {
    "type": "video/mp4",
    "etag": "\"1bfeae-FK2hrvkrc0KKIeeL0LaP103HP/k\"",
    "mtime": "2026-05-26T18:57:58.744Z",
    "size": 1834670,
    "path": "../public/_nuxt/Dettagli-B2B-3.DdOoLmC8.mp4"
  },
  "/_nuxt/Dettagli-B2B.DpCRxc4S.mp4": {
    "type": "video/mp4",
    "etag": "\"1c9d2a-o8imehKVv8KNbb1hSI3/sVTe1MM\"",
    "mtime": "2026-05-26T18:57:58.744Z",
    "size": 1875242,
    "path": "../public/_nuxt/Dettagli-B2B.DpCRxc4S.mp4"
  },
  "/_nuxt/DNXxylBF.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"74-7vklrwgUxYES5UNHKesMZpLtez8\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 116,
    "path": "../public/_nuxt/DNXxylBF.js"
  },
  "/_nuxt/DoE3Yejg.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-sPCkNRtv8fvFgarwfzWvDpVhslE\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 120,
    "path": "../public/_nuxt/DoE3Yejg.js"
  },
  "/_nuxt/Dol-sKCS.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-OdWfbcAvBe2PIU2Tggp5YMfE6ng\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 120,
    "path": "../public/_nuxt/Dol-sKCS.js"
  },
  "/_nuxt/DoMz5Oah.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"75-0rHB7/NXhTPZAMenKS8+TUhYN2g\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 117,
    "path": "../public/_nuxt/DoMz5Oah.js"
  },
  "/_nuxt/DOxAN974.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-+96eCd2SfsnWFFrfVtDkJE8y1j8\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 110,
    "path": "../public/_nuxt/DOxAN974.js"
  },
  "/_nuxt/Dp439R8W.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-u9WMnztqFKUtHIZWIk45JnxjRIA\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 119,
    "path": "../public/_nuxt/Dp439R8W.js"
  },
  "/_nuxt/DpFJRVkT.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-UTNj7B8EtW2QRDfw+Kp05ejy/2U\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 113,
    "path": "../public/_nuxt/DpFJRVkT.js"
  },
  "/_nuxt/DpLAWEC3.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-haCf/UHtaS+wEM/40cQ5GCqfI2A\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 115,
    "path": "../public/_nuxt/DpLAWEC3.js"
  },
  "/_nuxt/DqiT91a0.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6f-LAUHGPGJraHzG7ncHJ9pMo80oXY\"",
    "mtime": "2026-05-26T18:57:58.711Z",
    "size": 111,
    "path": "../public/_nuxt/DqiT91a0.js"
  },
  "/_nuxt/DqUkL1Te.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-ueasEviOiwmzVdBMk/ZJVGddkCI\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 115,
    "path": "../public/_nuxt/DqUkL1Te.js"
  },
  "/_nuxt/DrTZ1kqX.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-S+ZONku/RtYPl1zO8xB/HvoDs94\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 119,
    "path": "../public/_nuxt/DrTZ1kqX.js"
  },
  "/_nuxt/DrrYbFKn.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-iQa9rdvanjfKGi9SW1LypCtewkY\"",
    "mtime": "2026-05-26T18:57:58.711Z",
    "size": 113,
    "path": "../public/_nuxt/DrrYbFKn.js"
  },
  "/_nuxt/DRuNxpRj.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"70-J1umX54kt9xEPCvC/NSt4UGJ4NM\"",
    "mtime": "2026-05-26T18:57:58.710Z",
    "size": 112,
    "path": "../public/_nuxt/DRuNxpRj.js"
  },
  "/_nuxt/DSjron9Q.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6c-LIo07hSxZG3Itx6H+u71LYfgu6A\"",
    "mtime": "2026-05-26T18:57:58.711Z",
    "size": 108,
    "path": "../public/_nuxt/DSjron9Q.js"
  },
  "/_nuxt/DT6wRgL1.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-Hk92//q1WDsISGbl0QZbB9E0V2o\"",
    "mtime": "2026-05-26T18:57:58.716Z",
    "size": 115,
    "path": "../public/_nuxt/DT6wRgL1.js"
  },
  "/_nuxt/DtYZtT6p.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-bPU3KD/6Cu6AkkAQe69vN9mIsD0\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 115,
    "path": "../public/_nuxt/DtYZtT6p.js"
  },
  "/_nuxt/Dvf-A1eg.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"dfa4-sKRZBWibvzZd5iyMsDaAYubYYvw\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 57252,
    "path": "../public/_nuxt/Dvf-A1eg.js"
  },
  "/_nuxt/DWeKgVqL.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-c5Q2L+DQAOJYIjsp2AJLSV7Yikk\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 119,
    "path": "../public/_nuxt/DWeKgVqL.js"
  },
  "/_nuxt/DWmJNJCP.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"74-QissZK/X5chgiMmx6joq0xqTo6M\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 116,
    "path": "../public/_nuxt/DWmJNJCP.js"
  },
  "/_nuxt/DWoE0sfL.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-Of5Sf93CDxkm+7axF/Zvkl6mAbY\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 119,
    "path": "../public/_nuxt/DWoE0sfL.js"
  },
  "/_nuxt/cover.DOD4l8zJ.mp4": {
    "type": "video/mp4",
    "etag": "\"7e5935-2oH85kWP9kUijzTwxOO499ZvtLM\"",
    "mtime": "2026-05-26T18:57:58.748Z",
    "size": 8280373,
    "path": "../public/_nuxt/cover.DOD4l8zJ.mp4"
  },
  "/_nuxt/DWqV-vwn.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-0+LEXpKTG7B/4rKmDD4ylDO6EyU\"",
    "mtime": "2026-05-26T18:57:58.716Z",
    "size": 114,
    "path": "../public/_nuxt/DWqV-vwn.js"
  },
  "/_nuxt/DwVkMJaw.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-N8TksQzpueVY7Ht3nNiHwtBfh0g\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 119,
    "path": "../public/_nuxt/DwVkMJaw.js"
  },
  "/_nuxt/Dxx1hHFf.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-UL+DdDzk+N6Tt+PB/OnX12xZ2+I\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 114,
    "path": "../public/_nuxt/Dxx1hHFf.js"
  },
  "/_nuxt/DYwcSPJY.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"75-6sRQo5ZEx6vtMspfbVFZmqjOAT0\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 117,
    "path": "../public/_nuxt/DYwcSPJY.js"
  },
  "/_nuxt/DzP0Vc8V.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6a-TsXNlZ9ldNNAcp/FiZAA6GQMXnw\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 106,
    "path": "../public/_nuxt/DzP0Vc8V.js"
  },
  "/_nuxt/cover.BJ_p9HYa.mp4": {
    "type": "video/mp4",
    "etag": "\"7cccb3-18JAFkajcM17yY0lKAibwYGg3KA\"",
    "mtime": "2026-05-26T18:57:58.748Z",
    "size": 8178867,
    "path": "../public/_nuxt/cover.BJ_p9HYa.mp4"
  },
  "/_nuxt/D_jmk6fb.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-5Ksh8UUA7zi8B25n8rzaqNQLx+Q\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 115,
    "path": "../public/_nuxt/D_jmk6fb.js"
  },
  "/_nuxt/D_STAkEs.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-Y2Al246Y3ePetZD/1OUzNPY2vRM\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 122,
    "path": "../public/_nuxt/D_STAkEs.js"
  },
  "/_nuxt/entry.BG5gjr-A.css": {
    "type": "text/css; charset=utf-8",
    "etag": "\"6d-t9oMXxXvlemgyaSiz9WjxFlDIBw\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 109,
    "path": "../public/_nuxt/entry.BG5gjr-A.css"
  },
  "/_nuxt/error-404.DL_4WIao.css": {
    "type": "text/css; charset=utf-8",
    "etag": "\"dca-KnjyV0UbpsrliiJzZx69defY74k\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 3530,
    "path": "../public/_nuxt/error-404.DL_4WIao.css"
  },
  "/_nuxt/error-500.I1Dtv2V5.css": {
    "type": "text/css; charset=utf-8",
    "etag": "\"75a-vEGyJqldBVJrnMfcLsrGaHcxYl0\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 1882,
    "path": "../public/_nuxt/error-500.I1Dtv2V5.css"
  },
  "/_nuxt/Eu4cgzaY.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-sPCkNRtv8fvFgarwfzWvDpVhslE\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 120,
    "path": "../public/_nuxt/Eu4cgzaY.js"
  },
  "/_nuxt/F49dW2QD.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6a-Q28tPZo4UXSxHrXtJpEKmwCuu5Y\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 106,
    "path": "../public/_nuxt/F49dW2QD.js"
  },
  "/_nuxt/fbVUumBB.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-04OTVMwIHh0NZThke+8E5QlCbpE\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 110,
    "path": "../public/_nuxt/fbVUumBB.js"
  },
  "/_nuxt/fj_dUhX-.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-hzTBqbP8+NMjBvOHB+mQgdExrjM\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 115,
    "path": "../public/_nuxt/fj_dUhX-.js"
  },
  "/_nuxt/fBiZTdOz.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-onWrnof3NZzxKUTLqydnCfAGU9M\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 119,
    "path": "../public/_nuxt/fBiZTdOz.js"
  },
  "/_nuxt/FOWfm034.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"79-U0qvG/D9gb8cO0AXHCF7v3WAWuU\"",
    "mtime": "2026-05-26T18:57:58.710Z",
    "size": 121,
    "path": "../public/_nuxt/FOWfm034.js"
  },
  "/_nuxt/fragile_1.BInGzSuV.webp": {
    "type": "image/webp",
    "etag": "\"b5e40-UkPw0Y2MazfiX8sdVjz6Al0PuFs\"",
    "mtime": "2026-05-26T18:57:58.720Z",
    "size": 745024,
    "path": "../public/_nuxt/fragile_1.BInGzSuV.webp"
  },
  "/_nuxt/fragile_10.DD2ApxVb.webp": {
    "type": "image/webp",
    "etag": "\"eda18-ug57Bvemf6U2pIW5rb2wIT3JVuM\"",
    "mtime": "2026-05-26T18:57:58.720Z",
    "size": 973336,
    "path": "../public/_nuxt/fragile_10.DD2ApxVb.webp"
  },
  "/_nuxt/fragile_11.C2nZ33KK.webp": {
    "type": "image/webp",
    "etag": "\"c1456-Jlw5sIpP4trYKHnznF3x2WsdB6k\"",
    "mtime": "2026-05-26T18:57:58.720Z",
    "size": 791638,
    "path": "../public/_nuxt/fragile_11.C2nZ33KK.webp"
  },
  "/_nuxt/fragile_12.U2gUXP6g.webp": {
    "type": "image/webp",
    "etag": "\"c9968-lPEfzNmS1Yy8bLiB2tMuYDikv0g\"",
    "mtime": "2026-05-26T18:57:58.720Z",
    "size": 825704,
    "path": "../public/_nuxt/fragile_12.U2gUXP6g.webp"
  },
  "/_nuxt/fragile_13.DENN5SWl.webp": {
    "type": "image/webp",
    "etag": "\"c6cce-DQR523uBr7SApCh5SyKNfkdiccI\"",
    "mtime": "2026-05-26T18:57:58.720Z",
    "size": 814286,
    "path": "../public/_nuxt/fragile_13.DENN5SWl.webp"
  },
  "/_nuxt/fragile_14.BwE0wvr9.webp": {
    "type": "image/webp",
    "etag": "\"aba2c-xUlvyFLZ7O7dihAvHsHqHbpG8z8\"",
    "mtime": "2026-05-26T18:57:58.720Z",
    "size": 703020,
    "path": "../public/_nuxt/fragile_14.BwE0wvr9.webp"
  },
  "/_nuxt/fragile_15.DGBJSrFO.webp": {
    "type": "image/webp",
    "etag": "\"c4004-D2k8se5fXKJJtRrubgCD0a/SfYc\"",
    "mtime": "2026-05-26T18:57:58.720Z",
    "size": 802820,
    "path": "../public/_nuxt/fragile_15.DGBJSrFO.webp"
  },
  "/_nuxt/fragile_16.CiROaqSG.webp": {
    "type": "image/webp",
    "etag": "\"bcdee-10wp+qJSWIfztBQSKyxwCdn4yic\"",
    "mtime": "2026-05-26T18:57:58.720Z",
    "size": 773614,
    "path": "../public/_nuxt/fragile_16.CiROaqSG.webp"
  },
  "/_nuxt/fragile_17.BdK3A_gg.webp": {
    "type": "image/webp",
    "etag": "\"bee9c-7qRS1spflnNlz0dU165+hd/xf1A\"",
    "mtime": "2026-05-26T18:57:58.720Z",
    "size": 781980,
    "path": "../public/_nuxt/fragile_17.BdK3A_gg.webp"
  },
  "/_nuxt/fragile_18.VvhRrGo7.webp": {
    "type": "image/webp",
    "etag": "\"b771e-0JeEHtnwheDVBddzmE+O2nssVeo\"",
    "mtime": "2026-05-26T18:57:58.720Z",
    "size": 751390,
    "path": "../public/_nuxt/fragile_18.VvhRrGo7.webp"
  },
  "/_nuxt/fragile_19.DAZlOwLh.webp": {
    "type": "image/webp",
    "etag": "\"b9176-vOZDbSC1meQjvNcxhKH6vYfYJ50\"",
    "mtime": "2026-05-26T18:57:58.720Z",
    "size": 758134,
    "path": "../public/_nuxt/fragile_19.DAZlOwLh.webp"
  },
  "/_nuxt/fragile_2.ry4bl73r.webp": {
    "type": "image/webp",
    "etag": "\"dca14-YewP70GA8J2D6Php69LuwGbQUd0\"",
    "mtime": "2026-05-26T18:57:58.720Z",
    "size": 903700,
    "path": "../public/_nuxt/fragile_2.ry4bl73r.webp"
  },
  "/_nuxt/fragile_20.CEIDH902.webp": {
    "type": "image/webp",
    "etag": "\"90b98-ENf6Yvjj8DJ/S8LG/nqrqLe106k\"",
    "mtime": "2026-05-26T18:57:58.720Z",
    "size": 592792,
    "path": "../public/_nuxt/fragile_20.CEIDH902.webp"
  },
  "/_nuxt/fragile_21.Dc2Ql6Dn.webp": {
    "type": "image/webp",
    "etag": "\"c2b7c-qJ/fWfZAAVUM1v82gFfvkWc3ajo\"",
    "mtime": "2026-05-26T18:57:58.720Z",
    "size": 797564,
    "path": "../public/_nuxt/fragile_21.Dc2Ql6Dn.webp"
  },
  "/_nuxt/fragile_22.Bi-5zxwq.webp": {
    "type": "image/webp",
    "etag": "\"ebb4e-vRDjfT8pu53rs/EomyDYCLH4grQ\"",
    "mtime": "2026-05-26T18:57:58.720Z",
    "size": 965454,
    "path": "../public/_nuxt/fragile_22.Bi-5zxwq.webp"
  },
  "/_nuxt/fragile_3.p5jhQa2X.webp": {
    "type": "image/webp",
    "etag": "\"af106-qcLKTDkULmajCToxcE4Jd46oATM\"",
    "mtime": "2026-05-26T18:57:58.720Z",
    "size": 717062,
    "path": "../public/_nuxt/fragile_3.p5jhQa2X.webp"
  },
  "/_nuxt/fs1OqnKa.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-pq7lgIhfu7sWFgadMxNlaEbDvck\"",
    "mtime": "2026-05-26T18:57:58.716Z",
    "size": 120,
    "path": "../public/_nuxt/fs1OqnKa.js"
  },
  "/_nuxt/G3qaogXG.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-z8WMd0i32EKQzOoo+MjU8MfYFso\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 114,
    "path": "../public/_nuxt/G3qaogXG.js"
  },
  "/_nuxt/fragile_4.DMeTVzyw.webp": {
    "type": "image/webp",
    "etag": "\"82b36-+d11dmrbyE/K1tLavMPUxCTUKbg\"",
    "mtime": "2026-05-26T18:57:58.720Z",
    "size": 535350,
    "path": "../public/_nuxt/fragile_4.DMeTVzyw.webp"
  },
  "/_nuxt/fragile_5.BFKFnNHY.webp": {
    "type": "image/webp",
    "etag": "\"ce2ba-eLyPezuxyevuUubr+UEKlPuiOfU\"",
    "mtime": "2026-05-26T18:57:58.720Z",
    "size": 844474,
    "path": "../public/_nuxt/fragile_5.BFKFnNHY.webp"
  },
  "/_nuxt/fragile_8.C4_Fd_f6.webp": {
    "type": "image/webp",
    "etag": "\"9734a-VVwitH0P6p/wXo1lsAyPahLgHzI\"",
    "mtime": "2026-05-26T18:57:58.720Z",
    "size": 619338,
    "path": "../public/_nuxt/fragile_8.C4_Fd_f6.webp"
  },
  "/_nuxt/fragile_7.CDyOkS-7.webp": {
    "type": "image/webp",
    "etag": "\"c6b14-1CwRNB4wRPkZE4vkOeuoEkb2qC4\"",
    "mtime": "2026-05-26T18:57:58.720Z",
    "size": 813844,
    "path": "../public/_nuxt/fragile_7.CDyOkS-7.webp"
  },
  "/_nuxt/fragile_6.BGx-vMjJ.webp": {
    "type": "image/webp",
    "etag": "\"c2db6-9uR4B6RqqANaXzRSWI5VeYme3iI\"",
    "mtime": "2026-05-26T18:57:58.721Z",
    "size": 798134,
    "path": "../public/_nuxt/fragile_6.BGx-vMjJ.webp"
  },
  "/_nuxt/fragile_9.CPnadO7F.webp": {
    "type": "image/webp",
    "etag": "\"acb36-Qw3XnyufMDO50aW+nuffujOGojg\"",
    "mtime": "2026-05-26T18:57:58.721Z",
    "size": 707382,
    "path": "../public/_nuxt/fragile_9.CPnadO7F.webp"
  },
  "/_nuxt/Gk8DFnCV.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-fjKzg3X89DtcCa5lTiOde52ZPCM\"",
    "mtime": "2026-05-26T18:57:58.716Z",
    "size": 115,
    "path": "../public/_nuxt/Gk8DFnCV.js"
  },
  "/_nuxt/gkI07bBC.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-P72Oosxu82tgGhgsgnqDucokxwU\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 119,
    "path": "../public/_nuxt/gkI07bBC.js"
  },
  "/_nuxt/HAAwlDbY.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"76-WV+QTA+kl+j/vA322gBrP1SFVPg\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 118,
    "path": "../public/_nuxt/HAAwlDbY.js"
  },
  "/_nuxt/heysport_01.BM9NsltV.webp": {
    "type": "image/webp",
    "etag": "\"606f6-r0JSNeuWVkZYFIVt4NRmsxByeZE\"",
    "mtime": "2026-05-26T18:57:58.694Z",
    "size": 394998,
    "path": "../public/_nuxt/heysport_01.BM9NsltV.webp"
  },
  "/_nuxt/guarn1.C9rWrX23.webp": {
    "type": "image/webp",
    "etag": "\"de318-q7gZN0afhCTKlj29DPQl1B/GtEA\"",
    "mtime": "2026-05-26T18:57:58.721Z",
    "size": 910104,
    "path": "../public/_nuxt/guarn1.C9rWrX23.webp"
  },
  "/_nuxt/guarn1_section.BHbzVaWT.webp": {
    "type": "image/webp",
    "etag": "\"93d74-K1ziaPHSpJlsL9tXuCUOmHA25lE\"",
    "mtime": "2026-05-26T18:57:58.721Z",
    "size": 605556,
    "path": "../public/_nuxt/guarn1_section.BHbzVaWT.webp"
  },
  "/_nuxt/heysport_010.CI9Laai8.webp": {
    "type": "image/webp",
    "etag": "\"64460-6CkyY4BBD7IWpMIbBFpr6tgeTVc\"",
    "mtime": "2026-05-26T18:57:58.694Z",
    "size": 410720,
    "path": "../public/_nuxt/heysport_010.CI9Laai8.webp"
  },
  "/_nuxt/heysport_011.lPGaFJYU.webp": {
    "type": "image/webp",
    "etag": "\"589c0-W3YI/M8QGruu1xhi0Rj795uunb0\"",
    "mtime": "2026-05-26T18:57:58.694Z",
    "size": 362944,
    "path": "../public/_nuxt/heysport_011.lPGaFJYU.webp"
  },
  "/_nuxt/heysport_012.WRlxwF5l.webp": {
    "type": "image/webp",
    "etag": "\"4c608-j1qx1+KLIkLq6F3JywyszNKCnjc\"",
    "mtime": "2026-05-26T18:57:58.694Z",
    "size": 312840,
    "path": "../public/_nuxt/heysport_012.WRlxwF5l.webp"
  },
  "/_nuxt/heysport_013.KFt41wJC.webp": {
    "type": "image/webp",
    "etag": "\"6271c-0TwhPM6jljkKLn9rSUE2tFVNcKA\"",
    "mtime": "2026-05-26T18:57:58.694Z",
    "size": 403228,
    "path": "../public/_nuxt/heysport_013.KFt41wJC.webp"
  },
  "/_nuxt/heysport_014.BebRmkKZ.webp": {
    "type": "image/webp",
    "etag": "\"53190-7knr5W88gE1OrtkiSbxYKsC10dY\"",
    "mtime": "2026-05-26T18:57:58.694Z",
    "size": 340368,
    "path": "../public/_nuxt/heysport_014.BebRmkKZ.webp"
  },
  "/_nuxt/heysport_016.j05En8Zn.webp": {
    "type": "image/webp",
    "etag": "\"67cf6-/kza/tk1yeznJiSCQ5VX5WHunrE\"",
    "mtime": "2026-05-26T18:57:58.694Z",
    "size": 425206,
    "path": "../public/_nuxt/heysport_016.j05En8Zn.webp"
  },
  "/_nuxt/heysport_017.CYe37wMH.webp": {
    "type": "image/webp",
    "etag": "\"5b9f2-UxX26J0JpyiOPqCV+Vah7rstGdM\"",
    "mtime": "2026-05-26T18:57:58.694Z",
    "size": 375282,
    "path": "../public/_nuxt/heysport_017.CYe37wMH.webp"
  },
  "/_nuxt/heysport_02.BgcqqUvr.webp": {
    "type": "image/webp",
    "etag": "\"5cfb8-NDqpnDKzoUVtdACyLJ21gpQSBk8\"",
    "mtime": "2026-05-26T18:57:58.694Z",
    "size": 380856,
    "path": "../public/_nuxt/heysport_02.BgcqqUvr.webp"
  },
  "/_nuxt/heysport_03.X2eig4UB.webp": {
    "type": "image/webp",
    "etag": "\"67386-rBzBNlOpgx1LaPwGzXgAs3rEXkk\"",
    "mtime": "2026-05-26T18:57:58.694Z",
    "size": 422790,
    "path": "../public/_nuxt/heysport_03.X2eig4UB.webp"
  },
  "/_nuxt/heysport_05.C_1gJlN6.webp": {
    "type": "image/webp",
    "etag": "\"53f0a-n8wvHxgKg69UWMTZt0vPu/WAjpg\"",
    "mtime": "2026-05-26T18:57:58.694Z",
    "size": 343818,
    "path": "../public/_nuxt/heysport_05.C_1gJlN6.webp"
  },
  "/_nuxt/heysport_04.bvyWxAzQ.webp": {
    "type": "image/webp",
    "etag": "\"55a22-X2wi6T49IKBPIyOntHQC9XD2hlI\"",
    "mtime": "2026-05-26T18:57:58.694Z",
    "size": 350754,
    "path": "../public/_nuxt/heysport_04.bvyWxAzQ.webp"
  },
  "/_nuxt/heysport_06.m93Dvraq.webp": {
    "type": "image/webp",
    "etag": "\"59c0e-RPYxbWcwY5PEmt+MiOS9gXDuTcc\"",
    "mtime": "2026-05-26T18:57:58.694Z",
    "size": 367630,
    "path": "../public/_nuxt/heysport_06.m93Dvraq.webp"
  },
  "/_nuxt/hfCJ1h4k.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"74-wRWlZIGxfKYlim4U+QfyxTxDuVo\"",
    "mtime": "2026-05-26T18:57:58.711Z",
    "size": 116,
    "path": "../public/_nuxt/hfCJ1h4k.js"
  },
  "/_nuxt/HlJ14IYq.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-N2PG5QsjE1C6lLPHkN7l/+LyIWg\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 107,
    "path": "../public/_nuxt/HlJ14IYq.js"
  },
  "/_nuxt/heysport_08.tbT2IgCt.webp": {
    "type": "image/webp",
    "etag": "\"5231c-QuTw7frJNpBwrHFUlydTp/k2x6k\"",
    "mtime": "2026-05-26T18:57:58.694Z",
    "size": 336668,
    "path": "../public/_nuxt/heysport_08.tbT2IgCt.webp"
  },
  "/_nuxt/i7-CRP3b.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-inNxJX/iCUS1wfjm8WnwjIsW1Qg\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 115,
    "path": "../public/_nuxt/i7-CRP3b.js"
  },
  "/_nuxt/hXDgaZEz.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"74-RwVYUSESG+gueSyFE+UByJ5YQyQ\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 116,
    "path": "../public/_nuxt/hXDgaZEz.js"
  },
  "/_nuxt/IOs2JNjh.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-nXfhuNY5La287R4o4rKFSwTZjLQ\"",
    "mtime": "2026-05-26T18:57:58.717Z",
    "size": 107,
    "path": "../public/_nuxt/IOs2JNjh.js"
  },
  "/_nuxt/iP-E0WhS.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-9+UT0vyKb66bB0joRKkNqB+fY+o\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 120,
    "path": "../public/_nuxt/iP-E0WhS.js"
  },
  "/_nuxt/iYAPGQnZ.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-4ATgRK6xiWYCVBMk1HPuVbwZMZE\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 113,
    "path": "../public/_nuxt/iYAPGQnZ.js"
  },
  "/_nuxt/jgM1uGtH.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-Of5Sf93CDxkm+7axF/Zvkl6mAbY\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 119,
    "path": "../public/_nuxt/jgM1uGtH.js"
  },
  "/_nuxt/kko3gE-Z.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6a-8C1UNBcc2IXxSbyKTCqW2T/vJZw\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 106,
    "path": "../public/_nuxt/kko3gE-Z.js"
  },
  "/_nuxt/KS2Mrt42.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-+p5J94ZREl0ZB9rzDUhigNUlanE\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 122,
    "path": "../public/_nuxt/KS2Mrt42.js"
  },
  "/_nuxt/Gara.DbmDujH0.mp4": {
    "type": "video/mp4",
    "etag": "\"2eec86-vu+Twn6LTEsQ5cron9K25+5pt0A\"",
    "mtime": "2026-05-26T18:57:58.746Z",
    "size": 3075206,
    "path": "../public/_nuxt/Gara.DbmDujH0.mp4"
  },
  "/_nuxt/lQOHH2EM.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-cv0MBVelM0vecfdKIWaJfEStpXA\"",
    "mtime": "2026-05-26T18:57:58.710Z",
    "size": 122,
    "path": "../public/_nuxt/lQOHH2EM.js"
  },
  "/_nuxt/l8IKUdnp.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-lF/NBGPTh075LR5+8kR1TBFZkcU\"",
    "mtime": "2026-05-26T18:57:58.716Z",
    "size": 115,
    "path": "../public/_nuxt/l8IKUdnp.js"
  },
  "/_nuxt/LsbDOjAZ.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-nQGQktyIOyaEcAr4FeQhVTHJjI0\"",
    "mtime": "2026-05-26T18:57:58.716Z",
    "size": 115,
    "path": "../public/_nuxt/LsbDOjAZ.js"
  },
  "/_nuxt/cover.CxMhcwUC.mp4": {
    "type": "video/mp4",
    "etag": "\"469029-yQNV8SO8FMYCaYrzeAt+0VSexcA\"",
    "mtime": "2026-05-26T18:57:58.747Z",
    "size": 4624425,
    "path": "../public/_nuxt/cover.CxMhcwUC.mp4"
  },
  "/_nuxt/LSmf7dZm.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-bpVmSDc2FywAAINJGp7Hs/2Nk7Y\"",
    "mtime": "2026-05-26T18:57:58.716Z",
    "size": 114,
    "path": "../public/_nuxt/LSmf7dZm.js"
  },
  "/_nuxt/lyQiCXji.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"70-8MXZizktQxbRMZ8oq9FIkiFNknM\"",
    "mtime": "2026-05-26T18:57:58.711Z",
    "size": 112,
    "path": "../public/_nuxt/lyQiCXji.js"
  },
  "/_nuxt/merlo_01.DbyfGf1P.webp": {
    "type": "image/webp",
    "etag": "\"27528-3nCLuQaeMPwR4sn8uykBb5U6EG0\"",
    "mtime": "2026-05-26T18:57:58.695Z",
    "size": 161064,
    "path": "../public/_nuxt/merlo_01.DbyfGf1P.webp"
  },
  "/_nuxt/merlo_02.B7aMcTXh.webp": {
    "type": "image/webp",
    "etag": "\"2d3e4-oLUf6Zf5jwrmZlwQjjtgoBRwR0Y\"",
    "mtime": "2026-05-26T18:57:58.695Z",
    "size": 185316,
    "path": "../public/_nuxt/merlo_02.B7aMcTXh.webp"
  },
  "/_nuxt/merlo_03.Cwi0r-2O.webp": {
    "type": "image/webp",
    "etag": "\"2341e-EpK7TYMw7XMNYNxODsIDUPowRUw\"",
    "mtime": "2026-05-26T18:57:58.695Z",
    "size": 144414,
    "path": "../public/_nuxt/merlo_03.Cwi0r-2O.webp"
  },
  "/_nuxt/merlo_04.CXeUGaMF.webp": {
    "type": "image/webp",
    "etag": "\"3af4a-23mdjB2R16n6sd0yU7xqlhrEP5s\"",
    "mtime": "2026-05-26T18:57:58.695Z",
    "size": 241482,
    "path": "../public/_nuxt/merlo_04.CXeUGaMF.webp"
  },
  "/_nuxt/merlo_06.rcBn_2ZC.webp": {
    "type": "image/webp",
    "etag": "\"3a916-26RIW1P7tpe34cv0suv3MZY/euI\"",
    "mtime": "2026-05-26T18:57:58.695Z",
    "size": 239894,
    "path": "../public/_nuxt/merlo_06.rcBn_2ZC.webp"
  },
  "/_nuxt/merlo_05.CPzD1Z6q.webp": {
    "type": "image/webp",
    "etag": "\"2f26c-GM6KZrbWQsrFeSA5udcH4dwHJMg\"",
    "mtime": "2026-05-26T18:57:58.695Z",
    "size": 193132,
    "path": "../public/_nuxt/merlo_05.CPzD1Z6q.webp"
  },
  "/_nuxt/merlo_07.G4uu6H_8.webp": {
    "type": "image/webp",
    "etag": "\"1c1c8-Gfz5ug0V+VhNzUITwNDvwUsXGIU\"",
    "mtime": "2026-05-26T18:57:58.695Z",
    "size": 115144,
    "path": "../public/_nuxt/merlo_07.G4uu6H_8.webp"
  },
  "/_nuxt/merlo_08.BUESYY5A.webp": {
    "type": "image/webp",
    "etag": "\"2c78e-rGuau8AsgcO3gaimgW4unFEN06E\"",
    "mtime": "2026-05-26T18:57:58.695Z",
    "size": 182158,
    "path": "../public/_nuxt/merlo_08.BUESYY5A.webp"
  },
  "/_nuxt/merlo_09.Dpw-H_1Z.webp": {
    "type": "image/webp",
    "etag": "\"16ccc-kLlF9U97/EjeeGfPNLaqIV3DuYs\"",
    "mtime": "2026-05-26T18:57:58.695Z",
    "size": 93388,
    "path": "../public/_nuxt/merlo_09.Dpw-H_1Z.webp"
  },
  "/_nuxt/mWj6gRGu.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-UXm9lc+0ZBKAeAJMmKTz1LVrwz4\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 120,
    "path": "../public/_nuxt/mWj6gRGu.js"
  },
  "/_nuxt/MyLamination-1.DEdhDx0K.webp": {
    "type": "image/webp",
    "etag": "\"58b2e-WTFK5JUre8yCt3dSu8S56eMf2yU\"",
    "mtime": "2026-05-26T18:57:58.695Z",
    "size": 363310,
    "path": "../public/_nuxt/MyLamination-1.DEdhDx0K.webp"
  },
  "/_nuxt/MyLamination-11.H-UCQOU2.webp": {
    "type": "image/webp",
    "etag": "\"70338-652I6I6ZnUdcmWcfY1IVaFqLDl0\"",
    "mtime": "2026-05-26T18:57:58.695Z",
    "size": 459576,
    "path": "../public/_nuxt/MyLamination-11.H-UCQOU2.webp"
  },
  "/_nuxt/MyLamination-13.j8h24tZT.webp": {
    "type": "image/webp",
    "etag": "\"4bd18-4GdOmbYhtEPpgVUuGUP/IS8eXFw\"",
    "mtime": "2026-05-26T18:57:58.695Z",
    "size": 310552,
    "path": "../public/_nuxt/MyLamination-13.j8h24tZT.webp"
  },
  "/_nuxt/MyLamination-14.DllIOz8w.webp": {
    "type": "image/webp",
    "etag": "\"77cc6-HxccVLA5RL7zJNE6tSqrbfCdPQU\"",
    "mtime": "2026-05-26T18:57:58.695Z",
    "size": 490694,
    "path": "../public/_nuxt/MyLamination-14.DllIOz8w.webp"
  },
  "/_nuxt/MyLamination-15.ZAPrPgHL.webp": {
    "type": "image/webp",
    "etag": "\"68926-Or7sTcnb+Tjg+46STOZE/xnF+9U\"",
    "mtime": "2026-05-26T18:57:58.695Z",
    "size": 428326,
    "path": "../public/_nuxt/MyLamination-15.ZAPrPgHL.webp"
  },
  "/_nuxt/MyLamination-16.BVAwx8av.webp": {
    "type": "image/webp",
    "etag": "\"692e2-n89H2EevVHSm7t9JVTdSZl85jdY\"",
    "mtime": "2026-05-26T18:57:58.695Z",
    "size": 430818,
    "path": "../public/_nuxt/MyLamination-16.BVAwx8av.webp"
  },
  "/_nuxt/MyLamination-3.CME1PvBS.webp": {
    "type": "image/webp",
    "etag": "\"541a2-XSYi6v1KvxHA8QCQHuu5KxuWXk8\"",
    "mtime": "2026-05-26T18:57:58.695Z",
    "size": 344482,
    "path": "../public/_nuxt/MyLamination-3.CME1PvBS.webp"
  },
  "/_nuxt/MyLamination-6.CQHkb8vj.webp": {
    "type": "image/webp",
    "etag": "\"53f9e-IIziVdMrfGIJrdLM2q2UWhOgLX0\"",
    "mtime": "2026-05-26T18:57:58.695Z",
    "size": 343966,
    "path": "../public/_nuxt/MyLamination-6.CQHkb8vj.webp"
  },
  "/_nuxt/MyLamination-5.SlyAbUEr.webp": {
    "type": "image/webp",
    "etag": "\"6c030-2uK9v32sZ5Vnlijt+gZw3PvRZ6k\"",
    "mtime": "2026-05-26T18:57:58.695Z",
    "size": 442416,
    "path": "../public/_nuxt/MyLamination-5.SlyAbUEr.webp"
  },
  "/_nuxt/MyLamination-7.CAZEQMJt.webp": {
    "type": "image/webp",
    "etag": "\"55c7c-TNgMbXxNYlQEgxate91wTTkX6ic\"",
    "mtime": "2026-05-26T18:57:58.695Z",
    "size": 351356,
    "path": "../public/_nuxt/MyLamination-7.CAZEQMJt.webp"
  },
  "/_nuxt/MyLamination-9.c29xTlFQ.webp": {
    "type": "image/webp",
    "etag": "\"75ad8-mGDrU5/21Ke2V3eNg1FeOZUiG1E\"",
    "mtime": "2026-05-26T18:57:58.695Z",
    "size": 482008,
    "path": "../public/_nuxt/MyLamination-9.c29xTlFQ.webp"
  },
  "/_nuxt/N7li3ZKB.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-NUgnjR4cImlH9G13g0UqdK6GOoI\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 110,
    "path": "../public/_nuxt/N7li3ZKB.js"
  },
  "/_nuxt/NC77Gkt2.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-lG2760ED2fVxRhX6F48RNK53re4\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 119,
    "path": "../public/_nuxt/NC77Gkt2.js"
  },
  "/_nuxt/MyLamination-17.BVJBbPWl.webp": {
    "type": "image/webp",
    "etag": "\"810f0-zzUCVidI8S/1Mv6whWrJ5Opej1g\"",
    "mtime": "2026-05-26T18:57:58.721Z",
    "size": 528624,
    "path": "../public/_nuxt/MyLamination-17.BVJBbPWl.webp"
  },
  "/_nuxt/n_17mhiL.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6a-V0C39saLlPOAPOcvnQsvf6Dzwqw\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 106,
    "path": "../public/_nuxt/n_17mhiL.js"
  },
  "/_nuxt/MyLamination-8._EcY2sqf.webp": {
    "type": "image/webp",
    "etag": "\"84b26-TRkZHm5RY+0n0iDIBN+SEiRnFko\"",
    "mtime": "2026-05-26T18:57:58.721Z",
    "size": 543526,
    "path": "../public/_nuxt/MyLamination-8._EcY2sqf.webp"
  },
  "/_nuxt/orYXUV2q.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-hONIPGwptoaSUVqetAO3T8YF878\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 115,
    "path": "../public/_nuxt/orYXUV2q.js"
  },
  "/_nuxt/PANA9339.DZ14lbIl.webp": {
    "type": "image/webp",
    "etag": "\"36858-PFx93h4yEZD3FY4ucbXyMqwR+YA\"",
    "mtime": "2026-05-26T18:57:58.692Z",
    "size": 223320,
    "path": "../public/_nuxt/PANA9339.DZ14lbIl.webp"
  },
  "/_nuxt/PANA9342.DPsXQ1Ck.webp": {
    "type": "image/webp",
    "etag": "\"24f5c-GhOTYIjWru0QU7BJ8iBS+T13Ti0\"",
    "mtime": "2026-05-26T18:57:58.693Z",
    "size": 151388,
    "path": "../public/_nuxt/PANA9342.DPsXQ1Ck.webp"
  },
  "/_nuxt/PANA9347.C6FNWSRe.webp": {
    "type": "image/webp",
    "etag": "\"32b22-abPIR6H/JmVwtyEP6NWMRb3hHTo\"",
    "mtime": "2026-05-26T18:57:58.693Z",
    "size": 207650,
    "path": "../public/_nuxt/PANA9347.C6FNWSRe.webp"
  },
  "/_nuxt/PANA9348.CwHsorxG.webp": {
    "type": "image/webp",
    "etag": "\"6f35e-mmXRkiWKu2/sandPhhsIO+MthEk\"",
    "mtime": "2026-05-26T18:57:58.693Z",
    "size": 455518,
    "path": "../public/_nuxt/PANA9348.CwHsorxG.webp"
  },
  "/_nuxt/PANA9392.CI_4YH72.webp": {
    "type": "image/webp",
    "etag": "\"54bda-eCBCSEH9Eyu8QO9ewMuHu1Hghhc\"",
    "mtime": "2026-05-26T18:57:58.693Z",
    "size": 347098,
    "path": "../public/_nuxt/PANA9392.CI_4YH72.webp"
  },
  "/_nuxt/PANA9395.CRsHSK3X.webp": {
    "type": "image/webp",
    "etag": "\"2fc90-Ypzjx7PrOK7QXfG60HEjyN83MYI\"",
    "mtime": "2026-05-26T18:57:58.693Z",
    "size": 195728,
    "path": "../public/_nuxt/PANA9395.CRsHSK3X.webp"
  },
  "/_nuxt/PANA9397.BFIGaeXp.webp": {
    "type": "image/webp",
    "etag": "\"44022-bGK5rATGWws4+dKSjabIpgBRrIE\"",
    "mtime": "2026-05-26T18:57:58.693Z",
    "size": 278562,
    "path": "../public/_nuxt/PANA9397.BFIGaeXp.webp"
  },
  "/_nuxt/PANA9401.-5XSY0zU.webp": {
    "type": "image/webp",
    "etag": "\"4fb84-NGaAO3V9OrwMY56xjoLB1MKYNJY\"",
    "mtime": "2026-05-26T18:57:58.693Z",
    "size": 326532,
    "path": "../public/_nuxt/PANA9401.-5XSY0zU.webp"
  },
  "/_nuxt/Mood.DOeN3S3Z.mp4": {
    "type": "video/mp4",
    "etag": "\"2053d6-VAXFeabJWrfYoKE5BBwaloqzMQY\"",
    "mtime": "2026-05-26T18:57:58.746Z",
    "size": 2118614,
    "path": "../public/_nuxt/Mood.DOeN3S3Z.mp4"
  },
  "/_nuxt/PANA9403.C8awFeF2.webp": {
    "type": "image/webp",
    "etag": "\"6610c-OtHDksgp37lmIVi2TlgADrjZOQ8\"",
    "mtime": "2026-05-26T18:57:58.693Z",
    "size": 418060,
    "path": "../public/_nuxt/PANA9403.C8awFeF2.webp"
  },
  "/_nuxt/PANA9405.DycVmkCK.webp": {
    "type": "image/webp",
    "etag": "\"b78ca-BCAnQDc578V7xKfQyO93YCdkiXU\"",
    "mtime": "2026-05-26T18:57:58.719Z",
    "size": 751818,
    "path": "../public/_nuxt/PANA9405.DycVmkCK.webp"
  },
  "/_nuxt/PANA9412.IQen3UPO.webp": {
    "type": "image/webp",
    "etag": "\"37d42-QFUk9zSoDDzcqX/9lgduJeLSZR0\"",
    "mtime": "2026-05-26T18:57:58.693Z",
    "size": 228674,
    "path": "../public/_nuxt/PANA9412.IQen3UPO.webp"
  },
  "/_nuxt/PANA9407.BcPLIf9C.webp": {
    "type": "image/webp",
    "etag": "\"c7a4c-KDzh/czGFYGC2IU2FwCJ+IIksZU\"",
    "mtime": "2026-05-26T18:57:58.719Z",
    "size": 817740,
    "path": "../public/_nuxt/PANA9407.BcPLIf9C.webp"
  },
  "/_nuxt/pdhhrtDW.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6a-IR75ucdd1i+A6WlcZzIMYjfZwf4\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 106,
    "path": "../public/_nuxt/pdhhrtDW.js"
  },
  "/_nuxt/PHVYDAPV.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-sDtkyXdsjalBUvHjByxspXetU8c\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 119,
    "path": "../public/_nuxt/PHVYDAPV.js"
  },
  "/_nuxt/PowerGrotesk-Regular.DNJ9ML-1.woff2": {
    "type": "font/woff2",
    "etag": "\"53b4-3y3eUrmFI11SKzg4U8TvS0hSFf0\"",
    "mtime": "2026-05-26T18:57:58.692Z",
    "size": 21428,
    "path": "../public/_nuxt/PowerGrotesk-Regular.DNJ9ML-1.woff2"
  },
  "/_nuxt/PUpacSz8.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-nHE/4mrhtLYhRLKk8GD+ES4Lguk\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 114,
    "path": "../public/_nuxt/PUpacSz8.js"
  },
  "/_nuxt/QCYEJSU0.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-onWrnof3NZzxKUTLqydnCfAGU9M\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 119,
    "path": "../public/_nuxt/QCYEJSU0.js"
  },
  "/_nuxt/PANA9409.DaHVepRC.webp": {
    "type": "image/webp",
    "etag": "\"90d5e-ZxuPoT/GAPFrjfPHQLapmuaj0pk\"",
    "mtime": "2026-05-26T18:57:58.719Z",
    "size": 593246,
    "path": "../public/_nuxt/PANA9409.DaHVepRC.webp"
  },
  "/_nuxt/QiRUP_Y1.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6f-cxPXBxaC89nCW/793cgP3qu/nF0\"",
    "mtime": "2026-05-26T18:57:58.711Z",
    "size": 111,
    "path": "../public/_nuxt/QiRUP_Y1.js"
  },
  "/_nuxt/qYH3qyU8.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6a-rnrqrXLXwaTRGG49E63OwvBbWMI\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 106,
    "path": "../public/_nuxt/qYH3qyU8.js"
  },
  "/_nuxt/rigolizia_1.H552A0St.webp": {
    "type": "image/webp",
    "etag": "\"59a08-zN+Pnj/4y3XrJZdkTupf2aJThwM\"",
    "mtime": "2026-05-26T18:57:58.695Z",
    "size": 367112,
    "path": "../public/_nuxt/rigolizia_1.H552A0St.webp"
  },
  "/_nuxt/rigolizia_10.DWCP-yRx.webp": {
    "type": "image/webp",
    "etag": "\"790fa-dlmcVAwT6FdGdAfxDgeNsLfkbJQ\"",
    "mtime": "2026-05-26T18:57:58.695Z",
    "size": 495866,
    "path": "../public/_nuxt/rigolizia_10.DWCP-yRx.webp"
  },
  "/_nuxt/RANDOM4.C23X0MsK.webp": {
    "type": "image/webp",
    "etag": "\"e9b7e-vQSdFeKiy/RXJ3ko04jhEE/r15M\"",
    "mtime": "2026-05-26T18:57:58.718Z",
    "size": 957310,
    "path": "../public/_nuxt/RANDOM4.C23X0MsK.webp"
  },
  "/_nuxt/rigolizia_13.BTCnC0t2.webp": {
    "type": "image/webp",
    "etag": "\"65c98-llWO0lyGevMk/gvVd4X8xSHwYD0\"",
    "mtime": "2026-05-26T18:57:58.696Z",
    "size": 416920,
    "path": "../public/_nuxt/rigolizia_13.BTCnC0t2.webp"
  },
  "/_nuxt/rigolizia_11.DYXd5iPW.webp": {
    "type": "image/webp",
    "etag": "\"bee6c-sgGLeW8qKSvFIvcU8a8nJ2hiGb4\"",
    "mtime": "2026-05-26T18:57:58.721Z",
    "size": 781932,
    "path": "../public/_nuxt/rigolizia_11.DYXd5iPW.webp"
  },
  "/_nuxt/rigolizia_12.DqkzmLrs.webp": {
    "type": "image/webp",
    "etag": "\"9f072-85pO+SShlLqHMnqytZ6KUfIWrxo\"",
    "mtime": "2026-05-26T18:57:58.721Z",
    "size": 651378,
    "path": "../public/_nuxt/rigolizia_12.DqkzmLrs.webp"
  },
  "/_nuxt/RANDOM19.55xTwRTV.webp": {
    "type": "image/webp",
    "etag": "\"17e62a-0/N7T2hLK6wv9/UMrFjdfoIsLkc\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1566250,
    "path": "../public/_nuxt/RANDOM19.55xTwRTV.webp"
  },
  "/_nuxt/rigolizia_14.DXN9OKAR.webp": {
    "type": "image/webp",
    "etag": "\"c5ad0-mAYHhbfFuzYG7sLQiwDrdkJnrPA\"",
    "mtime": "2026-05-26T18:57:58.721Z",
    "size": 809680,
    "path": "../public/_nuxt/rigolizia_14.DXN9OKAR.webp"
  },
  "/_nuxt/rigolizia_15.Dq5rQ8kX.webp": {
    "type": "image/webp",
    "etag": "\"966ac-oC2/SvUTq2boR4l0VRyt0eSwGyY\"",
    "mtime": "2026-05-26T18:57:58.721Z",
    "size": 616108,
    "path": "../public/_nuxt/rigolizia_15.Dq5rQ8kX.webp"
  },
  "/_nuxt/rigolizia_17.sc9Ntezp.webp": {
    "type": "image/webp",
    "etag": "\"cf8f6-wKYdlvMMvZDz1+VyTry3P/3GDaY\"",
    "mtime": "2026-05-26T18:57:58.721Z",
    "size": 850166,
    "path": "../public/_nuxt/rigolizia_17.sc9Ntezp.webp"
  },
  "/_nuxt/rigolizia_18.BGpsXjTo.webp": {
    "type": "image/webp",
    "etag": "\"bf8a6-ZIxDWaHLVmosB7F2y2zfY1BPBYc\"",
    "mtime": "2026-05-26T18:57:58.722Z",
    "size": 784550,
    "path": "../public/_nuxt/rigolizia_18.BGpsXjTo.webp"
  },
  "/_nuxt/rigolizia_19.Ct2yh91A.webp": {
    "type": "image/webp",
    "etag": "\"8e8ec-KZ8xgPSBLplhUwG/3xF2xmj41Vc\"",
    "mtime": "2026-05-26T18:57:58.721Z",
    "size": 583916,
    "path": "../public/_nuxt/rigolizia_19.Ct2yh91A.webp"
  },
  "/_nuxt/rigolizia_2.DwB3YPvP.webp": {
    "type": "image/webp",
    "etag": "\"9c8da-3NmvoBBeHGMPLSO0AwgzcRMk1+s\"",
    "mtime": "2026-05-26T18:57:58.721Z",
    "size": 641242,
    "path": "../public/_nuxt/rigolizia_2.DwB3YPvP.webp"
  },
  "/_nuxt/rigolizia_22.Cd28j9ND.webp": {
    "type": "image/webp",
    "etag": "\"723a4-zHcAG45I9Pgor3Sw/VFdeS5/aII\"",
    "mtime": "2026-05-26T18:57:58.696Z",
    "size": 467876,
    "path": "../public/_nuxt/rigolizia_22.Cd28j9ND.webp"
  },
  "/_nuxt/rigolizia_20.BVewlEKg.webp": {
    "type": "image/webp",
    "etag": "\"87c28-zW9DNQCgN5+AnKS6BbAkNU0SArs\"",
    "mtime": "2026-05-26T18:57:58.721Z",
    "size": 556072,
    "path": "../public/_nuxt/rigolizia_20.BVewlEKg.webp"
  },
  "/_nuxt/rigolizia_21.BqkTF_uc.webp": {
    "type": "image/webp",
    "etag": "\"947a6-A8pljk0RhmjDGITC096XzmpD/N0\"",
    "mtime": "2026-05-26T18:57:58.722Z",
    "size": 608166,
    "path": "../public/_nuxt/rigolizia_21.BqkTF_uc.webp"
  },
  "/_nuxt/rigolizia_23.Ch5TH77J.webp": {
    "type": "image/webp",
    "etag": "\"aeeee-H4AOHo/7dOgLDKfMaxJV2nL+1n0\"",
    "mtime": "2026-05-26T18:57:58.722Z",
    "size": 716526,
    "path": "../public/_nuxt/rigolizia_23.Ch5TH77J.webp"
  },
  "/_nuxt/rigolizia_3.BE2wZv0G.webp": {
    "type": "image/webp",
    "etag": "\"9d0e0-oe67DWCbmJUyXYpCqEFTAIE3GEk\"",
    "mtime": "2026-05-26T18:57:58.722Z",
    "size": 643296,
    "path": "../public/_nuxt/rigolizia_3.BE2wZv0G.webp"
  },
  "/_nuxt/rigolizia_4.C6m7ewT5.webp": {
    "type": "image/webp",
    "etag": "\"9e5fc-yWiQBYT3amJPDgOqQcJ+lgiiYrs\"",
    "mtime": "2026-05-26T18:57:58.722Z",
    "size": 648700,
    "path": "../public/_nuxt/rigolizia_4.C6m7ewT5.webp"
  },
  "/_nuxt/rigolizia_5.DO5cyP62.webp": {
    "type": "image/webp",
    "etag": "\"91e2a-6AeUDa87HD+wQZ6ha/UjWiiElBU\"",
    "mtime": "2026-05-26T18:57:58.722Z",
    "size": 597546,
    "path": "../public/_nuxt/rigolizia_5.DO5cyP62.webp"
  },
  "/_nuxt/rigolizia_6.BLQdPqo9.webp": {
    "type": "image/webp",
    "etag": "\"a33a6-wteMFqSoMNHPkCloLfX7qYSMh9s\"",
    "mtime": "2026-05-26T18:57:58.723Z",
    "size": 668582,
    "path": "../public/_nuxt/rigolizia_6.BLQdPqo9.webp"
  },
  "/_nuxt/rigolizia_7.DaWq9N-y.webp": {
    "type": "image/webp",
    "etag": "\"9c282-YI5h8x9aBnqwt0CSSpxcDt58WwU\"",
    "mtime": "2026-05-26T18:57:58.722Z",
    "size": 639618,
    "path": "../public/_nuxt/rigolizia_7.DaWq9N-y.webp"
  },
  "/_nuxt/rigolizia_8.la8zDCTp.webp": {
    "type": "image/webp",
    "etag": "\"a3f92-8XNUQkEC/RhmsBn6az5cE9ILMEM\"",
    "mtime": "2026-05-26T18:57:58.722Z",
    "size": 671634,
    "path": "../public/_nuxt/rigolizia_8.la8zDCTp.webp"
  },
  "/_nuxt/rigolizia_9.D-0LNBMg.webp": {
    "type": "image/webp",
    "etag": "\"bfd72-P3us9UUJbSMq8OfgQyoD+dhfxxg\"",
    "mtime": "2026-05-26T18:57:58.722Z",
    "size": 785778,
    "path": "../public/_nuxt/rigolizia_9.D-0LNBMg.webp"
  },
  "/_nuxt/roma_2026_104.TX3LaVAi.webp": {
    "type": "image/webp",
    "etag": "\"e4c54-z53Z4x9uGqy66UbT3e6vMwaEXew\"",
    "mtime": "2026-05-26T18:57:58.722Z",
    "size": 937044,
    "path": "../public/_nuxt/roma_2026_104.TX3LaVAi.webp"
  },
  "/_nuxt/Paganella-Prep.D-lEEBse.mp4": {
    "type": "video/mp4",
    "etag": "\"483428-0XGEEoKjQAOsYcAtxcJ0MKK8g7I\"",
    "mtime": "2026-05-26T18:57:58.747Z",
    "size": 4731944,
    "path": "../public/_nuxt/Paganella-Prep.D-lEEBse.mp4"
  },
  "/_nuxt/roma_2026_132.CeTqVtpz.webp": {
    "type": "image/webp",
    "etag": "\"b4932-s23NGZFE4Lbs8gaGmSNsp5nMlcg\"",
    "mtime": "2026-05-26T18:57:58.722Z",
    "size": 739634,
    "path": "../public/_nuxt/roma_2026_132.CeTqVtpz.webp"
  },
  "/_nuxt/roma_2026_121.Do1wCuia.webp": {
    "type": "image/webp",
    "etag": "\"f8148-WYG8Cnh3lMWt49jFVFYQqCbNTkM\"",
    "mtime": "2026-05-26T18:57:58.723Z",
    "size": 1016136,
    "path": "../public/_nuxt/roma_2026_121.Do1wCuia.webp"
  },
  "/_nuxt/roma_2026_114.H-aKDmFY.webp": {
    "type": "image/webp",
    "etag": "\"135752-UIHtUwsnhIxvZPZfz8Pc0sv6XcM\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1267538,
    "path": "../public/_nuxt/roma_2026_114.H-aKDmFY.webp"
  },
  "/_nuxt/roma_2026_15.DWf4L3zu.webp": {
    "type": "image/webp",
    "etag": "\"e741c-GEmyqNpPD+3LFt6sw0J7BztZ6nY\"",
    "mtime": "2026-05-26T18:57:58.723Z",
    "size": 947228,
    "path": "../public/_nuxt/roma_2026_15.DWf4L3zu.webp"
  },
  "/_nuxt/roma_2026_151.Bj0PQCWN.webp": {
    "type": "image/webp",
    "etag": "\"e6f70-GBUSN8jI8ZP2AMjK+b8a++P5+8o\"",
    "mtime": "2026-05-26T18:57:58.723Z",
    "size": 946032,
    "path": "../public/_nuxt/roma_2026_151.Bj0PQCWN.webp"
  },
  "/_nuxt/roma_2026_16.DQ4lnpMb.webp": {
    "type": "image/webp",
    "etag": "\"ebf08-GjJN/yGrV7A5gMMxh8xjuFFwv6w\"",
    "mtime": "2026-05-26T18:57:58.723Z",
    "size": 966408,
    "path": "../public/_nuxt/roma_2026_16.DQ4lnpMb.webp"
  },
  "/_nuxt/roma_2026_140.BL7YY3UN.webp": {
    "type": "image/webp",
    "etag": "\"11630a-upL4yHROcEI658k+b8OLy9RTYL4\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1139466,
    "path": "../public/_nuxt/roma_2026_140.BL7YY3UN.webp"
  },
  "/_nuxt/roma_2026_167.uy7pMQ1S.webp": {
    "type": "image/webp",
    "etag": "\"c55b6-atuoWOSVFDjekLsXNAdnccnkoTg\"",
    "mtime": "2026-05-26T18:57:58.723Z",
    "size": 808374,
    "path": "../public/_nuxt/roma_2026_167.uy7pMQ1S.webp"
  },
  "/_nuxt/roma_2026_168.CgKBD66M.webp": {
    "type": "image/webp",
    "etag": "\"c7b80-GnXaXQY943IJNE7rF5ZLlFPkbKg\"",
    "mtime": "2026-05-26T18:57:58.723Z",
    "size": 818048,
    "path": "../public/_nuxt/roma_2026_168.CgKBD66M.webp"
  },
  "/_nuxt/roma_2026_173.B_1v2i5E.webp": {
    "type": "image/webp",
    "etag": "\"bfe9a-39THK/GgLQFzcVP7+JaFIjEMoOU\"",
    "mtime": "2026-05-26T18:57:58.723Z",
    "size": 786074,
    "path": "../public/_nuxt/roma_2026_173.B_1v2i5E.webp"
  },
  "/_nuxt/roma_2026_153.D9U4xmGH.webp": {
    "type": "image/webp",
    "etag": "\"102a04-qPQKkglY205DQg15P5DMqH6b8mE\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1059332,
    "path": "../public/_nuxt/roma_2026_153.D9U4xmGH.webp"
  },
  "/_nuxt/roma_2026_18.Df7ri95l.webp": {
    "type": "image/webp",
    "etag": "\"10fb7a-W3TjXwtW+HDNEb0MWPG8Tzh3zxQ\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1112954,
    "path": "../public/_nuxt/roma_2026_18.Df7ri95l.webp"
  },
  "/_nuxt/roma_2026_187.DG7fb2SX.webp": {
    "type": "image/webp",
    "etag": "\"17c9b4-vynKO4OS6rzG6rlDr6TOHcr3XMw\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1558964,
    "path": "../public/_nuxt/roma_2026_187.DG7fb2SX.webp"
  },
  "/_nuxt/roma_2026_198.BneHqWUc.webp": {
    "type": "image/webp",
    "etag": "\"c9838-p7+Td8dTQwjZYP9QY/zdGhs0SfY\"",
    "mtime": "2026-05-26T18:57:58.723Z",
    "size": 825400,
    "path": "../public/_nuxt/roma_2026_198.BneHqWUc.webp"
  },
  "/_nuxt/roma_2026_203.6h6jbqFp.webp": {
    "type": "image/webp",
    "etag": "\"bde6a-0zy+W6HV+zqruYapoyFeHr6HVDs\"",
    "mtime": "2026-05-26T18:57:58.723Z",
    "size": 777834,
    "path": "../public/_nuxt/roma_2026_203.6h6jbqFp.webp"
  },
  "/_nuxt/roma_2026_204.DBY5_thM.webp": {
    "type": "image/webp",
    "etag": "\"cdd70-XkC1BdNgZT5aZXM5aZ9v13fwImc\"",
    "mtime": "2026-05-26T18:57:58.723Z",
    "size": 843120,
    "path": "../public/_nuxt/roma_2026_204.DBY5_thM.webp"
  },
  "/_nuxt/roma_2026_218.CiYacnta.webp": {
    "type": "image/webp",
    "etag": "\"f87b0-3Ph1/duhl9jPyM8NUCk8EKFaNiQ\"",
    "mtime": "2026-05-26T18:57:58.723Z",
    "size": 1017776,
    "path": "../public/_nuxt/roma_2026_218.CiYacnta.webp"
  },
  "/_nuxt/roma_2026_22.DiuCUPlo.webp": {
    "type": "image/webp",
    "etag": "\"f01f2-YdIHuVewkiVDYmcE6AjY6vdjbek\"",
    "mtime": "2026-05-26T18:57:58.723Z",
    "size": 983538,
    "path": "../public/_nuxt/roma_2026_22.DiuCUPlo.webp"
  },
  "/_nuxt/roma_2026_220.C9kZ9-S0.webp": {
    "type": "image/webp",
    "etag": "\"a7c20-3PTq6otuKTORiaOYVhGsOQZ7AuE\"",
    "mtime": "2026-05-26T18:57:58.723Z",
    "size": 687136,
    "path": "../public/_nuxt/roma_2026_220.C9kZ9-S0.webp"
  },
  "/_nuxt/roma_2026_188.CoLt3KVy.webp": {
    "type": "image/webp",
    "etag": "\"1608a2-8H69bUZ0PXs40wf9N1n6C5FzwmA\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1444002,
    "path": "../public/_nuxt/roma_2026_188.CoLt3KVy.webp"
  },
  "/_nuxt/roma_2026_189.BNZqO7r3.webp": {
    "type": "image/webp",
    "etag": "\"106bbe-3DLZpGuY8m9TYOiPSfZRzd10f/M\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1076158,
    "path": "../public/_nuxt/roma_2026_189.BNZqO7r3.webp"
  },
  "/_nuxt/roma_2026_23.BQ_A61VZ.webp": {
    "type": "image/webp",
    "etag": "\"e9d76-OTHiP3Tm3/UUCzX6ouGIogTHNe0\"",
    "mtime": "2026-05-26T18:57:58.723Z",
    "size": 957814,
    "path": "../public/_nuxt/roma_2026_23.BQ_A61VZ.webp"
  },
  "/_nuxt/roma_2026_235.CMfqqm1Y.webp": {
    "type": "image/webp",
    "etag": "\"ec1fc-fb6729AabNE1rFc76lMBX8vlx1U\"",
    "mtime": "2026-05-26T18:57:58.723Z",
    "size": 967164,
    "path": "../public/_nuxt/roma_2026_235.CMfqqm1Y.webp"
  },
  "/_nuxt/roma_2026_266.DjdEli03.webp": {
    "type": "image/webp",
    "etag": "\"d7b62-oaNNjg5XYlW1x62Lgwb9SEb7ieM\"",
    "mtime": "2026-05-26T18:57:58.723Z",
    "size": 883554,
    "path": "../public/_nuxt/roma_2026_266.DjdEli03.webp"
  },
  "/_nuxt/roma_2026_272.DCK_2NOt.webp": {
    "type": "image/webp",
    "etag": "\"ff14c-ebQ/WW51FPWIfHOtotdfLhergQQ\"",
    "mtime": "2026-05-26T18:57:58.723Z",
    "size": 1044812,
    "path": "../public/_nuxt/roma_2026_272.DCK_2NOt.webp"
  },
  "/_nuxt/roma_2026_279.DeTN01NJ.webp": {
    "type": "image/webp",
    "etag": "\"d61c6-Vk56pgHngNGOvqeY189CQQph6yg\"",
    "mtime": "2026-05-26T18:57:58.723Z",
    "size": 876998,
    "path": "../public/_nuxt/roma_2026_279.DeTN01NJ.webp"
  },
  "/_nuxt/roma_2026_288.BJwV5P4E.webp": {
    "type": "image/webp",
    "etag": "\"c2fc4-9vHfsDp0twK8nQ/n/2Bmki1mj5w\"",
    "mtime": "2026-05-26T18:57:58.723Z",
    "size": 798660,
    "path": "../public/_nuxt/roma_2026_288.BJwV5P4E.webp"
  },
  "/_nuxt/roma_2026_291.Ch4juJAw.webp": {
    "type": "image/webp",
    "etag": "\"ea260-k6L9VZfC8+9T4W1b7SotfPjA6tA\"",
    "mtime": "2026-05-26T18:57:58.723Z",
    "size": 959072,
    "path": "../public/_nuxt/roma_2026_291.Ch4juJAw.webp"
  },
  "/_nuxt/roma_2026_297.C6LN4qFX.webp": {
    "type": "image/webp",
    "etag": "\"df80c-qdCEkiUHPTXmL7xudnloel+4uwg\"",
    "mtime": "2026-05-26T18:57:58.724Z",
    "size": 915468,
    "path": "../public/_nuxt/roma_2026_297.C6LN4qFX.webp"
  },
  "/_nuxt/roma_2026_298.DprIcLC4.webp": {
    "type": "image/webp",
    "etag": "\"e49a8-25GOS9NjOwPziJ7sV6GnQxrSG1Y\"",
    "mtime": "2026-05-26T18:57:58.724Z",
    "size": 936360,
    "path": "../public/_nuxt/roma_2026_298.DprIcLC4.webp"
  },
  "/_nuxt/roma_2026_290.BS1kCZPo.webp": {
    "type": "image/webp",
    "etag": "\"12c326-FyR0aa7v1rQ6S/5ILDetqR+lwCs\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1229606,
    "path": "../public/_nuxt/roma_2026_290.BS1kCZPo.webp"
  },
  "/_nuxt/roma_2026_313.CRNEluWa.webp": {
    "type": "image/webp",
    "etag": "\"ea360-CVW5fbH6+8SpeyxfhmnSYoMLhmY\"",
    "mtime": "2026-05-26T18:57:58.724Z",
    "size": 959328,
    "path": "../public/_nuxt/roma_2026_313.CRNEluWa.webp"
  },
  "/_nuxt/roma_2026_315.DaOUjldo.webp": {
    "type": "image/webp",
    "etag": "\"aedf2-og3ctDZFwySJB3aoMPJRk4RkMGE\"",
    "mtime": "2026-05-26T18:57:58.724Z",
    "size": 716274,
    "path": "../public/_nuxt/roma_2026_315.DaOUjldo.webp"
  },
  "/_nuxt/roma_2026_303.Fq_WbT2g.webp": {
    "type": "image/webp",
    "etag": "\"108174-uAjMxdH4EuKexsof0/6CmxqLRrw\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1081716,
    "path": "../public/_nuxt/roma_2026_303.Fq_WbT2g.webp"
  },
  "/_nuxt/roma_2026_30.BD_CuaaH.webp": {
    "type": "image/webp",
    "etag": "\"10e08e-WMmYhkEApYmmu5/pKwFQhZuLEC8\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1106062,
    "path": "../public/_nuxt/roma_2026_30.BD_CuaaH.webp"
  },
  "/_nuxt/roma_2026_320.CbDLFc3w.webp": {
    "type": "image/webp",
    "etag": "\"c6720-KcI0yUFpLroA1sRLwJ43aH8KySc\"",
    "mtime": "2026-05-26T18:57:58.724Z",
    "size": 812832,
    "path": "../public/_nuxt/roma_2026_320.CbDLFc3w.webp"
  },
  "/_nuxt/roma_2026_31.Bsk4Lpyi.webp": {
    "type": "image/webp",
    "etag": "\"160378-oBOb/DTqQ0SzGqboRvOoTO3f7Lw\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1442680,
    "path": "../public/_nuxt/roma_2026_31.Bsk4Lpyi.webp"
  },
  "/_nuxt/roma_2026_321.B6p4qE2O.webp": {
    "type": "image/webp",
    "etag": "\"ce06e-9lSfxaO5XnI6Xv3d2nK6Hcjea+w\"",
    "mtime": "2026-05-26T18:57:58.724Z",
    "size": 843886,
    "path": "../public/_nuxt/roma_2026_321.B6p4qE2O.webp"
  },
  "/_nuxt/roma_2026_322.1E49Pmje.webp": {
    "type": "image/webp",
    "etag": "\"9de60-k9q9nVjUwvityNnqE1tboJcRW8o\"",
    "mtime": "2026-05-26T18:57:58.724Z",
    "size": 646752,
    "path": "../public/_nuxt/roma_2026_322.1E49Pmje.webp"
  },
  "/_nuxt/roma_2026_329.DYt7lfyO.webp": {
    "type": "image/webp",
    "etag": "\"c4044-34fRXxC/OYpsETMGEJCK5HrrhJ4\"",
    "mtime": "2026-05-26T18:57:58.724Z",
    "size": 802884,
    "path": "../public/_nuxt/roma_2026_329.DYt7lfyO.webp"
  },
  "/_nuxt/roma_2026_64._nTdqetq.webp": {
    "type": "image/webp",
    "etag": "\"f6086-qbZx9qF3nTfb6IF27XCwAFiCLU0\"",
    "mtime": "2026-05-26T18:57:58.724Z",
    "size": 1007750,
    "path": "../public/_nuxt/roma_2026_64._nTdqetq.webp"
  },
  "/_nuxt/roma_2026_80.BH9gKYAB.webp": {
    "type": "image/webp",
    "etag": "\"c9682-Mqx25uNre2fEjlolScgqTREsW1M\"",
    "mtime": "2026-05-26T18:57:58.724Z",
    "size": 824962,
    "path": "../public/_nuxt/roma_2026_80.BH9gKYAB.webp"
  },
  "/_nuxt/roma_2026_72.BRGmYTPv.webp": {
    "type": "image/webp",
    "etag": "\"ef19a-zDC2af4cT9rHfGka3bsuOo6qs4k\"",
    "mtime": "2026-05-26T18:57:58.724Z",
    "size": 979354,
    "path": "../public/_nuxt/roma_2026_72.BRGmYTPv.webp"
  },
  "/_nuxt/roma_2026_82.CpwpqEY3.webp": {
    "type": "image/webp",
    "etag": "\"da4ac-/lMaD0RJQJ9fHCi13JIw2iYNoT0\"",
    "mtime": "2026-05-26T18:57:58.724Z",
    "size": 894124,
    "path": "../public/_nuxt/roma_2026_82.CpwpqEY3.webp"
  },
  "/_nuxt/roma_2026_33.GFVzvQnb.webp": {
    "type": "image/webp",
    "etag": "\"106696-60+8Vn4+yOKhtqNGeJ4ycLgvaEo\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1074838,
    "path": "../public/_nuxt/roma_2026_33.GFVzvQnb.webp"
  },
  "/_nuxt/roma_2026_36.BHbVEvUP.webp": {
    "type": "image/webp",
    "etag": "\"124d44-9lQGBQPERaPY+gntuFCfgCMs668\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1199428,
    "path": "../public/_nuxt/roma_2026_36.BHbVEvUP.webp"
  },
  "/_nuxt/roma_2026_70.uTEtTAxq.webp": {
    "type": "image/webp",
    "etag": "\"115bfc-BIdb+VoxwjGl6q0I9IdnNXBgIFA\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1137660,
    "path": "../public/_nuxt/roma_2026_70.uTEtTAxq.webp"
  },
  "/_nuxt/Rouo2hS_.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"70-O+2GN7lxBKsns+OQSBrsrqRk/Sg\"",
    "mtime": "2026-05-26T18:57:58.710Z",
    "size": 112,
    "path": "../public/_nuxt/Rouo2hS_.js"
  },
  "/_nuxt/RZ1OXgw9.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-tsXvXIPGGWGfttA/6AAr2Zd0EGQ\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 119,
    "path": "../public/_nuxt/RZ1OXgw9.js"
  },
  "/_nuxt/sCXzH78g.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"1818-PEWqcCOSc2m89FIAyOlUdtkcEzI\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 6168,
    "path": "../public/_nuxt/sCXzH78g.js"
  },
  "/_nuxt/roma_2026_leica_13.Db8MPmQI.webp": {
    "type": "image/webp",
    "etag": "\"23da60-9spcCLAvzxf2j0otqMeev1rYkO0\"",
    "mtime": "2026-05-26T18:57:58.746Z",
    "size": 2349664,
    "path": "../public/_nuxt/roma_2026_leica_13.Db8MPmQI.webp"
  },
  "/_nuxt/roma_2026_leica_17.2M_smFku.webp": {
    "type": "image/webp",
    "etag": "\"229382-Aqy6Mp9uT96FB9nakEvKIgbi09k\"",
    "mtime": "2026-05-26T18:57:58.746Z",
    "size": 2265986,
    "path": "../public/_nuxt/roma_2026_leica_17.2M_smFku.webp"
  },
  "/_nuxt/roma_2026_leica_46.4o00CC1v.webp": {
    "type": "image/webp",
    "etag": "\"1dd1b2-Z4QqAuU42WiOx8xHuLro7hoTJ2g\"",
    "mtime": "2026-05-26T18:57:58.744Z",
    "size": 1954226,
    "path": "../public/_nuxt/roma_2026_leica_46.4o00CC1v.webp"
  },
  "/_nuxt/roma_2026_leica_56.G-PvJM2T.webp": {
    "type": "image/webp",
    "etag": "\"1f6068-wP4OAip6tF72eB0j/H1XVHSMNW4\"",
    "mtime": "2026-05-26T18:57:58.744Z",
    "size": 2056296,
    "path": "../public/_nuxt/roma_2026_leica_56.G-PvJM2T.webp"
  },
  "/_nuxt/roma_2026_leica_45.DxM-iI1N.webp": {
    "type": "image/webp",
    "etag": "\"201458-71mhhHpmNFDTQHonKKLGXMWLsb8\"",
    "mtime": "2026-05-26T18:57:58.746Z",
    "size": 2102360,
    "path": "../public/_nuxt/roma_2026_leica_45.DxM-iI1N.webp"
  },
  "/_nuxt/sfilata_nicolaci_120.Dlhf64ik.webp": {
    "type": "image/webp",
    "etag": "\"efed2-yxo6yWU6X4TZelyvvo3n3XCwPEA\"",
    "mtime": "2026-05-26T18:57:58.718Z",
    "size": 982738,
    "path": "../public/_nuxt/sfilata_nicolaci_120.Dlhf64ik.webp"
  },
  "/_nuxt/sfilata_nicolaci_160.vFT6QUtG.webp": {
    "type": "image/webp",
    "etag": "\"7665a-gyOGNOK2sAezZ3bEXL4Z7AFbDG8\"",
    "mtime": "2026-05-26T18:57:58.693Z",
    "size": 484954,
    "path": "../public/_nuxt/sfilata_nicolaci_160.vFT6QUtG.webp"
  },
  "/_nuxt/sfilata_nicolaci_127.V5i4dRCg.webp": {
    "type": "image/webp",
    "etag": "\"9963c-kZbObSmnxdWfP17Zvz4hubW4q6M\"",
    "mtime": "2026-05-26T18:57:58.718Z",
    "size": 628284,
    "path": "../public/_nuxt/sfilata_nicolaci_127.V5i4dRCg.webp"
  },
  "/_nuxt/sfilata_nicolaci_122.B2deuTkR.webp": {
    "type": "image/webp",
    "etag": "\"fb5de-HsIoyiZkEpvfo90DaPaW5AhtOQg\"",
    "mtime": "2026-05-26T18:57:58.719Z",
    "size": 1029598,
    "path": "../public/_nuxt/sfilata_nicolaci_122.B2deuTkR.webp"
  },
  "/_nuxt/sfilata_nicolaci_128.BB52RsRg.webp": {
    "type": "image/webp",
    "etag": "\"a3f04-FagQrAN8uQnCYEpi0qjeEVbL/cY\"",
    "mtime": "2026-05-26T18:57:58.719Z",
    "size": 671492,
    "path": "../public/_nuxt/sfilata_nicolaci_128.BB52RsRg.webp"
  },
  "/_nuxt/sfilata_nicolaci_190.x2wEMYQl.webp": {
    "type": "image/webp",
    "etag": "\"7f7a2-sihIYI48UEtXubN0AYASyFlfMyY\"",
    "mtime": "2026-05-26T18:57:58.693Z",
    "size": 522146,
    "path": "../public/_nuxt/sfilata_nicolaci_190.x2wEMYQl.webp"
  },
  "/_nuxt/roma_2026_leica_7.B85hvzs4.webp": {
    "type": "image/webp",
    "etag": "\"1fc5ca-E117FHxuXmPBADRjZc1DT4Au9xY\"",
    "mtime": "2026-05-26T18:57:58.744Z",
    "size": 2082250,
    "path": "../public/_nuxt/roma_2026_leica_7.B85hvzs4.webp"
  },
  "/_nuxt/roma_2026_leica_47.QaReoAWo.webp": {
    "type": "image/webp",
    "etag": "\"215aa2-09bZAIKhd6JrTSo3UQ9sACFRTr8\"",
    "mtime": "2026-05-26T18:57:58.746Z",
    "size": 2185890,
    "path": "../public/_nuxt/roma_2026_leica_47.QaReoAWo.webp"
  },
  "/_nuxt/sfilata_nicolaci_147.ClaPw8e1.webp": {
    "type": "image/webp",
    "etag": "\"ea9a6-ERSBMEGqlazJbgc2ZhaowJMu0yA\"",
    "mtime": "2026-05-26T18:57:58.719Z",
    "size": 960934,
    "path": "../public/_nuxt/sfilata_nicolaci_147.ClaPw8e1.webp"
  },
  "/_nuxt/roma_2026_leica_81.bD9sasTt.webp": {
    "type": "image/webp",
    "etag": "\"1f63c8-bF2lX88o/15vAYE5HbZ6rh7m5gE\"",
    "mtime": "2026-05-26T18:57:58.745Z",
    "size": 2057160,
    "path": "../public/_nuxt/roma_2026_leica_81.bD9sasTt.webp"
  },
  "/_nuxt/roma_2026_leica_89.a4o9rv8S.webp": {
    "type": "image/webp",
    "etag": "\"1b5010-FNGrFJK8z+SeXAJboSs9Oe4n9as\"",
    "mtime": "2026-05-26T18:57:58.744Z",
    "size": 1789968,
    "path": "../public/_nuxt/roma_2026_leica_89.a4o9rv8S.webp"
  },
  "/_nuxt/sfilata_nicolaci_114.DOeqrRuu.webp": {
    "type": "image/webp",
    "etag": "\"144d54-xnrJhYeD0vuFfp4AkVriJo9Hp30\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1330516,
    "path": "../public/_nuxt/sfilata_nicolaci_114.DOeqrRuu.webp"
  },
  "/_nuxt/sfilata_nicolaci_186.BRwOJNGQ.webp": {
    "type": "image/webp",
    "etag": "\"da15a-qQlMtty6tXi6MN/Iyvsni3BrPHI\"",
    "mtime": "2026-05-26T18:57:58.719Z",
    "size": 893274,
    "path": "../public/_nuxt/sfilata_nicolaci_186.BRwOJNGQ.webp"
  },
  "/_nuxt/sfilata_nicolaci_189.B0wDFMlg.webp": {
    "type": "image/webp",
    "etag": "\"8b786-bCaQWrGX5ZJXVfxldTRGBOu/WNQ\"",
    "mtime": "2026-05-26T18:57:58.719Z",
    "size": 571270,
    "path": "../public/_nuxt/sfilata_nicolaci_189.B0wDFMlg.webp"
  },
  "/_nuxt/sfilata_nicolaci_191.B_RVDZdq.webp": {
    "type": "image/webp",
    "etag": "\"93602-F/X3p8Fj+0QhF3ed+ocVXDnepY0\"",
    "mtime": "2026-05-26T18:57:58.719Z",
    "size": 603650,
    "path": "../public/_nuxt/sfilata_nicolaci_191.B_RVDZdq.webp"
  },
  "/_nuxt/roma_2026_leica_78.a1i2pvtn.webp": {
    "type": "image/webp",
    "etag": "\"21a28c-eSH79C3PjGOaqhuieokTrsIePb0\"",
    "mtime": "2026-05-26T18:57:58.746Z",
    "size": 2204300,
    "path": "../public/_nuxt/roma_2026_leica_78.a1i2pvtn.webp"
  },
  "/_nuxt/sfilata_nicolaci_192._xxNZYFm.webp": {
    "type": "image/webp",
    "etag": "\"9418c-6V4GwE9wVI1Xa6JRukU/D+FBt5s\"",
    "mtime": "2026-05-26T18:57:58.719Z",
    "size": 606604,
    "path": "../public/_nuxt/sfilata_nicolaci_192._xxNZYFm.webp"
  },
  "/_nuxt/sfilata_nicolaci_232.BhHiRJqY.webp": {
    "type": "image/webp",
    "etag": "\"5ce84-aWsRpsocJ1/y05nNHhnKLyk2gtg\"",
    "mtime": "2026-05-26T18:57:58.693Z",
    "size": 380548,
    "path": "../public/_nuxt/sfilata_nicolaci_232.BhHiRJqY.webp"
  },
  "/_nuxt/sfilata_nicolaci_194.DzQHdBeH.webp": {
    "type": "image/webp",
    "etag": "\"90012-oTrk9j/ecABn/ghgEI1RAI4FzsA\"",
    "mtime": "2026-05-26T18:57:58.719Z",
    "size": 589842,
    "path": "../public/_nuxt/sfilata_nicolaci_194.DzQHdBeH.webp"
  },
  "/_nuxt/sfilata_nicolaci_213.CSW4Nj8f.webp": {
    "type": "image/webp",
    "etag": "\"cbd64-TdXcSuwhd/5aqJYvZmeHKsPIv6w\"",
    "mtime": "2026-05-26T18:57:58.719Z",
    "size": 834916,
    "path": "../public/_nuxt/sfilata_nicolaci_213.CSW4Nj8f.webp"
  },
  "/_nuxt/SjU4xgWo.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-4Y60sGdWv/HWm1Pq6uvIzt1JKlE\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 119,
    "path": "../public/_nuxt/SjU4xgWo.js"
  },
  "/_nuxt/sfilata_nicolaci_234.DtpYCZyY.webp": {
    "type": "image/webp",
    "etag": "\"a2230-Qkh48RaJZcIEP9mYbLm9Vu3C3HQ\"",
    "mtime": "2026-05-26T18:57:58.719Z",
    "size": 664112,
    "path": "../public/_nuxt/sfilata_nicolaci_234.DtpYCZyY.webp"
  },
  "/_nuxt/SoXiqEMP.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-1L0hIVYCX8cci3ZyM8haIh00I74\"",
    "mtime": "2026-05-26T18:57:58.711Z",
    "size": 114,
    "path": "../public/_nuxt/SoXiqEMP.js"
  },
  "/_nuxt/sfilata_nicolaci_239.7GtJHO7M.webp": {
    "type": "image/webp",
    "etag": "\"ad39c-uZWk+ETv8ScWYfQOtat+RfeFPVU\"",
    "mtime": "2026-05-26T18:57:58.719Z",
    "size": 709532,
    "path": "../public/_nuxt/sfilata_nicolaci_239.7GtJHO7M.webp"
  },
  "/_nuxt/SYE3OLCZ.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-S3kqEr5yyjyXZNN6zH2ojfC8gfA\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 120,
    "path": "../public/_nuxt/SYE3OLCZ.js"
  },
  "/_nuxt/SZYpcavJ.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-GuBpWOwogzDqICQ2uowtqlW/4eQ\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 119,
    "path": "../public/_nuxt/SZYpcavJ.js"
  },
  "/_nuxt/T0wjQ0r7.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-8sSuk58XDTDxYW9AHFl6y1nC5h4\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 114,
    "path": "../public/_nuxt/T0wjQ0r7.js"
  },
  "/_nuxt/sfilata_nicolaci_246.Drm42JsH.webp": {
    "type": "image/webp",
    "etag": "\"b5944-OR/kI++/4safAAS7QJm18vPKiUo\"",
    "mtime": "2026-05-26T18:57:58.719Z",
    "size": 743748,
    "path": "../public/_nuxt/sfilata_nicolaci_246.Drm42JsH.webp"
  },
  "/_nuxt/sfilata_nicolaci_260.C_z1rVQt.webp": {
    "type": "image/webp",
    "etag": "\"a0608-X7XOBdc91u3YzUgcWDvd2Vh1QaE\"",
    "mtime": "2026-05-26T18:57:58.719Z",
    "size": 656904,
    "path": "../public/_nuxt/sfilata_nicolaci_260.C_z1rVQt.webp"
  },
  "/_nuxt/sfilata_nicolaci_274.BrbyPuq1.webp": {
    "type": "image/webp",
    "etag": "\"cc2d6-oIdmt8Cwisj6/wrBEiBOYmkuVdU\"",
    "mtime": "2026-05-26T18:57:58.719Z",
    "size": 836310,
    "path": "../public/_nuxt/sfilata_nicolaci_274.BrbyPuq1.webp"
  },
  "/_nuxt/sfilata_nicolaci_276.DqCvLTLm.webp": {
    "type": "image/webp",
    "etag": "\"9eaea-BVAhou5TxbdTeWBBt8zACPoLGVU\"",
    "mtime": "2026-05-26T18:57:58.719Z",
    "size": 649962,
    "path": "../public/_nuxt/sfilata_nicolaci_276.DqCvLTLm.webp"
  },
  "/_nuxt/sfilata_nicolaci_31.D4VkjCIl.webp": {
    "type": "image/webp",
    "etag": "\"a8f7a-09OkBMoqJW5KNOND/re2j0p91WY\"",
    "mtime": "2026-05-26T18:57:58.719Z",
    "size": 692090,
    "path": "../public/_nuxt/sfilata_nicolaci_31.D4VkjCIl.webp"
  },
  "/_nuxt/sfilata_nicolaci_32.vL3Utiyu.webp": {
    "type": "image/webp",
    "etag": "\"b7900-esbaFOWRauPTn1hR9SkQfJMX/5I\"",
    "mtime": "2026-05-26T18:57:58.719Z",
    "size": 751872,
    "path": "../public/_nuxt/sfilata_nicolaci_32.vL3Utiyu.webp"
  },
  "/_nuxt/sfilata_nicolaci_40.BwHKhBTh.webp": {
    "type": "image/webp",
    "etag": "\"ab382-1qSftIY/Pdx84N/BfmfDosWtdZY\"",
    "mtime": "2026-05-26T18:57:58.719Z",
    "size": 701314,
    "path": "../public/_nuxt/sfilata_nicolaci_40.BwHKhBTh.webp"
  },
  "/_nuxt/test_canon_c50_120.B5s9q6Fg.webp": {
    "type": "image/webp",
    "etag": "\"6cce2-OVkF14mhKH6UldnNw5sS4c7NU5g\"",
    "mtime": "2026-05-26T18:57:58.695Z",
    "size": 445666,
    "path": "../public/_nuxt/test_canon_c50_120.B5s9q6Fg.webp"
  },
  "/_nuxt/test_canon_c50_121.C6fNpklx.webp": {
    "type": "image/webp",
    "etag": "\"63ae0-ZCQjU14Xy26K7Rwuc+M7fyRRqXE\"",
    "mtime": "2026-05-26T18:57:58.695Z",
    "size": 408288,
    "path": "../public/_nuxt/test_canon_c50_121.C6fNpklx.webp"
  },
  "/_nuxt/test_canon_c50_01.C0ZsDuOk.webp": {
    "type": "image/webp",
    "etag": "\"d9a2e-E9NN9hWHpAqk7XLa4m7pBOLtpJw\"",
    "mtime": "2026-05-26T18:57:58.721Z",
    "size": 891438,
    "path": "../public/_nuxt/test_canon_c50_01.C0ZsDuOk.webp"
  },
  "/_nuxt/test_canon_c50_113.DNshoH5y.webp": {
    "type": "image/webp",
    "etag": "\"c182e-mXC62CAO59SURnZvz/O4ZUew3/g\"",
    "mtime": "2026-05-26T18:57:58.721Z",
    "size": 792622,
    "path": "../public/_nuxt/test_canon_c50_113.DNshoH5y.webp"
  },
  "/_nuxt/test_canon_c50_118.DIwqilZY.webp": {
    "type": "image/webp",
    "etag": "\"85c60-R4+aCXR/UY9aKrV/ShJbrqDFEAU\"",
    "mtime": "2026-05-26T18:57:58.721Z",
    "size": 547936,
    "path": "../public/_nuxt/test_canon_c50_118.DIwqilZY.webp"
  },
  "/_nuxt/test_canon_c50_115.D9niYql2.webp": {
    "type": "image/webp",
    "etag": "\"ad01a-ihEfOCO1WAFzUzdvcLJo+xSOcmw\"",
    "mtime": "2026-05-26T18:57:58.721Z",
    "size": 708634,
    "path": "../public/_nuxt/test_canon_c50_115.D9niYql2.webp"
  },
  "/_nuxt/test_canon_c50_130.COgFJ4mE.webp": {
    "type": "image/webp",
    "etag": "\"7b3e4-GKNE4bUP17MZIWrlhskxFrrzKJI\"",
    "mtime": "2026-05-26T18:57:58.695Z",
    "size": 504804,
    "path": "../public/_nuxt/test_canon_c50_130.COgFJ4mE.webp"
  },
  "/_nuxt/sfilata_nicolaci_242.x8sXiH8k.webp": {
    "type": "image/webp",
    "etag": "\"1cd212-6huVKx1xq0Qg3S1I4bamKayHXrg\"",
    "mtime": "2026-05-26T18:57:58.744Z",
    "size": 1888786,
    "path": "../public/_nuxt/sfilata_nicolaci_242.x8sXiH8k.webp"
  },
  "/_nuxt/test_canon_c50_126.qHKNGLZ7.webp": {
    "type": "image/webp",
    "etag": "\"80dc6-WNfopw7YlarzdPtenHgiv2P4fto\"",
    "mtime": "2026-05-26T18:57:58.721Z",
    "size": 527814,
    "path": "../public/_nuxt/test_canon_c50_126.qHKNGLZ7.webp"
  },
  "/_nuxt/test_canon_c50_134.ow4TJxmN.webp": {
    "type": "image/webp",
    "etag": "\"7b316-TIHbDYiO7t97rXYYzh/qQPULpsE\"",
    "mtime": "2026-05-26T18:57:58.694Z",
    "size": 504598,
    "path": "../public/_nuxt/test_canon_c50_134.ow4TJxmN.webp"
  },
  "/_nuxt/test_canon_c50_22.YwAGJCHf.webp": {
    "type": "image/webp",
    "etag": "\"66bca-mett2a23x9ggLFkI8E3WUy0mDQU\"",
    "mtime": "2026-05-26T18:57:58.695Z",
    "size": 420810,
    "path": "../public/_nuxt/test_canon_c50_22.YwAGJCHf.webp"
  },
  "/_nuxt/test_canon_c50_135.kRQo5jjZ.webp": {
    "type": "image/webp",
    "etag": "\"91400-TQ9bfCyrsDT/pQS06Vb+1BOKkK0\"",
    "mtime": "2026-05-26T18:57:58.721Z",
    "size": 594944,
    "path": "../public/_nuxt/test_canon_c50_135.kRQo5jjZ.webp"
  },
  "/_nuxt/test_canon_c50_89.CCDxfWSk.webp": {
    "type": "image/webp",
    "etag": "\"59906-px8XU4FY7f3VJIl6owsFX1PPgiU\"",
    "mtime": "2026-05-26T18:57:58.695Z",
    "size": 366854,
    "path": "../public/_nuxt/test_canon_c50_89.CCDxfWSk.webp"
  },
  "/_nuxt/test_canon_c50_93.C5YUiFaW.webp": {
    "type": "image/webp",
    "etag": "\"7530a-JW/yNQVqPOj+6S7lNYyrgRixVoQ\"",
    "mtime": "2026-05-26T18:57:58.695Z",
    "size": 480010,
    "path": "../public/_nuxt/test_canon_c50_93.C5YUiFaW.webp"
  },
  "/_nuxt/tjgRd-o7.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-ro1CZ4NMrUOCqHJYLIcQTIEhF+g\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 119,
    "path": "../public/_nuxt/tjgRd-o7.js"
  },
  "/_nuxt/test_canon_c50_95.DjMXSu4C.webp": {
    "type": "image/webp",
    "etag": "\"7bfba-bPhHB+xNZ7dleFTdyLWwG4wBeN0\"",
    "mtime": "2026-05-26T18:57:58.695Z",
    "size": 507834,
    "path": "../public/_nuxt/test_canon_c50_95.DjMXSu4C.webp"
  },
  "/_nuxt/u6q8A0OX.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-fxFcVFNYFtYLBQ33MomNEinvFbI\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 120,
    "path": "../public/_nuxt/u6q8A0OX.js"
  },
  "/_nuxt/test_canon_c50_36.BNWm0OVV.webp": {
    "type": "image/webp",
    "etag": "\"809d2-Di5NsnMibQEGORdih/vhkmcZwtA\"",
    "mtime": "2026-05-26T18:57:58.721Z",
    "size": 526802,
    "path": "../public/_nuxt/test_canon_c50_36.BNWm0OVV.webp"
  },
  "/_nuxt/test_canon_c50_26.BXF7leY7.webp": {
    "type": "image/webp",
    "etag": "\"8f874-pcj/tIfDNN4Gz6zttKv0qznymG0\"",
    "mtime": "2026-05-26T18:57:58.721Z",
    "size": 587892,
    "path": "../public/_nuxt/test_canon_c50_26.BXF7leY7.webp"
  },
  "/_nuxt/test_canon_c50_37.71d8QbOy.webp": {
    "type": "image/webp",
    "etag": "\"91764-HLuoXLGMUhxvQVjhpVS5aKTDKPM\"",
    "mtime": "2026-05-26T18:57:58.721Z",
    "size": 595812,
    "path": "../public/_nuxt/test_canon_c50_37.71d8QbOy.webp"
  },
  "/_nuxt/test_canon_c50_43.DOXFdBpp.webp": {
    "type": "image/webp",
    "etag": "\"85880-XHykGS5aMJEtIKzoJIFKKN6d1U0\"",
    "mtime": "2026-05-26T18:57:58.721Z",
    "size": 546944,
    "path": "../public/_nuxt/test_canon_c50_43.DOXFdBpp.webp"
  },
  "/_nuxt/Uaiyl8gR.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-4gCSGHo/jXLelB6sqtkeQvdhM/M\"",
    "mtime": "2026-05-26T18:57:58.715Z",
    "size": 115,
    "path": "../public/_nuxt/Uaiyl8gR.js"
  },
  "/_nuxt/test_canon_c50_60.CxHb1jwa.webp": {
    "type": "image/webp",
    "etag": "\"d4d24-SWWn/w6bqijE3tcicxDZ92KJSs8\"",
    "mtime": "2026-05-26T18:57:58.721Z",
    "size": 871716,
    "path": "../public/_nuxt/test_canon_c50_60.CxHb1jwa.webp"
  },
  "/_nuxt/test_canon_c50_76.DfXCWcyr.webp": {
    "type": "image/webp",
    "etag": "\"9229c-P7H5M6Zx0Ha6460TWd9xE9rMZYU\"",
    "mtime": "2026-05-26T18:57:58.721Z",
    "size": 598684,
    "path": "../public/_nuxt/test_canon_c50_76.DfXCWcyr.webp"
  },
  "/_nuxt/UavujfXj.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-69IMl1kZz7WOaNZIt5vUw4vL9MY\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 119,
    "path": "../public/_nuxt/UavujfXj.js"
  },
  "/_nuxt/test_canon_c50_79.qgonCJSv.webp": {
    "type": "image/webp",
    "etag": "\"a23f6-JyhuHVBx81YlD2/eZQ+tJk4/V68\"",
    "mtime": "2026-05-26T18:57:58.721Z",
    "size": 664566,
    "path": "../public/_nuxt/test_canon_c50_79.qgonCJSv.webp"
  },
  "/_nuxt/uViZ15Zq.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-dDDw5LLz36PTCAz5Mh5R+G2B2yY\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 122,
    "path": "../public/_nuxt/uViZ15Zq.js"
  },
  "/_nuxt/v2UAOo1b.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"76-+pUqNn1RdMIC39o2tyqXi+3SyVw\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 118,
    "path": "../public/_nuxt/v2UAOo1b.js"
  },
  "/_nuxt/test_canon_c50_46.BXb7U_V3.webp": {
    "type": "image/webp",
    "etag": "\"10e000-Z2nprXbdQX17ETUtM/yLgG18SAg\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1105920,
    "path": "../public/_nuxt/test_canon_c50_46.BXb7U_V3.webp"
  },
  "/_nuxt/VFXShootingDay-11.BRjBu4Vp.webp": {
    "type": "image/webp",
    "etag": "\"d20cc-HzbKtuvIeuoG3yZVfUNtoUnzmR4\"",
    "mtime": "2026-05-26T18:57:58.724Z",
    "size": 860364,
    "path": "../public/_nuxt/VFXShootingDay-11.BRjBu4Vp.webp"
  },
  "/_nuxt/VFXShootingDay-12.DSxQv7oW.webp": {
    "type": "image/webp",
    "etag": "\"f20d0-+PclaFDjDG+aJ4PlyAvNxAPivoc\"",
    "mtime": "2026-05-26T18:57:58.724Z",
    "size": 991440,
    "path": "../public/_nuxt/VFXShootingDay-12.DSxQv7oW.webp"
  },
  "/_nuxt/VFXShootingDay-15.CovekTET.webp": {
    "type": "image/webp",
    "etag": "\"7970c-g+nA9U0HNXzb8hGi8q9BcFZM1zU\"",
    "mtime": "2026-05-26T18:57:58.696Z",
    "size": 497420,
    "path": "../public/_nuxt/VFXShootingDay-15.CovekTET.webp"
  },
  "/_nuxt/VFXShootingDay-1.PjESjBGJ.webp": {
    "type": "image/webp",
    "etag": "\"15e5e8-QjU6Sow78cCCVkpKvT1KPjGO36w\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1435112,
    "path": "../public/_nuxt/VFXShootingDay-1.PjESjBGJ.webp"
  },
  "/_nuxt/VFXShootingDay-10.CvsNyrxI.webp": {
    "type": "image/webp",
    "etag": "\"110d24-3oOwZysr64EGDTX5XPDWH5hKfQY\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1117476,
    "path": "../public/_nuxt/VFXShootingDay-10.CvsNyrxI.webp"
  },
  "/_nuxt/VFXShootingDay-13.DOz3JTW2.webp": {
    "type": "image/webp",
    "etag": "\"11fd7e-9cqeIi+nNx0tOTGDGjibLpFkrBs\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1179006,
    "path": "../public/_nuxt/VFXShootingDay-13.DOz3JTW2.webp"
  },
  "/_nuxt/TutaRossa-Prep.DCFxjJrc.mp4": {
    "type": "video/mp4",
    "etag": "\"206ea8-xqesk2XMID5wxPnDchVrojQH+Uw\"",
    "mtime": "2026-05-26T18:57:58.746Z",
    "size": 2125480,
    "path": "../public/_nuxt/TutaRossa-Prep.DCFxjJrc.mp4"
  },
  "/_nuxt/VFXShootingDay-16.D_K85eNd.webp": {
    "type": "image/webp",
    "etag": "\"cc71c-JI0TTe5uSkLr95VgpLzKHQL4Dtk\"",
    "mtime": "2026-05-26T18:57:58.724Z",
    "size": 837404,
    "path": "../public/_nuxt/VFXShootingDay-16.D_K85eNd.webp"
  },
  "/_nuxt/VFXShootingDay-18.k4sEr8Ys.webp": {
    "type": "image/webp",
    "etag": "\"c2a6e-CO3PFNMzo7RJZx4EOWpfEJfZABE\"",
    "mtime": "2026-05-26T18:57:58.724Z",
    "size": 797294,
    "path": "../public/_nuxt/VFXShootingDay-18.k4sEr8Ys.webp"
  },
  "/_nuxt/VFXShootingDay-19.RbbdSI5C.webp": {
    "type": "image/webp",
    "etag": "\"d1004-UUix6a7zzmHVsKxl9coXvw+bags\"",
    "mtime": "2026-05-26T18:57:58.724Z",
    "size": 856068,
    "path": "../public/_nuxt/VFXShootingDay-19.RbbdSI5C.webp"
  },
  "/_nuxt/VFXShootingDay-2.fyY2imTK.webp": {
    "type": "image/webp",
    "etag": "\"e4f0c-ZRRQfrqosFJY/xH13NDYWl8BvE0\"",
    "mtime": "2026-05-26T18:57:58.724Z",
    "size": 937740,
    "path": "../public/_nuxt/VFXShootingDay-2.fyY2imTK.webp"
  },
  "/_nuxt/VFXShootingDay-22.CcRT2tYQ.webp": {
    "type": "image/webp",
    "etag": "\"c3b18-nK7+CRpcEl02eeRPj1ZGvJ6LrCw\"",
    "mtime": "2026-05-26T18:57:58.725Z",
    "size": 801560,
    "path": "../public/_nuxt/VFXShootingDay-22.CcRT2tYQ.webp"
  },
  "/_nuxt/VFXShootingDay-21.BLfRmdUi.webp": {
    "type": "image/webp",
    "etag": "\"d5194-tJVWtYNf+wXrscZMFvfhxRwcDZs\"",
    "mtime": "2026-05-26T18:57:58.724Z",
    "size": 872852,
    "path": "../public/_nuxt/VFXShootingDay-21.BLfRmdUi.webp"
  },
  "/_nuxt/VFXShootingDay-20.C6oD6UT8.webp": {
    "type": "image/webp",
    "etag": "\"d3caa-esuSEq/XbiWz11VLbSdHGzCYzic\"",
    "mtime": "2026-05-26T18:57:58.724Z",
    "size": 867498,
    "path": "../public/_nuxt/VFXShootingDay-20.C6oD6UT8.webp"
  },
  "/_nuxt/VFXShootingDay-25.CmZIBoy1.webp": {
    "type": "image/webp",
    "etag": "\"ed506-IP0bEFZvi8yZD/vvFeau10IliJI\"",
    "mtime": "2026-05-26T18:57:58.725Z",
    "size": 972038,
    "path": "../public/_nuxt/VFXShootingDay-25.CmZIBoy1.webp"
  },
  "/_nuxt/VFXShootingDay-27.Cv5eHU04.webp": {
    "type": "image/webp",
    "etag": "\"bd06c-pho62zOiZt1Rkyo0wHsMHXkF0Pg\"",
    "mtime": "2026-05-26T18:57:58.724Z",
    "size": 774252,
    "path": "../public/_nuxt/VFXShootingDay-27.Cv5eHU04.webp"
  },
  "/_nuxt/VFXShootingDay-26.B0FgBgij.webp": {
    "type": "image/webp",
    "etag": "\"f4fa6-dWK4Jzubr24Tih7DP40zeHYicTc\"",
    "mtime": "2026-05-26T18:57:58.725Z",
    "size": 1003430,
    "path": "../public/_nuxt/VFXShootingDay-26.B0FgBgij.webp"
  },
  "/_nuxt/VFXShootingDay-30.C5TrwONA.webp": {
    "type": "image/webp",
    "etag": "\"d239a-Yl4iKi3oO7C6SOYB65HFCgy9Z9Y\"",
    "mtime": "2026-05-26T18:57:58.725Z",
    "size": 861082,
    "path": "../public/_nuxt/VFXShootingDay-30.C5TrwONA.webp"
  },
  "/_nuxt/VFXShootingDay-17.D07c8kaZ.webp": {
    "type": "image/webp",
    "etag": "\"12ac68-K52d3V9b4QjvalQNnc5TrY+y+tw\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1223784,
    "path": "../public/_nuxt/VFXShootingDay-17.D07c8kaZ.webp"
  },
  "/_nuxt/VFXShootingDay-23.Eh_3CiNc.webp": {
    "type": "image/webp",
    "etag": "\"11a106-7WdL7xOlbpWddhS8LwE2OrydaeA\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1155334,
    "path": "../public/_nuxt/VFXShootingDay-23.Eh_3CiNc.webp"
  },
  "/_nuxt/VFXShootingDay-24.DzjMkhTS.webp": {
    "type": "image/webp",
    "etag": "\"12be24-ebhHas4odEkLXDnTjlGXEfu0cn0\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1228324,
    "path": "../public/_nuxt/VFXShootingDay-24.DzjMkhTS.webp"
  },
  "/_nuxt/VFXShootingDay-28.CEkfSUqf.webp": {
    "type": "image/webp",
    "etag": "\"144630-ly6EjeBziYFtVsVEQr3nsPqWHvo\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1328688,
    "path": "../public/_nuxt/VFXShootingDay-28.CEkfSUqf.webp"
  },
  "/_nuxt/VFXShootingDay-29.DTgDc45H.webp": {
    "type": "image/webp",
    "etag": "\"100898-OEJsx6xzASBMCltQT0JriJw3dNI\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1050776,
    "path": "../public/_nuxt/VFXShootingDay-29.DTgDc45H.webp"
  },
  "/_nuxt/VFXShootingDay-3.9YcJ1MkE.webp": {
    "type": "image/webp",
    "etag": "\"116080-+v9tnVvmZnQulwPrjTY7EtiBtw8\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1138816,
    "path": "../public/_nuxt/VFXShootingDay-3.9YcJ1MkE.webp"
  },
  "/_nuxt/VFXShootingDay-4.9HEi4_Q2.webp": {
    "type": "image/webp",
    "etag": "\"17dd44-TzbMmLIl0vNfeauFTppE33ubQzI\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1563972,
    "path": "../public/_nuxt/VFXShootingDay-4.9HEi4_Q2.webp"
  },
  "/_nuxt/VFXShootingDay-8.1kg-EQa_.webp": {
    "type": "image/webp",
    "etag": "\"b5096-5yX+0Yk29uSeILyAyEB1p3h1sek\"",
    "mtime": "2026-05-26T18:57:58.725Z",
    "size": 741526,
    "path": "../public/_nuxt/VFXShootingDay-8.1kg-EQa_.webp"
  },
  "/_nuxt/VFXShootingDay-9.COQvSK8L.webp": {
    "type": "image/webp",
    "etag": "\"c8814-6Lce9BRGhIZ2d/J7K8JQdAmJOVc\"",
    "mtime": "2026-05-26T18:57:58.725Z",
    "size": 821268,
    "path": "../public/_nuxt/VFXShootingDay-9.COQvSK8L.webp"
  },
  "/_nuxt/VFXShootingDay-5.WhFM-Q94.webp": {
    "type": "image/webp",
    "etag": "\"10041e-P3YMtC4qRCT+W7s1a11dmx/uJtY\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1049630,
    "path": "../public/_nuxt/VFXShootingDay-5.WhFM-Q94.webp"
  },
  "/_nuxt/WC1LyMHw.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-vTLYfsTckaFiwBVww+eToMTFBLI\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 114,
    "path": "../public/_nuxt/WC1LyMHw.js"
  },
  "/_nuxt/VFXShootingDay-6.wLQ4xTAU.webp": {
    "type": "image/webp",
    "etag": "\"12c554-BQAkyiH3/cE9dW95f/mFY/2D3oM\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1230164,
    "path": "../public/_nuxt/VFXShootingDay-6.wLQ4xTAU.webp"
  },
  "/_nuxt/WyqX6iZK.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-S3kqEr5yyjyXZNN6zH2ojfC8gfA\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 120,
    "path": "../public/_nuxt/WyqX6iZK.js"
  },
  "/_nuxt/VFXShootingDay-7.C4CdfrwP.webp": {
    "type": "image/webp",
    "etag": "\"14d076-TOClymiNaQY6QipgRM7znU5tqmo\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1364086,
    "path": "../public/_nuxt/VFXShootingDay-7.C4CdfrwP.webp"
  },
  "/_nuxt/xGi1kqec.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-Id8SDVNlt3mePvWZ5PXCt0dta7M\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 119,
    "path": "../public/_nuxt/xGi1kqec.js"
  },
  "/_nuxt/xoRqeaUM.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"74-7A6fcsD5lemFipaLIjlwyAXnMhs\"",
    "mtime": "2026-05-26T18:57:58.712Z",
    "size": 116,
    "path": "../public/_nuxt/xoRqeaUM.js"
  },
  "/_nuxt/xQJmBfWH.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-6F9aTEqc1dqeIBTfU2Ogze4CHW4\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 107,
    "path": "../public/_nuxt/xQJmBfWH.js"
  },
  "/_nuxt/VFX_03.DrPXr-KH.webp": {
    "type": "image/webp",
    "etag": "\"e42ec-TKrvjSAviaomKdH3yJhh5nxD0K8\"",
    "mtime": "2026-05-26T18:57:58.721Z",
    "size": 934636,
    "path": "../public/_nuxt/VFX_03.DrPXr-KH.webp"
  },
  "/_nuxt/zgzi-Vvh.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"76-V/7PiKPFEi/u+iYQQ8HrNWMiW1U\"",
    "mtime": "2026-05-26T18:57:58.711Z",
    "size": 118,
    "path": "../public/_nuxt/zgzi-Vvh.js"
  },
  "/_nuxt/ZLX5joTt.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-CbbAo4SUwLmu6eCR9HdbgWc7wtI\"",
    "mtime": "2026-05-26T18:57:58.713Z",
    "size": 119,
    "path": "../public/_nuxt/ZLX5joTt.js"
  },
  "/_nuxt/zsh-JC9q.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-WG6677eXfF6iKMO+fJz8jeFSm+4\"",
    "mtime": "2026-05-26T18:57:58.709Z",
    "size": 107,
    "path": "../public/_nuxt/zsh-JC9q.js"
  },
  "/_nuxt/_i6GYrzA.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-fpR/z0++ckUIFuMTats0xgj+J+w\"",
    "mtime": "2026-05-26T18:57:58.716Z",
    "size": 119,
    "path": "../public/_nuxt/_i6GYrzA.js"
  },
  "/_nuxt/_zdmWS4W.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-KeZEVcqBtfmQldApaWgrdhs38Fo\"",
    "mtime": "2026-05-26T18:57:58.716Z",
    "size": 120,
    "path": "../public/_nuxt/_zdmWS4W.js"
  },
  "/_nuxt/VFX_02.Blh7y_ny.webp": {
    "type": "image/webp",
    "etag": "\"17799e-ldP5mF2Mu31n/lyJQ/p6mY8OAP4\"",
    "mtime": "2026-05-26T18:57:58.740Z",
    "size": 1538462,
    "path": "../public/_nuxt/VFX_02.Blh7y_ny.webp"
  },
  "/projects/Cars/02_03.webp": {
    "type": "image/webp",
    "etag": "\"762c6-SnXNZX0xmFIddCUQ8+OJWCa75Yo\"",
    "mtime": "2026-05-05T19:34:15.402Z",
    "size": 484038,
    "path": "../public/projects/Cars/02_03.webp"
  },
  "/_nuxt/VFX_01.Dfz1bpQ8.webp": {
    "type": "image/webp",
    "etag": "\"18713a-2mCdtqFDX3ni7LDjFJ4qGD/J1s0\"",
    "mtime": "2026-05-26T18:57:58.744Z",
    "size": 1601850,
    "path": "../public/_nuxt/VFX_01.Dfz1bpQ8.webp"
  },
  "/projects/Cars/02_020.webp": {
    "type": "image/webp",
    "etag": "\"b2d88-hjOCm4h7XCQZTljyJPsRjDxd8y0\"",
    "mtime": "2026-05-05T19:34:15.383Z",
    "size": 732552,
    "path": "../public/projects/Cars/02_020.webp"
  },
  "/projects/Cars/02_021.webp": {
    "type": "image/webp",
    "etag": "\"f76ba-pudWbTKN117ATKvqIsPG35otg8s\"",
    "mtime": "2026-05-05T19:34:15.396Z",
    "size": 1013434,
    "path": "../public/projects/Cars/02_021.webp"
  },
  "/projects/Cars/02_01.webp": {
    "type": "image/webp",
    "etag": "\"16c9fa-q+HrLy/Q2RIaDV1BQebItuFcuqM\"",
    "mtime": "2026-05-05T19:34:15.360Z",
    "size": 1493498,
    "path": "../public/projects/Cars/02_01.webp"
  },
  "/projects/Cars/CAR7.webp": {
    "type": "image/webp",
    "etag": "\"69338-ND42OkRkYFIirLw4Y5ayu5zFWWI\"",
    "mtime": "2026-05-05T19:34:15.460Z",
    "size": 430904,
    "path": "../public/projects/Cars/CAR7.webp"
  },
  "/projects/Cars/PANA9339.webp": {
    "type": "image/webp",
    "etag": "\"36858-PFx93h4yEZD3FY4ucbXyMqwR+YA\"",
    "mtime": "2026-05-05T19:34:15.464Z",
    "size": 223320,
    "path": "../public/projects/Cars/PANA9339.webp"
  },
  "/projects/Cars/PANA9342.webp": {
    "type": "image/webp",
    "etag": "\"24f5c-GhOTYIjWru0QU7BJ8iBS+T13Ti0\"",
    "mtime": "2026-05-05T19:34:15.471Z",
    "size": 151388,
    "path": "../public/projects/Cars/PANA9342.webp"
  },
  "/projects/Cars/PANA9347.webp": {
    "type": "image/webp",
    "etag": "\"32b22-abPIR6H/JmVwtyEP6NWMRb3hHTo\"",
    "mtime": "2026-05-05T19:34:15.477Z",
    "size": 207650,
    "path": "../public/projects/Cars/PANA9347.webp"
  },
  "/projects/Cars/project.json": {
    "type": "application/json",
    "etag": "\"48-UOz3SwzchSTeITBz/yMpdZcyYro\"",
    "mtime": "2026-05-25T17:39:23.595Z",
    "size": 72,
    "path": "../public/projects/Cars/project.json"
  },
  "/projects/Cars/PANA9348.webp": {
    "type": "image/webp",
    "etag": "\"6f35e-mmXRkiWKu2/sandPhhsIO+MthEk\"",
    "mtime": "2026-05-05T19:34:15.484Z",
    "size": 455518,
    "path": "../public/projects/Cars/PANA9348.webp"
  },
  "/projects/Cars/02_06.webp": {
    "type": "image/webp",
    "etag": "\"deabc-zbeXmwtpwWbRVHtAPfRl+WBZ7XI\"",
    "mtime": "2026-05-05T19:34:15.433Z",
    "size": 912060,
    "path": "../public/projects/Cars/02_06.webp"
  },
  "/projects/Cars/02_04.webp": {
    "type": "image/webp",
    "etag": "\"1036a4-kfI6p0NDgWLNgtV2QKDdXQNUziE\"",
    "mtime": "2026-05-05T19:34:15.414Z",
    "size": 1062564,
    "path": "../public/projects/Cars/02_04.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/project.json": {
    "type": "application/json",
    "etag": "\"5b-30Jg0ZiuWuHzqZVp+dveQrzhPRA\"",
    "mtime": "2026-05-26T18:11:28.391Z",
    "size": 91,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/project.json"
  },
  "/projects/Cars/CAR1.webp": {
    "type": "image/webp",
    "etag": "\"98c4a-xjLnLoJSThu5Fh2U4ODy+vCryZY\"",
    "mtime": "2026-05-05T19:34:15.443Z",
    "size": 625738,
    "path": "../public/projects/Cars/CAR1.webp"
  },
  "/projects/Cars/02_02.webp": {
    "type": "image/webp",
    "etag": "\"184bcc-H87O+loBNIoJJiWnBZUxMGR+xGA\"",
    "mtime": "2026-05-05T19:34:15.375Z",
    "size": 1592268,
    "path": "../public/projects/Cars/02_02.webp"
  },
  "/projects/Cars/CAR11.webp": {
    "type": "image/webp",
    "etag": "\"fd6ac-LF9e40X8/r1XU6MTVnktGF2pDt4\"",
    "mtime": "2026-05-05T19:34:15.454Z",
    "size": 1037996,
    "path": "../public/projects/Cars/CAR11.webp"
  },
  "/projects/Cars/02_05.webp": {
    "type": "image/webp",
    "etag": "\"100362-VH5l5OJBQFDoiVIPKtklirNgFc8\"",
    "mtime": "2026-05-05T19:34:15.425Z",
    "size": 1049442,
    "path": "../public/projects/Cars/02_05.webp"
  },
  "/projects/Fragile/project.json": {
    "type": "application/json",
    "etag": "\"399-6huJIzbBsG8sr1Ch1CBdzZmplxk\"",
    "mtime": "2026-05-04T18:43:23.275Z",
    "size": 921,
    "path": "../public/projects/Fragile/project.json"
  },
  "/projects/Cars/RANDOM4.webp": {
    "type": "image/webp",
    "etag": "\"e9b7e-vQSdFeKiy/RXJ3ko04jhEE/r15M\"",
    "mtime": "2026-05-05T19:34:15.509Z",
    "size": 957310,
    "path": "../public/projects/Cars/RANDOM4.webp"
  },
  "/projects/Fragile/cover.jpg": {
    "type": "image/jpeg",
    "etag": "\"8df29-7BOY6jpgQSHNavDfldMtB7HttJA\"",
    "mtime": "2026-05-04T13:11:33.709Z",
    "size": 581417,
    "path": "../public/projects/Fragile/cover.jpg"
  },
  "/projects/Fiat 600/convert_resize.sh": {
    "type": "application/x-sh",
    "etag": "\"2e4-d05HonIMrBa+cscCW4elPqeRF5c\"",
    "mtime": "2026-05-05T19:34:15.733Z",
    "size": 740,
    "path": "../public/projects/Fiat 600/convert_resize.sh"
  },
  "/projects/Fiat 600/PANA9392.webp": {
    "type": "image/webp",
    "etag": "\"54bda-eCBCSEH9Eyu8QO9ewMuHu1Hghhc\"",
    "mtime": "2026-05-05T19:34:15.669Z",
    "size": 347098,
    "path": "../public/projects/Fiat 600/PANA9392.webp"
  },
  "/projects/Cars/RANDOM19.webp": {
    "type": "image/webp",
    "etag": "\"17e62a-0/N7T2hLK6wv9/UMrFjdfoIsLkc\"",
    "mtime": "2026-05-05T19:34:15.499Z",
    "size": 1566250,
    "path": "../public/projects/Cars/RANDOM19.webp"
  },
  "/projects/Fiat 600/PANA9395.webp": {
    "type": "image/webp",
    "etag": "\"2fc90-Ypzjx7PrOK7QXfG60HEjyN83MYI\"",
    "mtime": "2026-05-05T19:34:15.676Z",
    "size": 195728,
    "path": "../public/projects/Fiat 600/PANA9395.webp"
  },
  "/projects/Fiat 600/PANA9397.webp": {
    "type": "image/webp",
    "etag": "\"44022-bGK5rATGWws4+dKSjabIpgBRrIE\"",
    "mtime": "2026-05-05T19:34:15.681Z",
    "size": 278562,
    "path": "../public/projects/Fiat 600/PANA9397.webp"
  },
  "/projects/Fragile/cover.mp4": {
    "type": "video/mp4",
    "etag": "\"1664b4-XUvsbLH+9TKo2Iil5Oz96EDmHeM\"",
    "mtime": "2026-05-04T21:30:20.513Z",
    "size": 1467572,
    "path": "../public/projects/Fragile/cover.mp4"
  },
  "/projects/Fiat 600/PANA9401.webp": {
    "type": "image/webp",
    "etag": "\"4fb84-NGaAO3V9OrwMY56xjoLB1MKYNJY\"",
    "mtime": "2026-05-05T19:34:15.687Z",
    "size": 326532,
    "path": "../public/projects/Fiat 600/PANA9401.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/cover.webp": {
    "type": "image/webp",
    "etag": "\"1dc830-I9bRpmxeCB3Ce5rbS5h3yqfMirI\"",
    "mtime": "2026-05-26T18:10:43.017Z",
    "size": 1951792,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/cover.webp"
  },
  "/projects/Fiat 600/PANA9403.webp": {
    "type": "image/webp",
    "etag": "\"6610c-OtHDksgp37lmIVi2TlgADrjZOQ8\"",
    "mtime": "2026-05-05T19:34:15.694Z",
    "size": 418060,
    "path": "../public/projects/Fiat 600/PANA9403.webp"
  },
  "/projects/Fiat 600/PANA9412.webp": {
    "type": "image/webp",
    "etag": "\"37d42-QFUk9zSoDDzcqX/9lgduJeLSZR0\"",
    "mtime": "2026-05-05T19:34:15.727Z",
    "size": 228674,
    "path": "../public/projects/Fiat 600/PANA9412.webp"
  },
  "/projects/Fiat 600/project.json": {
    "type": "application/json",
    "etag": "\"4c-AGaJ5oIe4yASBOWIGHGtjEnjROw\"",
    "mtime": "2026-05-25T17:39:23.596Z",
    "size": 76,
    "path": "../public/projects/Fiat 600/project.json"
  },
  "/projects/Freudenberg-Renders/cover.webp": {
    "type": "image/webp",
    "etag": "\"6cb84-2Tjl9hRdZ1AbD51LSZGeMAhL3+4\"",
    "mtime": "2026-05-03T22:36:41.689Z",
    "size": 445316,
    "path": "../public/projects/Freudenberg-Renders/cover.webp"
  },
  "/projects/Freudenberg-Renders/project.json": {
    "type": "application/json",
    "etag": "\"218-IgJp33fwCe2uZ3YWHt2HmmtoYUc\"",
    "mtime": "2026-05-05T23:17:29.234Z",
    "size": 536,
    "path": "../public/projects/Freudenberg-Renders/project.json"
  },
  "/projects/HeySport-Reels/project.json": {
    "type": "application/json",
    "etag": "\"2c9-XLUqqRE5cP0i3Omet6o7FuLCbLM\"",
    "mtime": "2026-05-03T22:36:41.691Z",
    "size": 713,
    "path": "../public/projects/HeySport-Reels/project.json"
  },
  "/projects/L'Autin-Logo-Animation/cover.jpg": {
    "type": "image/jpeg",
    "etag": "\"56bf3-1MBIlnBHmRcociziQHFOdythFlM\"",
    "mtime": "2026-05-03T22:36:41.691Z",
    "size": 355315,
    "path": "../public/projects/L'Autin-Logo-Animation/cover.jpg"
  },
  "/projects/Fiat 600/PANA9405.webp": {
    "type": "image/webp",
    "etag": "\"b78ca-BCAnQDc578V7xKfQyO93YCdkiXU\"",
    "mtime": "2026-05-05T19:34:15.704Z",
    "size": 751818,
    "path": "../public/projects/Fiat 600/PANA9405.webp"
  },
  "/projects/Fiat 600/PANA9409.webp": {
    "type": "image/webp",
    "etag": "\"90d5e-ZxuPoT/GAPFrjfPHQLapmuaj0pk\"",
    "mtime": "2026-05-05T19:34:15.721Z",
    "size": 593246,
    "path": "../public/projects/Fiat 600/PANA9409.webp"
  },
  "/projects/Fiat 600/PANA9407.webp": {
    "type": "image/webp",
    "etag": "\"c7a4c-KDzh/czGFYGC2IU2FwCJ+IIksZU\"",
    "mtime": "2026-05-05T19:34:15.713Z",
    "size": 817740,
    "path": "../public/projects/Fiat 600/PANA9407.webp"
  },
  "/projects/L'Autin-Logo-Animation/project.json": {
    "type": "application/json",
    "etag": "\"1ba-vrbqLYd++IutOM3Ifi2VP+rwwcU\"",
    "mtime": "2026-05-03T22:36:41.692Z",
    "size": 442,
    "path": "../public/projects/L'Autin-Logo-Animation/project.json"
  },
  "/projects/macello-horse-bts/project.json": {
    "type": "application/json",
    "etag": "\"1de-5NnPE6B/AhdC9Q1T3dx+fbf7SxQ\"",
    "mtime": "2026-05-03T22:36:41.700Z",
    "size": 478,
    "path": "../public/projects/macello-horse-bts/project.json"
  },
  "/projects/HeySport-Reels/cover.webp": {
    "type": "image/webp",
    "etag": "\"bae08-rHBo+2b6o2M3S3c7egKu2IeNNwU\"",
    "mtime": "2026-05-03T22:36:41.690Z",
    "size": 765448,
    "path": "../public/projects/HeySport-Reels/cover.webp"
  },
  "/projects/Macello-Castle-VFX/cover.webp": {
    "type": "image/webp",
    "etag": "\"79ffe-NLz/R73zQfnluvl45pHreeQcQVE\"",
    "mtime": "2026-05-03T22:36:41.692Z",
    "size": 499710,
    "path": "../public/projects/Macello-Castle-VFX/cover.webp"
  },
  "/projects/Macello-Castle-VFX/project.json": {
    "type": "application/json",
    "etag": "\"2cb-f/Vmh3kpaRl4OjMtw1nCf6n2zIk\"",
    "mtime": "2026-05-03T22:36:41.692Z",
    "size": 715,
    "path": "../public/projects/Macello-Castle-VFX/project.json"
  },
  "/_nuxt/Vialattea-PrepAction.BBrdMAYS.mp4": {
    "type": "video/mp4",
    "etag": "\"502bb2-3GpwEu0/7zSu2Y1unZm///GKVig\"",
    "mtime": "2026-05-26T18:57:58.747Z",
    "size": 5254066,
    "path": "../public/_nuxt/Vialattea-PrepAction.BBrdMAYS.mp4"
  },
  "/projects/Martina Pace/project.json": {
    "type": "application/json",
    "etag": "\"4e-EcDn1pY4+JLLrG13FZMZYG8CeGQ\"",
    "mtime": "2026-05-25T17:39:23.597Z",
    "size": 78,
    "path": "../public/projects/Martina Pace/project.json"
  },
  "/projects/Martina Pace/test_canon_c50_120.webp": {
    "type": "image/webp",
    "etag": "\"6cce2-OVkF14mhKH6UldnNw5sS4c7NU5g\"",
    "mtime": "2026-05-05T19:34:16.510Z",
    "size": 445666,
    "path": "../public/projects/Martina Pace/test_canon_c50_120.webp"
  },
  "/projects/macello-horse-bts/cover.webp": {
    "type": "image/webp",
    "etag": "\"12fdc8-8jt/aFAMc7tOULQGr0RE1+AC/KE\"",
    "mtime": "2026-05-03T22:36:41.697Z",
    "size": 1244616,
    "path": "../public/projects/macello-horse-bts/cover.webp"
  },
  "/projects/Martina Pace/test_canon_c50_01.webp": {
    "type": "image/webp",
    "etag": "\"d9a2e-E9NN9hWHpAqk7XLa4m7pBOLtpJw\"",
    "mtime": "2026-05-05T19:34:16.477Z",
    "size": 891438,
    "path": "../public/projects/Martina Pace/test_canon_c50_01.webp"
  },
  "/projects/Martina Pace/test_canon_c50_113.webp": {
    "type": "image/webp",
    "etag": "\"c182e-mXC62CAO59SURnZvz/O4ZUew3/g\"",
    "mtime": "2026-05-05T19:34:16.487Z",
    "size": 792622,
    "path": "../public/projects/Martina Pace/test_canon_c50_113.webp"
  },
  "/projects/Martina Pace/test_canon_c50_115.webp": {
    "type": "image/webp",
    "etag": "\"ad01a-ihEfOCO1WAFzUzdvcLJo+xSOcmw\"",
    "mtime": "2026-05-05T19:34:16.498Z",
    "size": 708634,
    "path": "../public/projects/Martina Pace/test_canon_c50_115.webp"
  },
  "/projects/Martina Pace/test_canon_c50_121.webp": {
    "type": "image/webp",
    "etag": "\"63ae0-ZCQjU14Xy26K7Rwuc+M7fyRRqXE\"",
    "mtime": "2026-05-05T19:34:16.518Z",
    "size": 408288,
    "path": "../public/projects/Martina Pace/test_canon_c50_121.webp"
  },
  "/projects/Martina Pace/test_canon_c50_130.webp": {
    "type": "image/webp",
    "etag": "\"7b3e4-GKNE4bUP17MZIWrlhskxFrrzKJI\"",
    "mtime": "2026-05-05T19:34:16.533Z",
    "size": 504804,
    "path": "../public/projects/Martina Pace/test_canon_c50_130.webp"
  },
  "/projects/Martina Pace/test_canon_c50_134.webp": {
    "type": "image/webp",
    "etag": "\"7b316-TIHbDYiO7t97rXYYzh/qQPULpsE\"",
    "mtime": "2026-05-05T19:34:16.541Z",
    "size": 504598,
    "path": "../public/projects/Martina Pace/test_canon_c50_134.webp"
  },
  "/projects/Martina Pace/test_canon_c50_118.webp": {
    "type": "image/webp",
    "etag": "\"85c60-R4+aCXR/UY9aKrV/ShJbrqDFEAU\"",
    "mtime": "2026-05-05T19:34:16.504Z",
    "size": 547936,
    "path": "../public/projects/Martina Pace/test_canon_c50_118.webp"
  },
  "/projects/Martina Pace/test_canon_c50_22.webp": {
    "type": "image/webp",
    "etag": "\"66bca-mett2a23x9ggLFkI8E3WUy0mDQU\"",
    "mtime": "2026-05-05T19:34:16.556Z",
    "size": 420810,
    "path": "../public/projects/Martina Pace/test_canon_c50_22.webp"
  },
  "/projects/Martina Pace/test_canon_c50_126.webp": {
    "type": "image/webp",
    "etag": "\"80dc6-WNfopw7YlarzdPtenHgiv2P4fto\"",
    "mtime": "2026-05-05T19:34:16.525Z",
    "size": 527814,
    "path": "../public/projects/Martina Pace/test_canon_c50_126.webp"
  },
  "/projects/Martina Pace/test_canon_c50_135.webp": {
    "type": "image/webp",
    "etag": "\"91400-TQ9bfCyrsDT/pQS06Vb+1BOKkK0\"",
    "mtime": "2026-05-05T19:34:16.549Z",
    "size": 594944,
    "path": "../public/projects/Martina Pace/test_canon_c50_135.webp"
  },
  "/projects/Martina Pace/test_canon_c50_26.webp": {
    "type": "image/webp",
    "etag": "\"8f874-pcj/tIfDNN4Gz6zttKv0qznymG0\"",
    "mtime": "2026-05-05T19:34:16.562Z",
    "size": 587892,
    "path": "../public/projects/Martina Pace/test_canon_c50_26.webp"
  },
  "/projects/Martina Pace/test_canon_c50_36.webp": {
    "type": "image/webp",
    "etag": "\"809d2-Di5NsnMibQEGORdih/vhkmcZwtA\"",
    "mtime": "2026-05-05T19:34:16.572Z",
    "size": 526802,
    "path": "../public/projects/Martina Pace/test_canon_c50_36.webp"
  },
  "/projects/Martina Pace/test_canon_c50_37.webp": {
    "type": "image/webp",
    "etag": "\"91764-HLuoXLGMUhxvQVjhpVS5aKTDKPM\"",
    "mtime": "2026-05-05T19:34:16.580Z",
    "size": 595812,
    "path": "../public/projects/Martina Pace/test_canon_c50_37.webp"
  },
  "/projects/Martina Pace/test_canon_c50_43.webp": {
    "type": "image/webp",
    "etag": "\"85880-XHykGS5aMJEtIKzoJIFKKN6d1U0\"",
    "mtime": "2026-05-05T19:34:16.587Z",
    "size": 546944,
    "path": "../public/projects/Martina Pace/test_canon_c50_43.webp"
  },
  "/projects/Martina Pace/test_canon_c50_89.webp": {
    "type": "image/webp",
    "etag": "\"59906-px8XU4FY7f3VJIl6owsFX1PPgiU\"",
    "mtime": "2026-05-05T19:34:16.633Z",
    "size": 366854,
    "path": "../public/projects/Martina Pace/test_canon_c50_89.webp"
  },
  "/projects/Martina Pace/test_canon_c50_93.webp": {
    "type": "image/webp",
    "etag": "\"7530a-JW/yNQVqPOj+6S7lNYyrgRixVoQ\"",
    "mtime": "2026-05-05T19:34:16.639Z",
    "size": 480010,
    "path": "../public/projects/Martina Pace/test_canon_c50_93.webp"
  },
  "/projects/Martina Pace/test_canon_c50_95.webp": {
    "type": "image/webp",
    "etag": "\"7bfba-bPhHB+xNZ7dleFTdyLWwG4wBeN0\"",
    "mtime": "2026-05-05T19:34:16.648Z",
    "size": 507834,
    "path": "../public/projects/Martina Pace/test_canon_c50_95.webp"
  },
  "/projects/Martina Pace/test_canon_c50_60.webp": {
    "type": "image/webp",
    "etag": "\"d4d24-SWWn/w6bqijE3tcicxDZ92KJSs8\"",
    "mtime": "2026-05-05T19:34:16.610Z",
    "size": 871716,
    "path": "../public/projects/Martina Pace/test_canon_c50_60.webp"
  },
  "/projects/Martina Pace/test_canon_c50_76.webp": {
    "type": "image/webp",
    "etag": "\"9229c-P7H5M6Zx0Ha6460TWd9xE9rMZYU\"",
    "mtime": "2026-05-05T19:34:16.617Z",
    "size": 598684,
    "path": "../public/projects/Martina Pace/test_canon_c50_76.webp"
  },
  "/projects/Martina Pace/test_canon_c50_79.webp": {
    "type": "image/webp",
    "etag": "\"a23f6-JyhuHVBx81YlD2/eZQ+tJk4/V68\"",
    "mtime": "2026-05-05T19:34:16.625Z",
    "size": 664566,
    "path": "../public/projects/Martina Pace/test_canon_c50_79.webp"
  },
  "/projects/Martina Pace/test_canon_c50_46.webp": {
    "type": "image/webp",
    "etag": "\"10e000-Z2nprXbdQX17ETUtM/yLgG18SAg\"",
    "mtime": "2026-05-05T19:34:16.599Z",
    "size": 1105920,
    "path": "../public/projects/Martina Pace/test_canon_c50_46.webp"
  },
  "/projects/Martina_Pace/cover.jpg": {
    "type": "image/jpeg",
    "etag": "\"4b437-jloMA3Q2//01aAywFK0Z6BKgElA\"",
    "mtime": "2026-05-04T13:01:34.419Z",
    "size": 308279,
    "path": "../public/projects/Martina_Pace/cover.jpg"
  },
  "/projects/Martina_Pace/project.json": {
    "type": "application/json",
    "etag": "\"158-PrwLPXjRCMdYiaMPxZsiKuItiMA\"",
    "mtime": "2026-05-04T10:52:25.783Z",
    "size": 344,
    "path": "../public/projects/Martina_Pace/project.json"
  },
  "/projects/Merlo-e-Worker-ADVs/cover.webp": {
    "type": "image/webp",
    "etag": "\"16476-HR25Rgy/HZSeY4UAG0kye5yhGxs\"",
    "mtime": "2026-05-03T22:36:41.692Z",
    "size": 91254,
    "path": "../public/projects/Merlo-e-Worker-ADVs/cover.webp"
  },
  "/projects/Merlo-e-Worker-ADVs/project.json": {
    "type": "application/json",
    "etag": "\"2f0-W6U1zx5mkt06BFRbrD7jnIfL3G0\"",
    "mtime": "2026-05-03T22:36:41.693Z",
    "size": 752,
    "path": "../public/projects/Merlo-e-Worker-ADVs/project.json"
  },
  "/projects/My-Lamination/project.json": {
    "type": "application/json",
    "etag": "\"2ec-17hUHL6WoVZTAQ847Xz3DrqhEi4\"",
    "mtime": "2026-05-03T22:36:41.695Z",
    "size": 748,
    "path": "../public/projects/My-Lamination/project.json"
  },
  "/projects/Rigolizia-Mon-Amour/project.json": {
    "type": "application/json",
    "etag": "\"2a1-OodT/vxysqznrW6rwO6V7Vde7H8\"",
    "mtime": "2026-05-04T20:28:27.243Z",
    "size": 673,
    "path": "../public/projects/Rigolizia-Mon-Amour/project.json"
  },
  "/projects/My-Lamination/cover.webp": {
    "type": "image/webp",
    "etag": "\"896bc-IRPADobx7Pyhs8Flfjwh8p0jI7M\"",
    "mtime": "2026-05-03T22:36:41.693Z",
    "size": 562876,
    "path": "../public/projects/My-Lamination/cover.webp"
  },
  "/projects/Roma/project.json": {
    "type": "application/json",
    "etag": "\"46-A8jmtRlUAbjcrBhhKvzymy9cXQ4\"",
    "mtime": "2026-05-25T17:39:23.599Z",
    "size": 70,
    "path": "../public/projects/Roma/project.json"
  },
  "/projects/Rigolizia-Mon-Amour/cover.webp": {
    "type": "image/webp",
    "etag": "\"bff88-kyi2i7/3CLJQ5qTZCmZMVPRANdg\"",
    "mtime": "2026-05-05T21:45:44.073Z",
    "size": 786312,
    "path": "../public/projects/Rigolizia-Mon-Amour/cover.webp"
  },
  "/projects/Roma/roma_2026_104.webp": {
    "type": "image/webp",
    "etag": "\"e4c54-z53Z4x9uGqy66UbT3e6vMwaEXew\"",
    "mtime": "2026-05-05T19:34:18.033Z",
    "size": 937044,
    "path": "../public/projects/Roma/roma_2026_104.webp"
  },
  "/projects/Roma/roma_2026_121.webp": {
    "type": "image/webp",
    "etag": "\"f8148-WYG8Cnh3lMWt49jFVFYQqCbNTkM\"",
    "mtime": "2026-05-05T19:34:18.055Z",
    "size": 1016136,
    "path": "../public/projects/Roma/roma_2026_121.webp"
  },
  "/projects/Roma/roma_2026_132.webp": {
    "type": "image/webp",
    "etag": "\"b4932-s23NGZFE4Lbs8gaGmSNsp5nMlcg\"",
    "mtime": "2026-05-05T19:34:18.064Z",
    "size": 739634,
    "path": "../public/projects/Roma/roma_2026_132.webp"
  },
  "/projects/Roma/roma_2026_15.webp": {
    "type": "image/webp",
    "etag": "\"e741c-GEmyqNpPD+3LFt6sw0J7BztZ6nY\"",
    "mtime": "2026-05-05T19:34:18.087Z",
    "size": 947228,
    "path": "../public/projects/Roma/roma_2026_15.webp"
  },
  "/projects/Rigolizia-Mon-Amour/cover.mp4": {
    "type": "video/mp4",
    "etag": "\"194af1-Yb6hWIGQxrJUy5+kuQqeMykJftw\"",
    "mtime": "2026-05-03T22:42:29.388Z",
    "size": 1657585,
    "path": "../public/projects/Rigolizia-Mon-Amour/cover.mp4"
  },
  "/projects/Roma/roma_2026_151.webp": {
    "type": "image/webp",
    "etag": "\"e6f70-GBUSN8jI8ZP2AMjK+b8a++P5+8o\"",
    "mtime": "2026-05-05T19:34:18.095Z",
    "size": 946032,
    "path": "../public/projects/Roma/roma_2026_151.webp"
  },
  "/projects/Roma/roma_2026_16.webp": {
    "type": "image/webp",
    "etag": "\"ebf08-GjJN/yGrV7A5gMMxh8xjuFFwv6w\"",
    "mtime": "2026-05-05T19:34:18.118Z",
    "size": 966408,
    "path": "../public/projects/Roma/roma_2026_16.webp"
  },
  "/projects/Roma/roma_2026_167.webp": {
    "type": "image/webp",
    "etag": "\"c55b6-atuoWOSVFDjekLsXNAdnccnkoTg\"",
    "mtime": "2026-05-05T19:34:18.125Z",
    "size": 808374,
    "path": "../public/projects/Roma/roma_2026_167.webp"
  },
  "/projects/Roma/roma_2026_168.webp": {
    "type": "image/webp",
    "etag": "\"c7b80-GnXaXQY943IJNE7rF5ZLlFPkbKg\"",
    "mtime": "2026-05-05T19:34:18.135Z",
    "size": 818048,
    "path": "../public/projects/Roma/roma_2026_168.webp"
  },
  "/projects/Roma/roma_2026_114.webp": {
    "type": "image/webp",
    "etag": "\"135752-UIHtUwsnhIxvZPZfz8Pc0sv6XcM\"",
    "mtime": "2026-05-05T19:34:18.045Z",
    "size": 1267538,
    "path": "../public/projects/Roma/roma_2026_114.webp"
  },
  "/projects/Roma/roma_2026_140.webp": {
    "type": "image/webp",
    "etag": "\"11630a-upL4yHROcEI658k+b8OLy9RTYL4\"",
    "mtime": "2026-05-05T19:34:18.077Z",
    "size": 1139466,
    "path": "../public/projects/Roma/roma_2026_140.webp"
  },
  "/projects/Roma/roma_2026_173.webp": {
    "type": "image/webp",
    "etag": "\"bfe9a-39THK/GgLQFzcVP7+JaFIjEMoOU\"",
    "mtime": "2026-05-05T19:34:18.144Z",
    "size": 786074,
    "path": "../public/projects/Roma/roma_2026_173.webp"
  },
  "/projects/Roma/roma_2026_153.webp": {
    "type": "image/webp",
    "etag": "\"102a04-qPQKkglY205DQg15P5DMqH6b8mE\"",
    "mtime": "2026-05-05T19:34:18.107Z",
    "size": 1059332,
    "path": "../public/projects/Roma/roma_2026_153.webp"
  },
  "/projects/Roma/roma_2026_198.webp": {
    "type": "image/webp",
    "etag": "\"c9838-p7+Td8dTQwjZYP9QY/zdGhs0SfY\"",
    "mtime": "2026-05-05T19:34:18.202Z",
    "size": 825400,
    "path": "../public/projects/Roma/roma_2026_198.webp"
  },
  "/projects/Roma/roma_2026_18.webp": {
    "type": "image/webp",
    "etag": "\"10fb7a-W3TjXwtW+HDNEb0MWPG8Tzh3zxQ\"",
    "mtime": "2026-05-05T19:34:18.155Z",
    "size": 1112954,
    "path": "../public/projects/Roma/roma_2026_18.webp"
  },
  "/projects/Roma/roma_2026_187.webp": {
    "type": "image/webp",
    "etag": "\"17c9b4-vynKO4OS6rzG6rlDr6TOHcr3XMw\"",
    "mtime": "2026-05-05T19:34:18.169Z",
    "size": 1558964,
    "path": "../public/projects/Roma/roma_2026_187.webp"
  },
  "/projects/Roma/roma_2026_203.webp": {
    "type": "image/webp",
    "etag": "\"bde6a-0zy+W6HV+zqruYapoyFeHr6HVDs\"",
    "mtime": "2026-05-05T19:34:18.212Z",
    "size": 777834,
    "path": "../public/projects/Roma/roma_2026_203.webp"
  },
  "/projects/Roma/roma_2026_188.webp": {
    "type": "image/webp",
    "etag": "\"1608a2-8H69bUZ0PXs40wf9N1n6C5FzwmA\"",
    "mtime": "2026-05-05T19:34:18.182Z",
    "size": 1444002,
    "path": "../public/projects/Roma/roma_2026_188.webp"
  },
  "/projects/Roma/roma_2026_189.webp": {
    "type": "image/webp",
    "etag": "\"106bbe-3DLZpGuY8m9TYOiPSfZRzd10f/M\"",
    "mtime": "2026-05-05T19:34:18.194Z",
    "size": 1076158,
    "path": "../public/projects/Roma/roma_2026_189.webp"
  },
  "/projects/Roma/roma_2026_204.webp": {
    "type": "image/webp",
    "etag": "\"cdd70-XkC1BdNgZT5aZXM5aZ9v13fwImc\"",
    "mtime": "2026-05-05T19:34:18.221Z",
    "size": 843120,
    "path": "../public/projects/Roma/roma_2026_204.webp"
  },
  "/projects/Roma/roma_2026_218.webp": {
    "type": "image/webp",
    "etag": "\"f87b0-3Ph1/duhl9jPyM8NUCk8EKFaNiQ\"",
    "mtime": "2026-05-05T19:34:18.233Z",
    "size": 1017776,
    "path": "../public/projects/Roma/roma_2026_218.webp"
  },
  "/projects/Roma/roma_2026_22.webp": {
    "type": "image/webp",
    "etag": "\"f01f2-YdIHuVewkiVDYmcE6AjY6vdjbek\"",
    "mtime": "2026-05-05T19:34:18.244Z",
    "size": 983538,
    "path": "../public/projects/Roma/roma_2026_22.webp"
  },
  "/projects/Roma/roma_2026_220.webp": {
    "type": "image/webp",
    "etag": "\"a7c20-3PTq6otuKTORiaOYVhGsOQZ7AuE\"",
    "mtime": "2026-05-05T19:34:18.252Z",
    "size": 687136,
    "path": "../public/projects/Roma/roma_2026_220.webp"
  },
  "/projects/Merlo-e-Worker-ADVs/cover.mp4": {
    "type": "video/mp4",
    "etag": "\"469029-yQNV8SO8FMYCaYrzeAt+0VSexcA\"",
    "mtime": "2026-05-03T22:42:29.388Z",
    "size": 4624425,
    "path": "../public/projects/Merlo-e-Worker-ADVs/cover.mp4"
  },
  "/projects/HeySport-Reels/cover.mp4": {
    "type": "video/mp4",
    "etag": "\"7cccb3-18JAFkajcM17yY0lKAibwYGg3KA\"",
    "mtime": "2026-05-03T22:42:29.387Z",
    "size": 8178867,
    "path": "../public/projects/HeySport-Reels/cover.mp4"
  },
  "/projects/Roma/roma_2026_23.webp": {
    "type": "image/webp",
    "etag": "\"e9d76-OTHiP3Tm3/UUCzX6ouGIogTHNe0\"",
    "mtime": "2026-05-05T19:34:18.262Z",
    "size": 957814,
    "path": "../public/projects/Roma/roma_2026_23.webp"
  },
  "/projects/Roma/roma_2026_235.webp": {
    "type": "image/webp",
    "etag": "\"ec1fc-fb6729AabNE1rFc76lMBX8vlx1U\"",
    "mtime": "2026-05-05T19:34:18.273Z",
    "size": 967164,
    "path": "../public/projects/Roma/roma_2026_235.webp"
  },
  "/projects/Roma/roma_2026_266.webp": {
    "type": "image/webp",
    "etag": "\"d7b62-oaNNjg5XYlW1x62Lgwb9SEb7ieM\"",
    "mtime": "2026-05-05T19:34:18.282Z",
    "size": 883554,
    "path": "../public/projects/Roma/roma_2026_266.webp"
  },
  "/projects/Roma/roma_2026_272.webp": {
    "type": "image/webp",
    "etag": "\"ff14c-ebQ/WW51FPWIfHOtotdfLhergQQ\"",
    "mtime": "2026-05-05T19:34:18.294Z",
    "size": 1044812,
    "path": "../public/projects/Roma/roma_2026_272.webp"
  },
  "/projects/Roma/roma_2026_279.webp": {
    "type": "image/webp",
    "etag": "\"d61c6-Vk56pgHngNGOvqeY189CQQph6yg\"",
    "mtime": "2026-05-05T19:34:18.304Z",
    "size": 876998,
    "path": "../public/projects/Roma/roma_2026_279.webp"
  },
  "/projects/Roma/roma_2026_288.webp": {
    "type": "image/webp",
    "etag": "\"c2fc4-9vHfsDp0twK8nQ/n/2Bmki1mj5w\"",
    "mtime": "2026-05-05T19:34:18.312Z",
    "size": 798660,
    "path": "../public/projects/Roma/roma_2026_288.webp"
  },
  "/projects/L'Autin-Logo-Animation/cover.mp4": {
    "type": "video/mp4",
    "etag": "\"7e5935-2oH85kWP9kUijzTwxOO499ZvtLM\"",
    "mtime": "2026-05-03T22:42:29.388Z",
    "size": 8280373,
    "path": "../public/projects/L'Autin-Logo-Animation/cover.mp4"
  },
  "/projects/Roma/roma_2026_291.webp": {
    "type": "image/webp",
    "etag": "\"ea260-k6L9VZfC8+9T4W1b7SotfPjA6tA\"",
    "mtime": "2026-05-05T19:34:18.337Z",
    "size": 959072,
    "path": "../public/projects/Roma/roma_2026_291.webp"
  },
  "/projects/Roma/roma_2026_297.webp": {
    "type": "image/webp",
    "etag": "\"df80c-qdCEkiUHPTXmL7xudnloel+4uwg\"",
    "mtime": "2026-05-05T19:34:18.345Z",
    "size": 915468,
    "path": "../public/projects/Roma/roma_2026_297.webp"
  },
  "/projects/Roma/roma_2026_298.webp": {
    "type": "image/webp",
    "etag": "\"e49a8-25GOS9NjOwPziJ7sV6GnQxrSG1Y\"",
    "mtime": "2026-05-05T19:34:18.358Z",
    "size": 936360,
    "path": "../public/projects/Roma/roma_2026_298.webp"
  },
  "/projects/Roma/roma_2026_290.webp": {
    "type": "image/webp",
    "etag": "\"12c326-FyR0aa7v1rQ6S/5ILDetqR+lwCs\"",
    "mtime": "2026-05-05T19:34:18.325Z",
    "size": 1229606,
    "path": "../public/projects/Roma/roma_2026_290.webp"
  },
  "/projects/Roma/roma_2026_30.webp": {
    "type": "image/webp",
    "etag": "\"10e08e-WMmYhkEApYmmu5/pKwFQhZuLEC8\"",
    "mtime": "2026-05-05T19:34:18.370Z",
    "size": 1106062,
    "path": "../public/projects/Roma/roma_2026_30.webp"
  },
  "/projects/Roma/roma_2026_303.webp": {
    "type": "image/webp",
    "etag": "\"108174-uAjMxdH4EuKexsof0/6CmxqLRrw\"",
    "mtime": "2026-05-05T19:34:18.381Z",
    "size": 1081716,
    "path": "../public/projects/Roma/roma_2026_303.webp"
  },
  "/projects/Roma/roma_2026_313.webp": {
    "type": "image/webp",
    "etag": "\"ea360-CVW5fbH6+8SpeyxfhmnSYoMLhmY\"",
    "mtime": "2026-05-05T19:34:18.406Z",
    "size": 959328,
    "path": "../public/projects/Roma/roma_2026_313.webp"
  },
  "/projects/Roma/roma_2026_315.webp": {
    "type": "image/webp",
    "etag": "\"aedf2-og3ctDZFwySJB3aoMPJRk4RkMGE\"",
    "mtime": "2026-05-05T19:34:18.414Z",
    "size": 716274,
    "path": "../public/projects/Roma/roma_2026_315.webp"
  },
  "/projects/Roma/roma_2026_320.webp": {
    "type": "image/webp",
    "etag": "\"c6720-KcI0yUFpLroA1sRLwJ43aH8KySc\"",
    "mtime": "2026-05-05T19:34:18.425Z",
    "size": 812832,
    "path": "../public/projects/Roma/roma_2026_320.webp"
  },
  "/projects/Roma/roma_2026_322.webp": {
    "type": "image/webp",
    "etag": "\"9de60-k9q9nVjUwvityNnqE1tboJcRW8o\"",
    "mtime": "2026-05-05T19:34:18.442Z",
    "size": 646752,
    "path": "../public/projects/Roma/roma_2026_322.webp"
  },
  "/projects/Roma/roma_2026_321.webp": {
    "type": "image/webp",
    "etag": "\"ce06e-9lSfxaO5XnI6Xv3d2nK6Hcjea+w\"",
    "mtime": "2026-05-05T19:34:18.433Z",
    "size": 843886,
    "path": "../public/projects/Roma/roma_2026_321.webp"
  },
  "/projects/Roma/roma_2026_329.webp": {
    "type": "image/webp",
    "etag": "\"c4044-34fRXxC/OYpsETMGEJCK5HrrhJ4\"",
    "mtime": "2026-05-05T19:34:18.451Z",
    "size": 802884,
    "path": "../public/projects/Roma/roma_2026_329.webp"
  },
  "/projects/Roma/roma_2026_31.webp": {
    "type": "image/webp",
    "etag": "\"160378-oBOb/DTqQ0SzGqboRvOoTO3f7Lw\"",
    "mtime": "2026-05-05T19:34:18.395Z",
    "size": 1442680,
    "path": "../public/projects/Roma/roma_2026_31.webp"
  },
  "/projects/Roma/roma_2026_33.webp": {
    "type": "image/webp",
    "etag": "\"106696-60+8Vn4+yOKhtqNGeJ4ycLgvaEo\"",
    "mtime": "2026-05-05T19:34:18.463Z",
    "size": 1074838,
    "path": "../public/projects/Roma/roma_2026_33.webp"
  },
  "/projects/Roma/roma_2026_36.webp": {
    "type": "image/webp",
    "etag": "\"124d44-9lQGBQPERaPY+gntuFCfgCMs668\"",
    "mtime": "2026-05-05T19:34:18.471Z",
    "size": 1199428,
    "path": "../public/projects/Roma/roma_2026_36.webp"
  },
  "/projects/Roma/roma_2026_64.webp": {
    "type": "image/webp",
    "etag": "\"f6086-qbZx9qF3nTfb6IF27XCwAFiCLU0\"",
    "mtime": "2026-05-05T19:34:18.485Z",
    "size": 1007750,
    "path": "../public/projects/Roma/roma_2026_64.webp"
  },
  "/projects/Roma/roma_2026_72.webp": {
    "type": "image/webp",
    "etag": "\"ef19a-zDC2af4cT9rHfGka3bsuOo6qs4k\"",
    "mtime": "2026-05-05T19:34:18.507Z",
    "size": 979354,
    "path": "../public/projects/Roma/roma_2026_72.webp"
  },
  "/projects/Roma/roma_2026_80.webp": {
    "type": "image/webp",
    "etag": "\"c9682-Mqx25uNre2fEjlolScgqTREsW1M\"",
    "mtime": "2026-05-05T19:34:18.514Z",
    "size": 824962,
    "path": "../public/projects/Roma/roma_2026_80.webp"
  },
  "/projects/Roma/roma_2026_82.webp": {
    "type": "image/webp",
    "etag": "\"da4ac-/lMaD0RJQJ9fHCi13JIw2iYNoT0\"",
    "mtime": "2026-05-05T19:34:18.525Z",
    "size": 894124,
    "path": "../public/projects/Roma/roma_2026_82.webp"
  },
  "/projects/Roma/roma_2026_70.webp": {
    "type": "image/webp",
    "etag": "\"115bfc-BIdb+VoxwjGl6q0I9IdnNXBgIFA\"",
    "mtime": "2026-05-05T19:34:18.495Z",
    "size": 1137660,
    "path": "../public/projects/Roma/roma_2026_70.webp"
  },
  "/projects/Unbow-Logo-Animation/project.json": {
    "type": "application/json",
    "etag": "\"1cb-2BmKz3veJEG7yStHHvTfFv9FjrM\"",
    "mtime": "2026-05-03T22:36:41.697Z",
    "size": 459,
    "path": "../public/projects/Unbow-Logo-Animation/project.json"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_120.webp": {
    "type": "image/webp",
    "etag": "\"efed2-yxo6yWU6X4TZelyvvo3n3XCwPEA\"",
    "mtime": "2026-05-25T12:20:47.945Z",
    "size": 982738,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_120.webp"
  },
  "/projects/Roma/roma_2026_leica_46.webp": {
    "type": "image/webp",
    "etag": "\"1dd1b2-Z4QqAuU42WiOx8xHuLro7hoTJ2g\"",
    "mtime": "2026-05-05T19:34:18.595Z",
    "size": 1954226,
    "path": "../public/projects/Roma/roma_2026_leica_46.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_122.webp": {
    "type": "image/webp",
    "etag": "\"fb5de-HsIoyiZkEpvfo90DaPaW5AhtOQg\"",
    "mtime": "2026-05-25T12:20:48.575Z",
    "size": 1029598,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_122.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_127.webp": {
    "type": "image/webp",
    "etag": "\"9963c-kZbObSmnxdWfP17Zvz4hubW4q6M\"",
    "mtime": "2026-05-25T12:20:49.137Z",
    "size": 628284,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_127.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_128.webp": {
    "type": "image/webp",
    "etag": "\"a3f04-FagQrAN8uQnCYEpi0qjeEVbL/cY\"",
    "mtime": "2026-05-25T12:20:49.702Z",
    "size": 671492,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_128.webp"
  },
  "/projects/Roma/roma_2026_leica_56.webp": {
    "type": "image/webp",
    "etag": "\"1f6068-wP4OAip6tF72eB0j/H1XVHSMNW4\"",
    "mtime": "2026-05-05T19:34:18.631Z",
    "size": 2056296,
    "path": "../public/projects/Roma/roma_2026_leica_56.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_160.webp": {
    "type": "image/webp",
    "etag": "\"7665a-gyOGNOK2sAezZ3bEXL4Z7AFbDG8\"",
    "mtime": "2026-05-25T12:20:50.826Z",
    "size": 484954,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_160.webp"
  },
  "/projects/Roma/roma_2026_leica_7.webp": {
    "type": "image/webp",
    "etag": "\"1fc5ca-E117FHxuXmPBADRjZc1DT4Au9xY\"",
    "mtime": "2026-05-05T19:34:18.649Z",
    "size": 2082250,
    "path": "../public/projects/Roma/roma_2026_leica_7.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_147.webp": {
    "type": "image/webp",
    "etag": "\"ea9a6-ERSBMEGqlazJbgc2ZhaowJMu0yA\"",
    "mtime": "2026-05-25T12:20:50.297Z",
    "size": 960934,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_147.webp"
  },
  "/projects/Roma/roma_2026_leica_13.webp": {
    "type": "image/webp",
    "etag": "\"23da60-9spcCLAvzxf2j0otqMeev1rYkO0\"",
    "mtime": "2026-05-05T19:34:18.544Z",
    "size": 2349664,
    "path": "../public/projects/Roma/roma_2026_leica_13.webp"
  },
  "/projects/Roma/roma_2026_leica_17.webp": {
    "type": "image/webp",
    "etag": "\"229382-Aqy6Mp9uT96FB9nakEvKIgbi09k\"",
    "mtime": "2026-05-05T19:34:18.562Z",
    "size": 2265986,
    "path": "../public/projects/Roma/roma_2026_leica_17.webp"
  },
  "/projects/Roma/roma_2026_leica_45.webp": {
    "type": "image/webp",
    "etag": "\"201458-71mhhHpmNFDTQHonKKLGXMWLsb8\"",
    "mtime": "2026-05-05T19:34:18.580Z",
    "size": 2102360,
    "path": "../public/projects/Roma/roma_2026_leica_45.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_114.webp": {
    "type": "image/webp",
    "etag": "\"144d54-xnrJhYeD0vuFfp4AkVriJo9Hp30\"",
    "mtime": "2026-05-25T12:20:47.327Z",
    "size": 1330516,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_114.webp"
  },
  "/projects/Roma/roma_2026_leica_47.webp": {
    "type": "image/webp",
    "etag": "\"215aa2-09bZAIKhd6JrTSo3UQ9sACFRTr8\"",
    "mtime": "2026-05-05T19:34:18.612Z",
    "size": 2185890,
    "path": "../public/projects/Roma/roma_2026_leica_47.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_190.webp": {
    "type": "image/webp",
    "etag": "\"7f7a2-sihIYI48UEtXubN0AYASyFlfMyY\"",
    "mtime": "2026-05-25T12:20:52.538Z",
    "size": 522146,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_190.webp"
  },
  "/projects/Roma/roma_2026_leica_81.webp": {
    "type": "image/webp",
    "etag": "\"1f63c8-bF2lX88o/15vAYE5HbZ6rh7m5gE\"",
    "mtime": "2026-05-05T19:34:18.681Z",
    "size": 2057160,
    "path": "../public/projects/Roma/roma_2026_leica_81.webp"
  },
  "/projects/Roma/roma_2026_leica_89.webp": {
    "type": "image/webp",
    "etag": "\"1b5010-FNGrFJK8z+SeXAJboSs9Oe4n9as\"",
    "mtime": "2026-05-05T19:34:18.698Z",
    "size": 1789968,
    "path": "../public/projects/Roma/roma_2026_leica_89.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_186.webp": {
    "type": "image/webp",
    "etag": "\"da15a-qQlMtty6tXi6MN/Iyvsni3BrPHI\"",
    "mtime": "2026-05-25T12:20:51.426Z",
    "size": 893274,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_186.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_189.webp": {
    "type": "image/webp",
    "etag": "\"8b786-bCaQWrGX5ZJXVfxldTRGBOu/WNQ\"",
    "mtime": "2026-05-25T12:20:51.988Z",
    "size": 571270,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_189.webp"
  },
  "/projects/Roma/roma_2026_leica_78.webp": {
    "type": "image/webp",
    "etag": "\"21a28c-eSH79C3PjGOaqhuieokTrsIePb0\"",
    "mtime": "2026-05-05T19:34:18.664Z",
    "size": 2204300,
    "path": "../public/projects/Roma/roma_2026_leica_78.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_191.webp": {
    "type": "image/webp",
    "etag": "\"93602-F/X3p8Fj+0QhF3ed+ocVXDnepY0\"",
    "mtime": "2026-05-25T12:20:53.114Z",
    "size": 603650,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_191.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_192.webp": {
    "type": "image/webp",
    "etag": "\"9418c-6V4GwE9wVI1Xa6JRukU/D+FBt5s\"",
    "mtime": "2026-05-25T12:20:53.675Z",
    "size": 606604,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_192.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_194.webp": {
    "type": "image/webp",
    "etag": "\"90012-oTrk9j/ecABn/ghgEI1RAI4FzsA\"",
    "mtime": "2026-05-25T12:20:54.231Z",
    "size": 589842,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_194.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_232.webp": {
    "type": "image/webp",
    "etag": "\"5ce84-aWsRpsocJ1/y05nNHhnKLyk2gtg\"",
    "mtime": "2026-05-25T12:20:55.345Z",
    "size": 380548,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_232.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_213.webp": {
    "type": "image/webp",
    "etag": "\"cbd64-TdXcSuwhd/5aqJYvZmeHKsPIv6w\"",
    "mtime": "2026-05-25T12:20:54.823Z",
    "size": 834916,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_213.webp"
  },
  "/projects/Unbow-Logo-Animation/cover.gif": {
    "type": "image/gif",
    "etag": "\"2c2109-ut9h0RcqfIxm6v7cKjFTP8MzLiY\"",
    "mtime": "2026-05-03T22:36:41.697Z",
    "size": 2892041,
    "path": "../public/projects/Unbow-Logo-Animation/cover.gif"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_234.webp": {
    "type": "image/webp",
    "etag": "\"a2230-Qkh48RaJZcIEP9mYbLm9Vu3C3HQ\"",
    "mtime": "2026-05-25T12:20:55.921Z",
    "size": 664112,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_234.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_239.webp": {
    "type": "image/webp",
    "etag": "\"ad39c-uZWk+ETv8ScWYfQOtat+RfeFPVU\"",
    "mtime": "2026-05-25T12:20:56.510Z",
    "size": 709532,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_239.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_246.webp": {
    "type": "image/webp",
    "etag": "\"b5944-OR/kI++/4safAAS7QJm18vPKiUo\"",
    "mtime": "2026-05-25T12:20:57.754Z",
    "size": 743748,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_246.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_260.webp": {
    "type": "image/webp",
    "etag": "\"a0608-X7XOBdc91u3YzUgcWDvd2Vh1QaE\"",
    "mtime": "2026-05-25T12:20:58.345Z",
    "size": 656904,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_260.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_274.webp": {
    "type": "image/webp",
    "etag": "\"cc2d6-oIdmt8Cwisj6/wrBEiBOYmkuVdU\"",
    "mtime": "2026-05-25T12:20:58.954Z",
    "size": 836310,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_274.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_276.webp": {
    "type": "image/webp",
    "etag": "\"9eaea-BVAhou5TxbdTeWBBt8zACPoLGVU\"",
    "mtime": "2026-05-25T12:20:59.533Z",
    "size": 649962,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_276.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_31.webp": {
    "type": "image/webp",
    "etag": "\"a8f7a-09OkBMoqJW5KNOND/re2j0p91WY\"",
    "mtime": "2026-05-25T12:21:00.126Z",
    "size": 692090,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_31.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_32.webp": {
    "type": "image/webp",
    "etag": "\"b7900-esbaFOWRauPTn1hR9SkQfJMX/5I\"",
    "mtime": "2026-05-25T12:21:00.728Z",
    "size": 751872,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_32.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_40.webp": {
    "type": "image/webp",
    "etag": "\"ab382-1qSftIY/Pdx84N/BfmfDosWtdZY\"",
    "mtime": "2026-05-25T12:21:01.314Z",
    "size": 701314,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_40.webp"
  },
  "/projects/Fragile/images/fragile_1.webp": {
    "type": "image/webp",
    "etag": "\"b5e40-UkPw0Y2MazfiX8sdVjz6Al0PuFs\"",
    "mtime": "2026-05-05T18:06:40.291Z",
    "size": 745024,
    "path": "../public/projects/Fragile/images/fragile_1.webp"
  },
  "/projects/Fragile/images/fragile_10.webp": {
    "type": "image/webp",
    "etag": "\"eda18-ug57Bvemf6U2pIW5rb2wIT3JVuM\"",
    "mtime": "2026-05-05T18:06:43.161Z",
    "size": 973336,
    "path": "../public/projects/Fragile/images/fragile_10.webp"
  },
  "/projects/Fragile/images/fragile_11.webp": {
    "type": "image/webp",
    "etag": "\"c1456-Jlw5sIpP4trYKHnznF3x2WsdB6k\"",
    "mtime": "2026-05-05T18:06:43.477Z",
    "size": 791638,
    "path": "../public/projects/Fragile/images/fragile_11.webp"
  },
  "/projects/Fragile/images/fragile_12.webp": {
    "type": "image/webp",
    "etag": "\"c9968-lPEfzNmS1Yy8bLiB2tMuYDikv0g\"",
    "mtime": "2026-05-05T18:06:43.789Z",
    "size": 825704,
    "path": "../public/projects/Fragile/images/fragile_12.webp"
  },
  "/projects/Fragile/images/fragile_13.webp": {
    "type": "image/webp",
    "etag": "\"c6cce-DQR523uBr7SApCh5SyKNfkdiccI\"",
    "mtime": "2026-05-05T18:06:44.097Z",
    "size": 814286,
    "path": "../public/projects/Fragile/images/fragile_13.webp"
  },
  "/projects/Fragile/images/fragile_14.webp": {
    "type": "image/webp",
    "etag": "\"aba2c-xUlvyFLZ7O7dihAvHsHqHbpG8z8\"",
    "mtime": "2026-05-05T18:06:44.403Z",
    "size": 703020,
    "path": "../public/projects/Fragile/images/fragile_14.webp"
  },
  "/projects/Fragile/images/fragile_15.webp": {
    "type": "image/webp",
    "etag": "\"c4004-D2k8se5fXKJJtRrubgCD0a/SfYc\"",
    "mtime": "2026-05-05T18:06:44.717Z",
    "size": 802820,
    "path": "../public/projects/Fragile/images/fragile_15.webp"
  },
  "/projects/Fragile/images/fragile_17.webp": {
    "type": "image/webp",
    "etag": "\"bee9c-7qRS1spflnNlz0dU165+hd/xf1A\"",
    "mtime": "2026-05-05T18:06:45.334Z",
    "size": 781980,
    "path": "../public/projects/Fragile/images/fragile_17.webp"
  },
  "/projects/Fragile/images/fragile_16.webp": {
    "type": "image/webp",
    "etag": "\"bcdee-10wp+qJSWIfztBQSKyxwCdn4yic\"",
    "mtime": "2026-05-05T18:06:45.026Z",
    "size": 773614,
    "path": "../public/projects/Fragile/images/fragile_16.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_242.webp": {
    "type": "image/webp",
    "etag": "\"1cd212-6huVKx1xq0Qg3S1I4bamKayHXrg\"",
    "mtime": "2026-05-25T12:20:57.231Z",
    "size": 1888786,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_242.webp"
  },
  "/projects/Fragile/images/fragile_18.webp": {
    "type": "image/webp",
    "etag": "\"b771e-0JeEHtnwheDVBddzmE+O2nssVeo\"",
    "mtime": "2026-05-05T18:06:45.637Z",
    "size": 751390,
    "path": "../public/projects/Fragile/images/fragile_18.webp"
  },
  "/projects/Fragile/images/fragile_19.webp": {
    "type": "image/webp",
    "etag": "\"b9176-vOZDbSC1meQjvNcxhKH6vYfYJ50\"",
    "mtime": "2026-05-05T18:06:45.944Z",
    "size": 758134,
    "path": "../public/projects/Fragile/images/fragile_19.webp"
  },
  "/projects/Fragile/images/fragile_2.webp": {
    "type": "image/webp",
    "etag": "\"dca14-YewP70GA8J2D6Php69LuwGbQUd0\"",
    "mtime": "2026-05-05T18:06:40.645Z",
    "size": 903700,
    "path": "../public/projects/Fragile/images/fragile_2.webp"
  },
  "/projects/Fragile/images/fragile_20.webp": {
    "type": "image/webp",
    "etag": "\"90b98-ENf6Yvjj8DJ/S8LG/nqrqLe106k\"",
    "mtime": "2026-05-05T18:06:46.223Z",
    "size": 592792,
    "path": "../public/projects/Fragile/images/fragile_20.webp"
  },
  "/projects/Fragile/images/fragile_21.webp": {
    "type": "image/webp",
    "etag": "\"c2b7c-qJ/fWfZAAVUM1v82gFfvkWc3ajo\"",
    "mtime": "2026-05-05T18:06:39.962Z",
    "size": 797564,
    "path": "../public/projects/Fragile/images/fragile_21.webp"
  },
  "/projects/Fragile/images/fragile_22.webp": {
    "type": "image/webp",
    "etag": "\"ebb4e-vRDjfT8pu53rs/EomyDYCLH4grQ\"",
    "mtime": "2026-05-05T18:08:56.670Z",
    "size": 965454,
    "path": "../public/projects/Fragile/images/fragile_22.webp"
  },
  "/projects/Fragile/images/fragile_3.webp": {
    "type": "image/webp",
    "etag": "\"af106-qcLKTDkULmajCToxcE4Jd46oATM\"",
    "mtime": "2026-05-05T18:06:40.996Z",
    "size": 717062,
    "path": "../public/projects/Fragile/images/fragile_3.webp"
  },
  "/projects/Fragile/images/fragile_4.webp": {
    "type": "image/webp",
    "etag": "\"82b36-+d11dmrbyE/K1tLavMPUxCTUKbg\"",
    "mtime": "2026-05-05T18:06:41.277Z",
    "size": 535350,
    "path": "../public/projects/Fragile/images/fragile_4.webp"
  },
  "/projects/Freudenberg-Renders/images/493908234_section.webp": {
    "type": "image/webp",
    "etag": "\"1d8c6-uyo64yVMIUO60W/eNNLNrjr7LkE\"",
    "mtime": "2026-05-03T22:36:41.689Z",
    "size": 121030,
    "path": "../public/projects/Freudenberg-Renders/images/493908234_section.webp"
  },
  "/projects/Fragile/images/fragile_5.webp": {
    "type": "image/webp",
    "etag": "\"ce2ba-eLyPezuxyevuUubr+UEKlPuiOfU\"",
    "mtime": "2026-05-05T18:06:41.597Z",
    "size": 844474,
    "path": "../public/projects/Fragile/images/fragile_5.webp"
  },
  "/projects/Fragile/images/fragile_6.webp": {
    "type": "image/webp",
    "etag": "\"c2db6-9uR4B6RqqANaXzRSWI5VeYme3iI\"",
    "mtime": "2026-05-05T18:06:41.919Z",
    "size": 798134,
    "path": "../public/projects/Fragile/images/fragile_6.webp"
  },
  "/projects/Freudenberg-Renders/images/496368201.webp": {
    "type": "image/webp",
    "etag": "\"2aeda-eI7oOUg01Te0EDZhSjNxkvMkdBw\"",
    "mtime": "2026-05-03T22:36:41.689Z",
    "size": 175834,
    "path": "../public/projects/Freudenberg-Renders/images/496368201.webp"
  },
  "/projects/Freudenberg-Renders/images/a3_section.webp": {
    "type": "image/webp",
    "etag": "\"5a54c-9YvynffO5zzRlV4Lr9xqE6YrLak\"",
    "mtime": "2026-05-03T22:36:41.690Z",
    "size": 369996,
    "path": "../public/projects/Freudenberg-Renders/images/a3_section.webp"
  },
  "/projects/Fragile/images/fragile_7.webp": {
    "type": "image/webp",
    "etag": "\"c6b14-1CwRNB4wRPkZE4vkOeuoEkb2qC4\"",
    "mtime": "2026-05-05T18:06:42.235Z",
    "size": 813844,
    "path": "../public/projects/Fragile/images/fragile_7.webp"
  },
  "/projects/Fragile/images/fragile_8.webp": {
    "type": "image/webp",
    "etag": "\"9734a-VVwitH0P6p/wXo1lsAyPahLgHzI\"",
    "mtime": "2026-05-05T18:06:42.528Z",
    "size": 619338,
    "path": "../public/projects/Fragile/images/fragile_8.webp"
  },
  "/projects/Fragile/images/fragile_9.webp": {
    "type": "image/webp",
    "etag": "\"acb36-Qw3XnyufMDO50aW+nuffujOGojg\"",
    "mtime": "2026-05-05T18:06:42.828Z",
    "size": 707382,
    "path": "../public/projects/Fragile/images/fragile_9.webp"
  },
  "/projects/Freudenberg-Renders/images/Aover.webp": {
    "type": "image/webp",
    "etag": "\"6cb84-2Tjl9hRdZ1AbD51LSZGeMAhL3+4\"",
    "mtime": "2026-05-03T22:36:41.689Z",
    "size": 445316,
    "path": "../public/projects/Freudenberg-Renders/images/Aover.webp"
  },
  "/projects/Freudenberg-Renders/images/49347758_section.webp": {
    "type": "image/webp",
    "etag": "\"cd968-yE8lLgixleS3m8Sk0A16a3Ii9pg\"",
    "mtime": "2026-05-03T22:36:41.689Z",
    "size": 842088,
    "path": "../public/projects/Freudenberg-Renders/images/49347758_section.webp"
  },
  "/projects/Freudenberg-Renders/images/49390834_section.webp": {
    "type": "image/webp",
    "etag": "\"b7cfc-Zt6F8ieI+I1fLBVV2y/qUp5dIfc\"",
    "mtime": "2026-05-03T22:36:41.689Z",
    "size": 752892,
    "path": "../public/projects/Freudenberg-Renders/images/49390834_section.webp"
  },
  "/projects/Freudenberg-Renders/images/guarn1_section.webp": {
    "type": "image/webp",
    "etag": "\"93d74-K1ziaPHSpJlsL9tXuCUOmHA25lE\"",
    "mtime": "2026-05-03T22:36:41.690Z",
    "size": 605556,
    "path": "../public/projects/Freudenberg-Renders/images/guarn1_section.webp"
  },
  "/projects/Freudenberg-Renders/images/guarn1.webp": {
    "type": "image/webp",
    "etag": "\"de318-q7gZN0afhCTKlj29DPQl1B/GtEA\"",
    "mtime": "2026-05-03T22:36:41.690Z",
    "size": 910104,
    "path": "../public/projects/Freudenberg-Renders/images/guarn1.webp"
  },
  "/projects/Freudenberg-Renders/images/49347758.webp": {
    "type": "image/webp",
    "etag": "\"12f182-TAIqHqqiVNA/56XxkLmL7ni+lks\"",
    "mtime": "2026-05-03T22:36:41.689Z",
    "size": 1241474,
    "path": "../public/projects/Freudenberg-Renders/images/49347758.webp"
  },
  "/projects/Freudenberg-Renders/images/a2.webp": {
    "type": "image/webp",
    "etag": "\"10a220-KA4RnqrN6Lub8YPaz3YVr+Q2E64\"",
    "mtime": "2026-05-03T22:36:41.690Z",
    "size": 1090080,
    "path": "../public/projects/Freudenberg-Renders/images/a2.webp"
  },
  "/projects/HeySport-Reels/images/heysport_01.webp": {
    "type": "image/webp",
    "etag": "\"606f6-r0JSNeuWVkZYFIVt4NRmsxByeZE\"",
    "mtime": "2026-05-03T22:36:41.690Z",
    "size": 394998,
    "path": "../public/projects/HeySport-Reels/images/heysport_01.webp"
  },
  "/projects/HeySport-Reels/images/heysport_010.webp": {
    "type": "image/webp",
    "etag": "\"64460-6CkyY4BBD7IWpMIbBFpr6tgeTVc\"",
    "mtime": "2026-05-03T22:36:41.691Z",
    "size": 410720,
    "path": "../public/projects/HeySport-Reels/images/heysport_010.webp"
  },
  "/projects/HeySport-Reels/images/heysport_011.webp": {
    "type": "image/webp",
    "etag": "\"589c0-W3YI/M8QGruu1xhi0Rj795uunb0\"",
    "mtime": "2026-05-03T22:36:41.691Z",
    "size": 362944,
    "path": "../public/projects/HeySport-Reels/images/heysport_011.webp"
  },
  "/projects/HeySport-Reels/images/heysport_012.webp": {
    "type": "image/webp",
    "etag": "\"4c608-j1qx1+KLIkLq6F3JywyszNKCnjc\"",
    "mtime": "2026-05-03T22:36:41.691Z",
    "size": 312840,
    "path": "../public/projects/HeySport-Reels/images/heysport_012.webp"
  },
  "/projects/HeySport-Reels/images/ASMR-Gara.mp4": {
    "type": "video/mp4",
    "etag": "\"18052d-rXgJ0YWp1nUsatulWp9j4eltSU8\"",
    "mtime": "2026-05-03T22:42:29.388Z",
    "size": 1574189,
    "path": "../public/projects/HeySport-Reels/images/ASMR-Gara.mp4"
  },
  "/projects/HeySport-Reels/images/heysport_013.webp": {
    "type": "image/webp",
    "etag": "\"6271c-0TwhPM6jljkKLn9rSUE2tFVNcKA\"",
    "mtime": "2026-05-03T22:36:41.691Z",
    "size": 403228,
    "path": "../public/projects/HeySport-Reels/images/heysport_013.webp"
  },
  "/projects/HeySport-Reels/images/heysport_014.webp": {
    "type": "image/webp",
    "etag": "\"53190-7knr5W88gE1OrtkiSbxYKsC10dY\"",
    "mtime": "2026-05-03T22:36:41.691Z",
    "size": 340368,
    "path": "../public/projects/HeySport-Reels/images/heysport_014.webp"
  },
  "/projects/HeySport-Reels/images/heysport_016.webp": {
    "type": "image/webp",
    "etag": "\"67cf6-/kza/tk1yeznJiSCQ5VX5WHunrE\"",
    "mtime": "2026-05-03T22:36:41.691Z",
    "size": 425206,
    "path": "../public/projects/HeySport-Reels/images/heysport_016.webp"
  },
  "/projects/HeySport-Reels/images/Dettagli-B2B-3.mp4": {
    "type": "video/mp4",
    "etag": "\"1bfeae-FK2hrvkrc0KKIeeL0LaP103HP/k\"",
    "mtime": "2026-05-03T22:42:29.388Z",
    "size": 1834670,
    "path": "../public/projects/HeySport-Reels/images/Dettagli-B2B-3.mp4"
  },
  "/projects/HeySport-Reels/images/heysport_017.webp": {
    "type": "image/webp",
    "etag": "\"5b9f2-UxX26J0JpyiOPqCV+Vah7rstGdM\"",
    "mtime": "2026-05-03T22:36:41.691Z",
    "size": 375282,
    "path": "../public/projects/HeySport-Reels/images/heysport_017.webp"
  },
  "/projects/HeySport-Reels/images/heysport_02.webp": {
    "type": "image/webp",
    "etag": "\"5cfb8-NDqpnDKzoUVtdACyLJ21gpQSBk8\"",
    "mtime": "2026-05-03T22:36:41.691Z",
    "size": 380856,
    "path": "../public/projects/HeySport-Reels/images/heysport_02.webp"
  },
  "/projects/HeySport-Reels/images/heysport_03.webp": {
    "type": "image/webp",
    "etag": "\"67386-rBzBNlOpgx1LaPwGzXgAs3rEXkk\"",
    "mtime": "2026-05-03T22:36:41.691Z",
    "size": 422790,
    "path": "../public/projects/HeySport-Reels/images/heysport_03.webp"
  },
  "/projects/HeySport-Reels/images/heysport_04.webp": {
    "type": "image/webp",
    "etag": "\"55a22-X2wi6T49IKBPIyOntHQC9XD2hlI\"",
    "mtime": "2026-05-03T22:36:41.691Z",
    "size": 350754,
    "path": "../public/projects/HeySport-Reels/images/heysport_04.webp"
  },
  "/projects/HeySport-Reels/images/heysport_05.webp": {
    "type": "image/webp",
    "etag": "\"53f0a-n8wvHxgKg69UWMTZt0vPu/WAjpg\"",
    "mtime": "2026-05-03T22:36:41.691Z",
    "size": 343818,
    "path": "../public/projects/HeySport-Reels/images/heysport_05.webp"
  },
  "/projects/HeySport-Reels/images/heysport_06.webp": {
    "type": "image/webp",
    "etag": "\"59c0e-RPYxbWcwY5PEmt+MiOS9gXDuTcc\"",
    "mtime": "2026-05-03T22:36:41.691Z",
    "size": 367630,
    "path": "../public/projects/HeySport-Reels/images/heysport_06.webp"
  },
  "/projects/HeySport-Reels/images/Dettagli-B2B.mp4": {
    "type": "video/mp4",
    "etag": "\"1c9d2a-o8imehKVv8KNbb1hSI3/sVTe1MM\"",
    "mtime": "2026-05-03T22:42:29.388Z",
    "size": 1875242,
    "path": "../public/projects/HeySport-Reels/images/Dettagli-B2B.mp4"
  },
  "/projects/HeySport-Reels/images/heysport_08.webp": {
    "type": "image/webp",
    "etag": "\"5231c-QuTw7frJNpBwrHFUlydTp/k2x6k\"",
    "mtime": "2026-05-03T22:36:41.691Z",
    "size": 336668,
    "path": "../public/projects/HeySport-Reels/images/heysport_08.webp"
  },
  "/projects/HeySport-Reels/images/Gara.mp4": {
    "type": "video/mp4",
    "etag": "\"2eec86-vu+Twn6LTEsQ5cron9K25+5pt0A\"",
    "mtime": "2026-05-03T22:42:29.388Z",
    "size": 3075206,
    "path": "../public/projects/HeySport-Reels/images/Gara.mp4"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-15.webp": {
    "type": "image/webp",
    "etag": "\"7970c-g+nA9U0HNXzb8hGi8q9BcFZM1zU\"",
    "mtime": "2026-05-03T22:36:41.698Z",
    "size": 497420,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-15.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-12.webp": {
    "type": "image/webp",
    "etag": "\"f20d0-+PclaFDjDG+aJ4PlyAvNxAPivoc\"",
    "mtime": "2026-05-03T22:36:41.697Z",
    "size": 991440,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-12.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-11.webp": {
    "type": "image/webp",
    "etag": "\"d20cc-HzbKtuvIeuoG3yZVfUNtoUnzmR4\"",
    "mtime": "2026-05-03T22:36:41.697Z",
    "size": 860364,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-11.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-1.webp": {
    "type": "image/webp",
    "etag": "\"15e5e8-QjU6Sow78cCCVkpKvT1KPjGO36w\"",
    "mtime": "2026-05-03T22:36:41.697Z",
    "size": 1435112,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-1.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-10.webp": {
    "type": "image/webp",
    "etag": "\"110d24-3oOwZysr64EGDTX5XPDWH5hKfQY\"",
    "mtime": "2026-05-03T22:36:41.697Z",
    "size": 1117476,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-10.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-14.webp": {
    "type": "image/webp",
    "etag": "\"12fdc8-8jt/aFAMc7tOULQGr0RE1+AC/KE\"",
    "mtime": "2026-05-03T22:36:41.698Z",
    "size": 1244616,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-14.webp"
  },
  "/projects/HeySport-Reels/images/Mood.mp4": {
    "type": "video/mp4",
    "etag": "\"2053d6-VAXFeabJWrfYoKE5BBwaloqzMQY\"",
    "mtime": "2026-05-03T22:42:29.388Z",
    "size": 2118614,
    "path": "../public/projects/HeySport-Reels/images/Mood.mp4"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-18.webp": {
    "type": "image/webp",
    "etag": "\"c2a6e-CO3PFNMzo7RJZx4EOWpfEJfZABE\"",
    "mtime": "2026-05-03T22:36:41.698Z",
    "size": 797294,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-18.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-13.webp": {
    "type": "image/webp",
    "etag": "\"11fd7e-9cqeIi+nNx0tOTGDGjibLpFkrBs\"",
    "mtime": "2026-05-03T22:36:41.697Z",
    "size": 1179006,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-13.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-19.webp": {
    "type": "image/webp",
    "etag": "\"d1004-UUix6a7zzmHVsKxl9coXvw+bags\"",
    "mtime": "2026-05-03T22:36:41.698Z",
    "size": 856068,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-19.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-2.webp": {
    "type": "image/webp",
    "etag": "\"e4f0c-ZRRQfrqosFJY/xH13NDYWl8BvE0\"",
    "mtime": "2026-05-03T22:36:41.698Z",
    "size": 937740,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-2.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-20.webp": {
    "type": "image/webp",
    "etag": "\"d3caa-esuSEq/XbiWz11VLbSdHGzCYzic\"",
    "mtime": "2026-05-03T22:36:41.698Z",
    "size": 867498,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-20.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-21.webp": {
    "type": "image/webp",
    "etag": "\"d5194-tJVWtYNf+wXrscZMFvfhxRwcDZs\"",
    "mtime": "2026-05-03T22:36:41.698Z",
    "size": 872852,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-21.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-22.webp": {
    "type": "image/webp",
    "etag": "\"c3b18-nK7+CRpcEl02eeRPj1ZGvJ6LrCw\"",
    "mtime": "2026-05-03T22:36:41.698Z",
    "size": 801560,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-22.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-16.webp": {
    "type": "image/webp",
    "etag": "\"cc71c-JI0TTe5uSkLr95VgpLzKHQL4Dtk\"",
    "mtime": "2026-05-03T22:36:41.698Z",
    "size": 837404,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-16.webp"
  },
  "/projects/HeySport-Reels/images/TutaRossa-Prep.mp4": {
    "type": "video/mp4",
    "etag": "\"206ea8-xqesk2XMID5wxPnDchVrojQH+Uw\"",
    "mtime": "2026-05-03T22:42:29.388Z",
    "size": 2125480,
    "path": "../public/projects/HeySport-Reels/images/TutaRossa-Prep.mp4"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-25.webp": {
    "type": "image/webp",
    "etag": "\"ed506-IP0bEFZvi8yZD/vvFeau10IliJI\"",
    "mtime": "2026-05-03T22:36:41.699Z",
    "size": 972038,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-25.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-27.webp": {
    "type": "image/webp",
    "etag": "\"bd06c-pho62zOiZt1Rkyo0wHsMHXkF0Pg\"",
    "mtime": "2026-05-03T22:36:41.699Z",
    "size": 774252,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-27.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-26.webp": {
    "type": "image/webp",
    "etag": "\"f4fa6-dWK4Jzubr24Tih7DP40zeHYicTc\"",
    "mtime": "2026-05-03T22:36:41.699Z",
    "size": 1003430,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-26.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-17.webp": {
    "type": "image/webp",
    "etag": "\"12ac68-K52d3V9b4QjvalQNnc5TrY+y+tw\"",
    "mtime": "2026-05-03T22:36:41.698Z",
    "size": 1223784,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-17.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-24.webp": {
    "type": "image/webp",
    "etag": "\"12be24-ebhHas4odEkLXDnTjlGXEfu0cn0\"",
    "mtime": "2026-05-03T22:36:41.699Z",
    "size": 1228324,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-24.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-23.webp": {
    "type": "image/webp",
    "etag": "\"11a106-7WdL7xOlbpWddhS8LwE2OrydaeA\"",
    "mtime": "2026-05-03T22:36:41.698Z",
    "size": 1155334,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-23.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-30.webp": {
    "type": "image/webp",
    "etag": "\"d239a-Yl4iKi3oO7C6SOYB65HFCgy9Z9Y\"",
    "mtime": "2026-05-03T22:36:41.699Z",
    "size": 861082,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-30.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-28.webp": {
    "type": "image/webp",
    "etag": "\"144630-ly6EjeBziYFtVsVEQr3nsPqWHvo\"",
    "mtime": "2026-05-03T22:36:41.699Z",
    "size": 1328688,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-28.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-29.webp": {
    "type": "image/webp",
    "etag": "\"100898-OEJsx6xzASBMCltQT0JriJw3dNI\"",
    "mtime": "2026-05-03T22:36:41.699Z",
    "size": 1050776,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-29.webp"
  },
  "/projects/Macello-Castle-VFX/images/VFX_00.webp": {
    "type": "image/webp",
    "etag": "\"79ffe-NLz/R73zQfnluvl45pHreeQcQVE\"",
    "mtime": "2026-05-03T22:36:41.692Z",
    "size": 499710,
    "path": "../public/projects/Macello-Castle-VFX/images/VFX_00.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-3.webp": {
    "type": "image/webp",
    "etag": "\"116080-+v9tnVvmZnQulwPrjTY7EtiBtw8\"",
    "mtime": "2026-05-03T22:36:41.699Z",
    "size": 1138816,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-3.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_120.webp": {
    "type": "image/webp",
    "etag": "\"6cce2-OVkF14mhKH6UldnNw5sS4c7NU5g\"",
    "mtime": "2026-04-19T20:03:35.284Z",
    "size": 445666,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_120.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_121.webp": {
    "type": "image/webp",
    "etag": "\"63ae0-ZCQjU14Xy26K7Rwuc+M7fyRRqXE\"",
    "mtime": "2026-04-19T20:03:35.286Z",
    "size": 408288,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_121.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-4.webp": {
    "type": "image/webp",
    "etag": "\"17dd44-TzbMmLIl0vNfeauFTppE33ubQzI\"",
    "mtime": "2026-05-03T22:36:41.699Z",
    "size": 1563972,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-4.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-8.webp": {
    "type": "image/webp",
    "etag": "\"b5096-5yX+0Yk29uSeILyAyEB1p3h1sek\"",
    "mtime": "2026-05-03T22:36:41.700Z",
    "size": 741526,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-8.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-9.webp": {
    "type": "image/webp",
    "etag": "\"c8814-6Lce9BRGhIZ2d/J7K8JQdAmJOVc\"",
    "mtime": "2026-05-03T22:36:41.700Z",
    "size": 821268,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-9.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-5.webp": {
    "type": "image/webp",
    "etag": "\"10041e-P3YMtC4qRCT+W7s1a11dmx/uJtY\"",
    "mtime": "2026-05-03T22:36:41.699Z",
    "size": 1049630,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-5.webp"
  },
  "/projects/Macello-Castle-VFX/images/VFX_03.webp": {
    "type": "image/webp",
    "etag": "\"e42ec-TKrvjSAviaomKdH3yJhh5nxD0K8\"",
    "mtime": "2026-05-03T22:36:41.692Z",
    "size": 934636,
    "path": "../public/projects/Macello-Castle-VFX/images/VFX_03.webp"
  },
  "/projects/HeySport-Reels/images/Paganella-Prep.mp4": {
    "type": "video/mp4",
    "etag": "\"483428-0XGEEoKjQAOsYcAtxcJ0MKK8g7I\"",
    "mtime": "2026-05-03T22:42:29.388Z",
    "size": 4731944,
    "path": "../public/projects/HeySport-Reels/images/Paganella-Prep.mp4"
  },
  "/projects/Martina_Pace/images/test_canon_c50_01.webp": {
    "type": "image/webp",
    "etag": "\"d9a2e-E9NN9hWHpAqk7XLa4m7pBOLtpJw\"",
    "mtime": "2026-04-19T20:03:35.275Z",
    "size": 891438,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_01.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_130.webp": {
    "type": "image/webp",
    "etag": "\"7b3e4-GKNE4bUP17MZIWrlhskxFrrzKJI\"",
    "mtime": "2026-04-19T20:03:35.289Z",
    "size": 504804,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_130.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_113.webp": {
    "type": "image/webp",
    "etag": "\"c182e-mXC62CAO59SURnZvz/O4ZUew3/g\"",
    "mtime": "2026-04-19T20:03:35.278Z",
    "size": 792622,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_113.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_134.webp": {
    "type": "image/webp",
    "etag": "\"7b316-TIHbDYiO7t97rXYYzh/qQPULpsE\"",
    "mtime": "2026-04-19T20:03:35.292Z",
    "size": 504598,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_134.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_115.webp": {
    "type": "image/webp",
    "etag": "\"ad01a-ihEfOCO1WAFzUzdvcLJo+xSOcmw\"",
    "mtime": "2026-04-19T20:03:35.280Z",
    "size": 708634,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_115.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_118.webp": {
    "type": "image/webp",
    "etag": "\"85c60-R4+aCXR/UY9aKrV/ShJbrqDFEAU\"",
    "mtime": "2026-04-19T20:03:35.282Z",
    "size": 547936,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_118.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_126.webp": {
    "type": "image/webp",
    "etag": "\"80dc6-WNfopw7YlarzdPtenHgiv2P4fto\"",
    "mtime": "2026-04-19T20:03:35.288Z",
    "size": 527814,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_126.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-6.webp": {
    "type": "image/webp",
    "etag": "\"12c554-BQAkyiH3/cE9dW95f/mFY/2D3oM\"",
    "mtime": "2026-05-03T22:36:41.699Z",
    "size": 1230164,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-6.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-7.webp": {
    "type": "image/webp",
    "etag": "\"14d076-TOClymiNaQY6QipgRM7znU5tqmo\"",
    "mtime": "2026-05-03T22:36:41.700Z",
    "size": 1364086,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-7.webp"
  },
  "/projects/Macello-Castle-VFX/images/VFX_02.webp": {
    "type": "image/webp",
    "etag": "\"17799e-ldP5mF2Mu31n/lyJQ/p6mY8OAP4\"",
    "mtime": "2026-05-03T22:36:41.692Z",
    "size": 1538462,
    "path": "../public/projects/Macello-Castle-VFX/images/VFX_02.webp"
  },
  "/projects/Macello-Castle-VFX/images/VFX_01.webp": {
    "type": "image/webp",
    "etag": "\"18713a-2mCdtqFDX3ni7LDjFJ4qGD/J1s0\"",
    "mtime": "2026-05-03T22:36:41.692Z",
    "size": 1601850,
    "path": "../public/projects/Macello-Castle-VFX/images/VFX_01.webp"
  },
  "/projects/HeySport-Reels/images/Vialattea-PrepAction.mp4": {
    "type": "video/mp4",
    "etag": "\"502bb2-3GpwEu0/7zSu2Y1unZm///GKVig\"",
    "mtime": "2026-05-03T22:42:29.388Z",
    "size": 5254066,
    "path": "../public/projects/HeySport-Reels/images/Vialattea-PrepAction.mp4"
  },
  "/projects/Martina_Pace/images/test_canon_c50_22.webp": {
    "type": "image/webp",
    "etag": "\"66bca-mett2a23x9ggLFkI8E3WUy0mDQU\"",
    "mtime": "2026-04-19T20:03:35.295Z",
    "size": 420810,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_22.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_135.webp": {
    "type": "image/webp",
    "etag": "\"91400-TQ9bfCyrsDT/pQS06Vb+1BOKkK0\"",
    "mtime": "2026-04-19T20:03:35.294Z",
    "size": 594944,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_135.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_26.webp": {
    "type": "image/webp",
    "etag": "\"8f874-pcj/tIfDNN4Gz6zttKv0qznymG0\"",
    "mtime": "2026-04-19T20:03:35.298Z",
    "size": 587892,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_26.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_36.webp": {
    "type": "image/webp",
    "etag": "\"809d2-Di5NsnMibQEGORdih/vhkmcZwtA\"",
    "mtime": "2026-04-19T20:03:35.300Z",
    "size": 526802,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_36.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_89.webp": {
    "type": "image/webp",
    "etag": "\"59906-px8XU4FY7f3VJIl6owsFX1PPgiU\"",
    "mtime": "2026-04-19T20:03:35.318Z",
    "size": 366854,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_89.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_93.webp": {
    "type": "image/webp",
    "etag": "\"7530a-JW/yNQVqPOj+6S7lNYyrgRixVoQ\"",
    "mtime": "2026-04-19T20:03:35.321Z",
    "size": 480010,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_93.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_95.webp": {
    "type": "image/webp",
    "etag": "\"7bfba-bPhHB+xNZ7dleFTdyLWwG4wBeN0\"",
    "mtime": "2026-04-19T20:03:35.322Z",
    "size": 507834,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_95.webp"
  },
  "/projects/Merlo-e-Worker-ADVs/images/merlo_01.webp": {
    "type": "image/webp",
    "etag": "\"27528-3nCLuQaeMPwR4sn8uykBb5U6EG0\"",
    "mtime": "2026-05-03T22:36:41.692Z",
    "size": 161064,
    "path": "../public/projects/Merlo-e-Worker-ADVs/images/merlo_01.webp"
  },
  "/projects/Merlo-e-Worker-ADVs/images/merlo_03.webp": {
    "type": "image/webp",
    "etag": "\"2341e-EpK7TYMw7XMNYNxODsIDUPowRUw\"",
    "mtime": "2026-05-03T22:36:41.692Z",
    "size": 144414,
    "path": "../public/projects/Merlo-e-Worker-ADVs/images/merlo_03.webp"
  },
  "/projects/Merlo-e-Worker-ADVs/images/merlo_02.webp": {
    "type": "image/webp",
    "etag": "\"2d3e4-oLUf6Zf5jwrmZlwQjjtgoBRwR0Y\"",
    "mtime": "2026-05-03T22:36:41.692Z",
    "size": 185316,
    "path": "../public/projects/Merlo-e-Worker-ADVs/images/merlo_02.webp"
  },
  "/projects/Merlo-e-Worker-ADVs/images/merlo_05.webp": {
    "type": "image/webp",
    "etag": "\"2f26c-GM6KZrbWQsrFeSA5udcH4dwHJMg\"",
    "mtime": "2026-05-03T22:36:41.693Z",
    "size": 193132,
    "path": "../public/projects/Merlo-e-Worker-ADVs/images/merlo_05.webp"
  },
  "/projects/Merlo-e-Worker-ADVs/images/merlo_04.webp": {
    "type": "image/webp",
    "etag": "\"3af4a-23mdjB2R16n6sd0yU7xqlhrEP5s\"",
    "mtime": "2026-05-03T22:36:41.693Z",
    "size": 241482,
    "path": "../public/projects/Merlo-e-Worker-ADVs/images/merlo_04.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_37.webp": {
    "type": "image/webp",
    "etag": "\"91764-HLuoXLGMUhxvQVjhpVS5aKTDKPM\"",
    "mtime": "2026-04-19T20:03:35.302Z",
    "size": 595812,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_37.webp"
  },
  "/projects/Merlo-e-Worker-ADVs/images/merlo_06.webp": {
    "type": "image/webp",
    "etag": "\"3a916-26RIW1P7tpe34cv0suv3MZY/euI\"",
    "mtime": "2026-05-03T22:36:41.693Z",
    "size": 239894,
    "path": "../public/projects/Merlo-e-Worker-ADVs/images/merlo_06.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_43.webp": {
    "type": "image/webp",
    "etag": "\"85880-XHykGS5aMJEtIKzoJIFKKN6d1U0\"",
    "mtime": "2026-04-19T20:03:35.305Z",
    "size": 546944,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_43.webp"
  },
  "/projects/Merlo-e-Worker-ADVs/images/merlo_07.webp": {
    "type": "image/webp",
    "etag": "\"1c1c8-Gfz5ug0V+VhNzUITwNDvwUsXGIU\"",
    "mtime": "2026-05-03T22:36:41.693Z",
    "size": 115144,
    "path": "../public/projects/Merlo-e-Worker-ADVs/images/merlo_07.webp"
  },
  "/projects/Merlo-e-Worker-ADVs/images/merlo_08.webp": {
    "type": "image/webp",
    "etag": "\"2c78e-rGuau8AsgcO3gaimgW4unFEN06E\"",
    "mtime": "2026-05-03T22:36:41.693Z",
    "size": 182158,
    "path": "../public/projects/Merlo-e-Worker-ADVs/images/merlo_08.webp"
  },
  "/projects/Merlo-e-Worker-ADVs/images/merlo_09.webp": {
    "type": "image/webp",
    "etag": "\"16ccc-kLlF9U97/EjeeGfPNLaqIV3DuYs\"",
    "mtime": "2026-05-03T22:36:41.693Z",
    "size": 93388,
    "path": "../public/projects/Merlo-e-Worker-ADVs/images/merlo_09.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_76.webp": {
    "type": "image/webp",
    "etag": "\"9229c-P7H5M6Zx0Ha6460TWd9xE9rMZYU\"",
    "mtime": "2026-04-19T20:03:35.314Z",
    "size": 598684,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_76.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_60.webp": {
    "type": "image/webp",
    "etag": "\"d4d24-SWWn/w6bqijE3tcicxDZ92KJSs8\"",
    "mtime": "2026-04-19T20:03:35.312Z",
    "size": 871716,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_60.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_79.webp": {
    "type": "image/webp",
    "etag": "\"a23f6-JyhuHVBx81YlD2/eZQ+tJk4/V68\"",
    "mtime": "2026-04-19T20:03:35.316Z",
    "size": 664566,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_79.webp"
  },
  "/projects/My-Lamination/images/convert_webp.bat": {
    "type": "application/x-msdownload",
    "etag": "\"46-KHZ7Umv89lb8Pey7AxUXqwOEn4U\"",
    "mtime": "2026-05-03T22:36:41.694Z",
    "size": 70,
    "path": "../public/projects/My-Lamination/images/convert_webp.bat"
  },
  "/projects/Martina_Pace/images/test_canon_c50_46.webp": {
    "type": "image/webp",
    "etag": "\"10e000-Z2nprXbdQX17ETUtM/yLgG18SAg\"",
    "mtime": "2026-04-19T20:03:35.309Z",
    "size": 1105920,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_46.webp"
  },
  "/projects/My-Lamination/images/MyLamination-1.webp": {
    "type": "image/webp",
    "etag": "\"58b2e-WTFK5JUre8yCt3dSu8S56eMf2yU\"",
    "mtime": "2026-05-03T22:36:41.693Z",
    "size": 363310,
    "path": "../public/projects/My-Lamination/images/MyLamination-1.webp"
  },
  "/projects/My-Lamination/images/MyLamination-11.webp": {
    "type": "image/webp",
    "etag": "\"70338-652I6I6ZnUdcmWcfY1IVaFqLDl0\"",
    "mtime": "2026-05-03T22:36:41.693Z",
    "size": 459576,
    "path": "../public/projects/My-Lamination/images/MyLamination-11.webp"
  },
  "/projects/My-Lamination/images/MyLamination-13.webp": {
    "type": "image/webp",
    "etag": "\"4bd18-4GdOmbYhtEPpgVUuGUP/IS8eXFw\"",
    "mtime": "2026-05-03T22:36:41.693Z",
    "size": 310552,
    "path": "../public/projects/My-Lamination/images/MyLamination-13.webp"
  },
  "/projects/My-Lamination/images/MyLamination-14.webp": {
    "type": "image/webp",
    "etag": "\"77cc6-HxccVLA5RL7zJNE6tSqrbfCdPQU\"",
    "mtime": "2026-05-03T22:36:41.693Z",
    "size": 490694,
    "path": "../public/projects/My-Lamination/images/MyLamination-14.webp"
  },
  "/projects/My-Lamination/images/MyLamination-15.webp": {
    "type": "image/webp",
    "etag": "\"68926-Or7sTcnb+Tjg+46STOZE/xnF+9U\"",
    "mtime": "2026-05-03T22:36:41.694Z",
    "size": 428326,
    "path": "../public/projects/My-Lamination/images/MyLamination-15.webp"
  },
  "/projects/My-Lamination/images/MyLamination-16.webp": {
    "type": "image/webp",
    "etag": "\"692e2-n89H2EevVHSm7t9JVTdSZl85jdY\"",
    "mtime": "2026-05-03T22:36:41.694Z",
    "size": 430818,
    "path": "../public/projects/My-Lamination/images/MyLamination-16.webp"
  },
  "/projects/My-Lamination/images/MyLamination-3.webp": {
    "type": "image/webp",
    "etag": "\"541a2-XSYi6v1KvxHA8QCQHuu5KxuWXk8\"",
    "mtime": "2026-05-03T22:36:41.694Z",
    "size": 344482,
    "path": "../public/projects/My-Lamination/images/MyLamination-3.webp"
  },
  "/projects/My-Lamination/images/MyLamination-5.webp": {
    "type": "image/webp",
    "etag": "\"6c030-2uK9v32sZ5Vnlijt+gZw3PvRZ6k\"",
    "mtime": "2026-05-03T22:36:41.694Z",
    "size": 442416,
    "path": "../public/projects/My-Lamination/images/MyLamination-5.webp"
  },
  "/projects/My-Lamination/images/MyLamination-6.webp": {
    "type": "image/webp",
    "etag": "\"53f9e-IIziVdMrfGIJrdLM2q2UWhOgLX0\"",
    "mtime": "2026-05-03T22:36:41.694Z",
    "size": 343966,
    "path": "../public/projects/My-Lamination/images/MyLamination-6.webp"
  },
  "/projects/My-Lamination/images/MyLamination-7.webp": {
    "type": "image/webp",
    "etag": "\"55c7c-TNgMbXxNYlQEgxate91wTTkX6ic\"",
    "mtime": "2026-05-03T22:36:41.694Z",
    "size": 351356,
    "path": "../public/projects/My-Lamination/images/MyLamination-7.webp"
  },
  "/projects/My-Lamination/images/MyLamination-9.webp": {
    "type": "image/webp",
    "etag": "\"75ad8-mGDrU5/21Ke2V3eNg1FeOZUiG1E\"",
    "mtime": "2026-05-03T22:36:41.694Z",
    "size": 482008,
    "path": "../public/projects/My-Lamination/images/MyLamination-9.webp"
  },
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_1.webp": {
    "type": "image/webp",
    "etag": "\"59a08-zN+Pnj/4y3XrJZdkTupf2aJThwM\"",
    "mtime": "2026-05-05T21:45:45.962Z",
    "size": 367112,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_1.webp"
  },
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_10.webp": {
    "type": "image/webp",
    "etag": "\"790fa-dlmcVAwT6FdGdAfxDgeNsLfkbJQ\"",
    "mtime": "2026-05-05T21:45:42.414Z",
    "size": 495866,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_10.webp"
  },
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_13.webp": {
    "type": "image/webp",
    "etag": "\"65c98-llWO0lyGevMk/gvVd4X8xSHwYD0\"",
    "mtime": "2026-05-05T21:45:43.297Z",
    "size": 416920,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_13.webp"
  },
  "/projects/My-Lamination/images/MyLamination-17.webp": {
    "type": "image/webp",
    "etag": "\"810f0-zzUCVidI8S/1Mv6whWrJ5Opej1g\"",
    "mtime": "2026-05-03T22:36:41.694Z",
    "size": 528624,
    "path": "../public/projects/My-Lamination/images/MyLamination-17.webp"
  },
  "/projects/My-Lamination/images/MyLamination-19.webp": {
    "type": "image/webp",
    "etag": "\"896bc-IRPADobx7Pyhs8Flfjwh8p0jI7M\"",
    "mtime": "2026-05-03T22:36:41.694Z",
    "size": 562876,
    "path": "../public/projects/My-Lamination/images/MyLamination-19.webp"
  },
  "/projects/My-Lamination/images/MyLamination-8.webp": {
    "type": "image/webp",
    "etag": "\"84b26-TRkZHm5RY+0n0iDIBN+SEiRnFko\"",
    "mtime": "2026-05-03T22:36:41.694Z",
    "size": 543526,
    "path": "../public/projects/My-Lamination/images/MyLamination-8.webp"
  },
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_11.webp": {
    "type": "image/webp",
    "etag": "\"bee6c-sgGLeW8qKSvFIvcU8a8nJ2hiGb4\"",
    "mtime": "2026-05-05T21:45:42.700Z",
    "size": 781932,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_11.webp"
  },
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_12.webp": {
    "type": "image/webp",
    "etag": "\"9f072-85pO+SShlLqHMnqytZ6KUfIWrxo\"",
    "mtime": "2026-05-05T21:45:43.058Z",
    "size": 651378,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_12.webp"
  },
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_15.webp": {
    "type": "image/webp",
    "etag": "\"966ac-oC2/SvUTq2boR4l0VRyt0eSwGyY\"",
    "mtime": "2026-05-05T21:45:43.815Z",
    "size": 616108,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_15.webp"
  },
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_14.webp": {
    "type": "image/webp",
    "etag": "\"c5ad0-mAYHhbfFuzYG7sLQiwDrdkJnrPA\"",
    "mtime": "2026-05-05T21:45:43.570Z",
    "size": 809680,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_14.webp"
  },
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_16.webp": {
    "type": "image/webp",
    "etag": "\"bff88-kyi2i7/3CLJQ5qTZCmZMVPRANdg\"",
    "mtime": "2026-05-05T21:45:44.073Z",
    "size": 786312,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_16.webp"
  },
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_17.webp": {
    "type": "image/webp",
    "etag": "\"cf8f6-wKYdlvMMvZDz1+VyTry3P/3GDaY\"",
    "mtime": "2026-05-05T21:45:44.331Z",
    "size": 850166,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_17.webp"
  },
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_18.webp": {
    "type": "image/webp",
    "etag": "\"bf8a6-ZIxDWaHLVmosB7F2y2zfY1BPBYc\"",
    "mtime": "2026-05-05T21:45:44.591Z",
    "size": 784550,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_18.webp"
  },
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_19.webp": {
    "type": "image/webp",
    "etag": "\"8e8ec-KZ8xgPSBLplhUwG/3xF2xmj41Vc\"",
    "mtime": "2026-05-05T21:45:44.826Z",
    "size": 583916,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_19.webp"
  },
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_2.webp": {
    "type": "image/webp",
    "etag": "\"9c8da-3NmvoBBeHGMPLSO0AwgzcRMk1+s\"",
    "mtime": "2026-05-05T21:45:46.203Z",
    "size": 641242,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_2.webp"
  },
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_20.webp": {
    "type": "image/webp",
    "etag": "\"87c28-zW9DNQCgN5+AnKS6BbAkNU0SArs\"",
    "mtime": "2026-05-05T21:45:45.058Z",
    "size": 556072,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_20.webp"
  },
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_21.webp": {
    "type": "image/webp",
    "etag": "\"947a6-A8pljk0RhmjDGITC096XzmpD/N0\"",
    "mtime": "2026-05-05T21:45:45.295Z",
    "size": 608166,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_21.webp"
  },
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_22.webp": {
    "type": "image/webp",
    "etag": "\"723a4-zHcAG45I9Pgor3Sw/VFdeS5/aII\"",
    "mtime": "2026-05-05T21:45:45.514Z",
    "size": 467876,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_22.webp"
  },
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_23.webp": {
    "type": "image/webp",
    "etag": "\"aeeee-H4AOHo/7dOgLDKfMaxJV2nL+1n0\"",
    "mtime": "2026-05-05T21:45:45.760Z",
    "size": 716526,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_23.webp"
  },
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_3.webp": {
    "type": "image/webp",
    "etag": "\"9d0e0-oe67DWCbmJUyXYpCqEFTAIE3GEk\"",
    "mtime": "2026-05-05T21:45:46.441Z",
    "size": 643296,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_3.webp"
  },
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_5.webp": {
    "type": "image/webp",
    "etag": "\"91e2a-6AeUDa87HD+wQZ6ha/UjWiiElBU\"",
    "mtime": "2026-05-05T21:45:46.914Z",
    "size": 597546,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_5.webp"
  },
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_4.webp": {
    "type": "image/webp",
    "etag": "\"9e5fc-yWiQBYT3amJPDgOqQcJ+lgiiYrs\"",
    "mtime": "2026-05-05T21:45:46.680Z",
    "size": 648700,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_4.webp"
  },
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_6.webp": {
    "type": "image/webp",
    "etag": "\"a33a6-wteMFqSoMNHPkCloLfX7qYSMh9s\"",
    "mtime": "2026-05-05T21:45:47.156Z",
    "size": 668582,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_6.webp"
  },
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_7.webp": {
    "type": "image/webp",
    "etag": "\"9c282-YI5h8x9aBnqwt0CSSpxcDt58WwU\"",
    "mtime": "2026-05-05T21:45:47.394Z",
    "size": 639618,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_7.webp"
  },
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_8.webp": {
    "type": "image/webp",
    "etag": "\"a3f92-8XNUQkEC/RhmsBn6az5cE9ILMEM\"",
    "mtime": "2026-05-05T21:45:47.633Z",
    "size": 671634,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_8.webp"
  },
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_9.webp": {
    "type": "image/webp",
    "etag": "\"bfd72-P3us9UUJbSMq8OfgQyoD+dhfxxg\"",
    "mtime": "2026-05-05T21:45:47.887Z",
    "size": 785778,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_9.webp"
  },
  "/projects/Unbow-Logo-Animation/images/unbow.gif": {
    "type": "image/gif",
    "etag": "\"2c2109-ut9h0RcqfIxm6v7cKjFTP8MzLiY\"",
    "mtime": "2026-05-03T22:36:41.697Z",
    "size": 2892041,
    "path": "../public/projects/Unbow-Logo-Animation/images/unbow.gif"
  }
};

const _DRIVE_LETTER_START_RE = /^[A-Za-z]:\//;
function normalizeWindowsPath(input = "") {
  if (!input) {
    return input;
  }
  return input.replace(/\\/g, "/").replace(_DRIVE_LETTER_START_RE, (r) => r.toUpperCase());
}
const _IS_ABSOLUTE_RE = /^[/\\](?![/\\])|^[/\\]{2}(?!\.)|^[A-Za-z]:[/\\]/;
const _DRIVE_LETTER_RE = /^[A-Za-z]:$/;
function cwd() {
  if (typeof process !== "undefined" && typeof process.cwd === "function") {
    return process.cwd().replace(/\\/g, "/");
  }
  return "/";
}
const resolve = function(...arguments_) {
  arguments_ = arguments_.map((argument) => normalizeWindowsPath(argument));
  let resolvedPath = "";
  let resolvedAbsolute = false;
  for (let index = arguments_.length - 1; index >= -1 && !resolvedAbsolute; index--) {
    const path = index >= 0 ? arguments_[index] : cwd();
    if (!path || path.length === 0) {
      continue;
    }
    resolvedPath = `${path}/${resolvedPath}`;
    resolvedAbsolute = isAbsolute(path);
  }
  resolvedPath = normalizeString(resolvedPath, !resolvedAbsolute);
  if (resolvedAbsolute && !isAbsolute(resolvedPath)) {
    return `/${resolvedPath}`;
  }
  return resolvedPath.length > 0 ? resolvedPath : ".";
};
function normalizeString(path, allowAboveRoot) {
  let res = "";
  let lastSegmentLength = 0;
  let lastSlash = -1;
  let dots = 0;
  let char = null;
  for (let index = 0; index <= path.length; ++index) {
    if (index < path.length) {
      char = path[index];
    } else if (char === "/") {
      break;
    } else {
      char = "/";
    }
    if (char === "/") {
      if (lastSlash === index - 1 || dots === 1) ; else if (dots === 2) {
        if (res.length < 2 || lastSegmentLength !== 2 || res[res.length - 1] !== "." || res[res.length - 2] !== ".") {
          if (res.length > 2) {
            const lastSlashIndex = res.lastIndexOf("/");
            if (lastSlashIndex === -1) {
              res = "";
              lastSegmentLength = 0;
            } else {
              res = res.slice(0, lastSlashIndex);
              lastSegmentLength = res.length - 1 - res.lastIndexOf("/");
            }
            lastSlash = index;
            dots = 0;
            continue;
          } else if (res.length > 0) {
            res = "";
            lastSegmentLength = 0;
            lastSlash = index;
            dots = 0;
            continue;
          }
        }
        if (allowAboveRoot) {
          res += res.length > 0 ? "/.." : "..";
          lastSegmentLength = 2;
        }
      } else {
        if (res.length > 0) {
          res += `/${path.slice(lastSlash + 1, index)}`;
        } else {
          res = path.slice(lastSlash + 1, index);
        }
        lastSegmentLength = index - lastSlash - 1;
      }
      lastSlash = index;
      dots = 0;
    } else if (char === "." && dots !== -1) {
      ++dots;
    } else {
      dots = -1;
    }
  }
  return res;
}
const isAbsolute = function(p) {
  return _IS_ABSOLUTE_RE.test(p);
};
const dirname = function(p) {
  const segments = normalizeWindowsPath(p).replace(/\/$/, "").split("/").slice(0, -1);
  if (segments.length === 1 && _DRIVE_LETTER_RE.test(segments[0])) {
    segments[0] += "/";
  }
  return segments.join("/") || (isAbsolute(p) ? "/" : ".");
};

function readAsset (id) {
  const serverDir = dirname(fileURLToPath(globalThis._importMeta_.url));
  return promises.readFile(resolve(serverDir, assets[id].path))
}

const publicAssetBases = {"/_nuxt/":{"maxAge":31536000}};

function isPublicAssetURL(id = '') {
  if (assets[id]) {
    return true
  }
  for (const base in publicAssetBases) {
    if (id.startsWith(base)) { return true }
  }
  return false
}

function getAsset (id) {
  return assets[id]
}

const METHODS = /* @__PURE__ */ new Set(["HEAD", "GET"]);
const EncodingMap = { gzip: ".gz", br: ".br" };
const _wjVw8s = eventHandler((event) => {
  if (event.method && !METHODS.has(event.method)) {
    return;
  }
  let id = decodePath(
    withLeadingSlash(withoutTrailingSlash(parseURL(event.path).pathname))
  );
  let asset;
  const encodingHeader = String(
    getRequestHeader(event, "accept-encoding") || ""
  );
  const encodings = [
    ...encodingHeader.split(",").map((e) => EncodingMap[e.trim()]).filter(Boolean).sort(),
    ""
  ];
  for (const encoding of encodings) {
    for (const _id of [id + encoding, joinURL(id, "index.html" + encoding)]) {
      const _asset = getAsset(_id);
      if (_asset) {
        asset = _asset;
        id = _id;
        break;
      }
    }
  }
  if (!asset) {
    if (isPublicAssetURL(id)) {
      removeResponseHeader(event, "Cache-Control");
      throw createError$1({ statusCode: 404 });
    }
    return;
  }
  if (asset.encoding !== void 0) {
    appendResponseHeader(event, "Vary", "Accept-Encoding");
  }
  const ifNotMatch = getRequestHeader(event, "if-none-match") === asset.etag;
  if (ifNotMatch) {
    setResponseStatus(event, 304, "Not Modified");
    return "";
  }
  const ifModifiedSinceH = getRequestHeader(event, "if-modified-since");
  const mtimeDate = new Date(asset.mtime);
  if (ifModifiedSinceH && asset.mtime && new Date(ifModifiedSinceH) >= mtimeDate) {
    setResponseStatus(event, 304, "Not Modified");
    return "";
  }
  if (asset.type && !getResponseHeader(event, "Content-Type")) {
    setResponseHeader(event, "Content-Type", asset.type);
  }
  if (asset.etag && !getResponseHeader(event, "ETag")) {
    setResponseHeader(event, "ETag", asset.etag);
  }
  if (asset.mtime && !getResponseHeader(event, "Last-Modified")) {
    setResponseHeader(event, "Last-Modified", mtimeDate.toUTCString());
  }
  if (asset.encoding && !getResponseHeader(event, "Content-Encoding")) {
    setResponseHeader(event, "Content-Encoding", asset.encoding);
  }
  if (asset.size > 0 && !getResponseHeader(event, "Content-Length")) {
    setResponseHeader(event, "Content-Length", asset.size);
  }
  return readAsset(id);
});

const _SxA8c9 = defineEventHandler(() => {});

function defineRenderHandler(render) {
  const runtimeConfig = useRuntimeConfig();
  return eventHandler(async (event) => {
    const nitroApp = useNitroApp();
    const ctx = { event, render, response: void 0 };
    await nitroApp.hooks.callHook("render:before", ctx);
    if (!ctx.response) {
      if (event.path === `${runtimeConfig.app.baseURL}favicon.ico`) {
        setResponseHeader(event, "Content-Type", "image/x-icon");
        return send(
          event,
          "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"
        );
      }
      ctx.response = await ctx.render(event);
      if (!ctx.response) {
        const _currentStatus = getResponseStatus(event);
        setResponseStatus(event, _currentStatus === 200 ? 500 : _currentStatus);
        return send(
          event,
          "No response returned from render handler: " + event.path
        );
      }
    }
    await nitroApp.hooks.callHook("render:response", ctx.response, ctx);
    if (ctx.response.headers) {
      setResponseHeaders(event, ctx.response.headers);
    }
    if (ctx.response.statusCode || ctx.response.statusMessage) {
      setResponseStatus(
        event,
        ctx.response.statusCode,
        ctx.response.statusMessage
      );
    }
    return ctx.response.body;
  });
}

function baseURL() {
	
	return useRuntimeConfig().app.baseURL;
}
function buildAssetsDir() {
	
	return useRuntimeConfig().app.buildAssetsDir;
}
function buildAssetsURL(...path) {
	return joinRelativeURL(publicAssetsURL(), buildAssetsDir(), ...path);
}
function publicAssetsURL(...path) {
	
	const app = useRuntimeConfig().app;
	const publicBase = app.cdnURL || app.baseURL;
	return path.length ? joinRelativeURL(publicBase, ...path) : publicBase;
}

const _cMEFW0 = lazyEventHandler(() => {
  const opts = useRuntimeConfig().ipx || {};
  const fsDir = opts?.fs?.dir ? (Array.isArray(opts.fs.dir) ? opts.fs.dir : [opts.fs.dir]).map((dir) => isAbsolute(dir) ? dir : fileURLToPath(new URL(dir, globalThis._importMeta_.url))) : void 0;
  const fsStorage = opts.fs?.dir ? ipxFSStorage({ ...opts.fs, dir: fsDir }) : void 0;
  const httpStorage = opts.http?.domains ? ipxHttpStorage({ ...opts.http }) : void 0;
  if (!fsStorage && !httpStorage) {
    throw new Error("IPX storage is not configured!");
  }
  const ipxOptions = {
    ...opts,
    storage: fsStorage || httpStorage,
    httpStorage
  };
  const ipx = createIPX(ipxOptions);
  const ipxHandler = createIPXH3Handler(ipx);
  return useBase(opts.baseURL, ipxHandler);
});

const _lazy_tlyLMH = () => import('../routes/renderer.mjs').then(function (n) { return n.r; });

const handlers = [
  { route: '', handler: _wjVw8s, lazy: false, middleware: true, method: undefined },
  { route: '/__nuxt_error', handler: _lazy_tlyLMH, lazy: true, middleware: false, method: undefined },
  { route: '/__nuxt_island/**', handler: _SxA8c9, lazy: false, middleware: false, method: undefined },
  { route: '/_ipx/**', handler: _cMEFW0, lazy: false, middleware: false, method: undefined },
  { route: '/**', handler: _lazy_tlyLMH, lazy: true, middleware: false, method: undefined }
];

function createNitroApp() {
  const config = useRuntimeConfig();
  const hooks = createHooks();
  const captureError = (error, context = {}) => {
    const promise = hooks.callHookParallel("error", error, context).catch((error_) => {
      console.error("Error while capturing another error", error_);
    });
    if (context.event && isEvent(context.event)) {
      const errors = context.event.context.nitro?.errors;
      if (errors) {
        errors.push({ error, context });
      }
      if (context.event.waitUntil) {
        context.event.waitUntil(promise);
      }
    }
  };
  const h3App = createApp({
    debug: destr(false),
    onError: (error, event) => {
      captureError(error, { event, tags: ["request"] });
      return errorHandler(error, event);
    },
    onRequest: async (event) => {
      event.context.nitro = event.context.nitro || { errors: [] };
      const fetchContext = event.node.req?.__unenv__;
      if (fetchContext?._platform) {
        event.context = {
          _platform: fetchContext?._platform,
          // #3335
          ...fetchContext._platform,
          ...event.context
        };
      }
      if (!event.context.waitUntil && fetchContext?.waitUntil) {
        event.context.waitUntil = fetchContext.waitUntil;
      }
      event.fetch = (req, init) => fetchWithEvent(event, req, init, { fetch: localFetch });
      event.$fetch = (req, init) => fetchWithEvent(event, req, init, {
        fetch: $fetch
      });
      event.waitUntil = (promise) => {
        if (!event.context.nitro._waitUntilPromises) {
          event.context.nitro._waitUntilPromises = [];
        }
        event.context.nitro._waitUntilPromises.push(promise);
        if (event.context.waitUntil) {
          event.context.waitUntil(promise);
        }
      };
      event.captureError = (error, context) => {
        captureError(error, { event, ...context });
      };
      await nitroApp.hooks.callHook("request", event).catch((error) => {
        captureError(error, { event, tags: ["request"] });
      });
    },
    onBeforeResponse: async (event, response) => {
      await nitroApp.hooks.callHook("beforeResponse", event, response).catch((error) => {
        captureError(error, { event, tags: ["request", "response"] });
      });
    },
    onAfterResponse: async (event, response) => {
      await nitroApp.hooks.callHook("afterResponse", event, response).catch((error) => {
        captureError(error, { event, tags: ["request", "response"] });
      });
    }
  });
  const router = createRouter({
    preemptive: true
  });
  const nodeHandler = toNodeListener(h3App);
  const localCall = (aRequest) => b(
    nodeHandler,
    aRequest
  );
  const localFetch = (input, init) => {
    if (!input.toString().startsWith("/")) {
      return globalThis.fetch(input, init);
    }
    return C(
      nodeHandler,
      input,
      init
    ).then((response) => normalizeFetchResponse(response));
  };
  const $fetch = createFetch({
    fetch: localFetch,
    Headers: Headers$1,
    defaults: { baseURL: config.app.baseURL }
  });
  globalThis.$fetch = $fetch;
  h3App.use(createRouteRulesHandler({ localFetch }));
  for (const h of handlers) {
    let handler = h.lazy ? lazyEventHandler(h.handler) : h.handler;
    if (h.middleware || !h.route) {
      const middlewareBase = (config.app.baseURL + (h.route || "/")).replace(
        /\/+/g,
        "/"
      );
      h3App.use(middlewareBase, handler);
    } else {
      const routeRules = getRouteRulesForPath(
        h.route.replace(/:\w+|\*\*/g, "_")
      );
      if (routeRules.cache) {
        handler = cachedEventHandler(handler, {
          group: "nitro/routes",
          ...routeRules.cache
        });
      }
      router.use(h.route, handler, h.method);
    }
  }
  h3App.use(config.app.baseURL, router.handler);
  const app = {
    hooks,
    h3App,
    router,
    localCall,
    localFetch,
    captureError
  };
  return app;
}
function runNitroPlugins(nitroApp2) {
  for (const plugin of plugins) {
    try {
      plugin(nitroApp2);
    } catch (error) {
      nitroApp2.captureError(error, { tags: ["plugin"] });
      throw error;
    }
  }
}
const nitroApp = createNitroApp();
function useNitroApp() {
  return nitroApp;
}
runNitroPlugins(nitroApp);

const debug = (...args) => {
};
function GracefulShutdown(server, opts) {
  opts = opts || {};
  const options = Object.assign(
    {
      signals: "SIGINT SIGTERM",
      timeout: 3e4,
      development: false,
      forceExit: true,
      onShutdown: (signal) => Promise.resolve(signal),
      preShutdown: (signal) => Promise.resolve(signal)
    },
    opts
  );
  let isShuttingDown = false;
  const connections = {};
  let connectionCounter = 0;
  const secureConnections = {};
  let secureConnectionCounter = 0;
  let failed = false;
  let finalRun = false;
  function onceFactory() {
    let called = false;
    return (emitter, events, callback) => {
      function call() {
        if (!called) {
          called = true;
          return Reflect.apply(callback, this, arguments);
        }
      }
      for (const e of events) {
        emitter.on(e, call);
      }
    };
  }
  const signals = options.signals.split(" ").map((s) => s.trim()).filter((s) => s.length > 0);
  const once = onceFactory();
  once(process, signals, (signal) => {
    debug("received shut down signal", signal);
    shutdown(signal).then(() => {
      if (options.forceExit) {
        process.exit(failed ? 1 : 0);
      }
    }).catch((error) => {
      debug("server shut down error occurred", error);
      process.exit(1);
    });
  });
  function isFunction(functionToCheck) {
    const getType = Object.prototype.toString.call(functionToCheck);
    return /^\[object\s([A-Za-z]+)?Function]$/.test(getType);
  }
  function destroy(socket, force = false) {
    if (socket._isIdle && isShuttingDown || force) {
      socket.destroy();
      if (socket.server instanceof http.Server) {
        delete connections[socket._connectionId];
      } else {
        delete secureConnections[socket._connectionId];
      }
    }
  }
  function destroyAllConnections(force = false) {
    debug("Destroy Connections : " + (force ? "forced close" : "close"));
    let counter = 0;
    let secureCounter = 0;
    for (const key of Object.keys(connections)) {
      const socket = connections[key];
      const serverResponse = socket._httpMessage;
      if (serverResponse && !force) {
        if (!serverResponse.headersSent) {
          serverResponse.setHeader("connection", "close");
        }
      } else {
        counter++;
        destroy(socket);
      }
    }
    debug("Connections destroyed : " + counter);
    debug("Connection Counter    : " + connectionCounter);
    for (const key of Object.keys(secureConnections)) {
      const socket = secureConnections[key];
      const serverResponse = socket._httpMessage;
      if (serverResponse && !force) {
        if (!serverResponse.headersSent) {
          serverResponse.setHeader("connection", "close");
        }
      } else {
        secureCounter++;
        destroy(socket);
      }
    }
    debug("Secure Connections destroyed : " + secureCounter);
    debug("Secure Connection Counter    : " + secureConnectionCounter);
  }
  server.on("request", (req, res) => {
    req.socket._isIdle = false;
    if (isShuttingDown && !res.headersSent) {
      res.setHeader("connection", "close");
    }
    res.on("finish", () => {
      req.socket._isIdle = true;
      destroy(req.socket);
    });
  });
  server.on("connection", (socket) => {
    if (isShuttingDown) {
      socket.destroy();
    } else {
      const id = connectionCounter++;
      socket._isIdle = true;
      socket._connectionId = id;
      connections[id] = socket;
      socket.once("close", () => {
        delete connections[socket._connectionId];
      });
    }
  });
  server.on("secureConnection", (socket) => {
    if (isShuttingDown) {
      socket.destroy();
    } else {
      const id = secureConnectionCounter++;
      socket._isIdle = true;
      socket._connectionId = id;
      secureConnections[id] = socket;
      socket.once("close", () => {
        delete secureConnections[socket._connectionId];
      });
    }
  });
  process.on("close", () => {
    debug("closed");
  });
  function shutdown(sig) {
    function cleanupHttp() {
      destroyAllConnections();
      debug("Close http server");
      return new Promise((resolve, reject) => {
        server.close((err) => {
          if (err) {
            return reject(err);
          }
          return resolve(true);
        });
      });
    }
    debug("shutdown signal - " + sig);
    if (options.development) {
      debug("DEV-Mode - immediate forceful shutdown");
      return process.exit(0);
    }
    function finalHandler() {
      if (!finalRun) {
        finalRun = true;
        if (options.finally && isFunction(options.finally)) {
          debug("executing finally()");
          options.finally();
        }
      }
      return Promise.resolve();
    }
    function waitForReadyToShutDown(totalNumInterval) {
      debug(`waitForReadyToShutDown... ${totalNumInterval}`);
      if (totalNumInterval === 0) {
        debug(
          `Could not close connections in time (${options.timeout}ms), will forcefully shut down`
        );
        return Promise.resolve(true);
      }
      const allConnectionsClosed = Object.keys(connections).length === 0 && Object.keys(secureConnections).length === 0;
      if (allConnectionsClosed) {
        debug("All connections closed. Continue to shutting down");
        return Promise.resolve(false);
      }
      debug("Schedule the next waitForReadyToShutdown");
      return new Promise((resolve) => {
        setTimeout(() => {
          resolve(waitForReadyToShutDown(totalNumInterval - 1));
        }, 250);
      });
    }
    if (isShuttingDown) {
      return Promise.resolve();
    }
    debug("shutting down");
    return options.preShutdown(sig).then(() => {
      isShuttingDown = true;
      cleanupHttp();
    }).then(() => {
      const pollIterations = options.timeout ? Math.round(options.timeout / 250) : 0;
      return waitForReadyToShutDown(pollIterations);
    }).then((force) => {
      debug("Do onShutdown now");
      if (force) {
        destroyAllConnections(force);
      }
      return options.onShutdown(sig);
    }).then(finalHandler).catch((error) => {
      const errString = typeof error === "string" ? error : JSON.stringify(error);
      debug(errString);
      failed = true;
      throw errString;
    });
  }
  function shutdownManual() {
    return shutdown("manual");
  }
  return shutdownManual;
}

function getGracefulShutdownConfig() {
  return {
    disabled: !!process.env.NITRO_SHUTDOWN_DISABLED,
    signals: (process.env.NITRO_SHUTDOWN_SIGNALS || "SIGTERM SIGINT").split(" ").map((s) => s.trim()),
    timeout: Number.parseInt(process.env.NITRO_SHUTDOWN_TIMEOUT || "", 10) || 3e4,
    forceExit: !process.env.NITRO_SHUTDOWN_NO_FORCE_EXIT
  };
}
function setupGracefulShutdown(listener, nitroApp) {
  const shutdownConfig = getGracefulShutdownConfig();
  if (shutdownConfig.disabled) {
    return;
  }
  GracefulShutdown(listener, {
    signals: shutdownConfig.signals.join(" "),
    timeout: shutdownConfig.timeout,
    forceExit: shutdownConfig.forceExit,
    onShutdown: async () => {
      await new Promise((resolve) => {
        const timeout = setTimeout(() => {
          console.warn("Graceful shutdown timeout, force exiting...");
          resolve();
        }, shutdownConfig.timeout);
        nitroApp.hooks.callHook("close").catch((error) => {
          console.error(error);
        }).finally(() => {
          clearTimeout(timeout);
          resolve();
        });
      });
    }
  });
}

export { $fetch as $, executeAsync as A, withLeadingSlash as B, encodeParam as C, parseQuery as D, withTrailingSlash as E, withoutTrailingSlash as F, trapUnhandledNodeErrors as a, useNitroApp as b, buildAssetsURL as c, destr as d, getResponseStatus as e, encodePath as f, getResponseStatusText as g, defineRenderHandler as h, getQuery as i, createError$1 as j, getRouteRules as k, joinURL as l, parseURL as m, decodePath as n, hasProtocol as o, publicAssetsURL as p, isScriptProtocol as q, sanitizeStatusCode as r, setupGracefulShutdown as s, toNodeListener as t, useRuntimeConfig as u, getContext as v, withQuery as w, baseURL as x, defu as y, createHooks as z };
//# sourceMappingURL=nitro.mjs.map
