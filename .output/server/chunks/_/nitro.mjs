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
    "buildId": "07f182e2-f1a6-4876-acb2-e2e4e16a02b5",
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
      "domains": [
        "peppecaruso-portfolio-storage.s3.eu-north-1.amazonaws.com",
        "s3.eu-north-1.amazonaws.com",
        "s3.amazonaws.com"
      ]
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
  "/fonts/PowerGrotesk-Regular.woff2": {
    "type": "font/woff2",
    "etag": "\"53b4-3y3eUrmFI11SKzg4U8TvS0hSFf0\"",
    "mtime": "2026-05-03T22:36:41.686Z",
    "size": 21428,
    "path": "../public/fonts/PowerGrotesk-Regular.woff2"
  },
  "/_nuxt/02_03.Bz1jIBX2.webp": {
    "type": "image/webp",
    "etag": "\"762c6-SnXNZX0xmFIddCUQ8+OJWCa75Yo\"",
    "mtime": "2026-09-28T12:17:37.578Z",
    "size": 484038,
    "path": "../public/_nuxt/02_03.Bz1jIBX2.webp"
  },
  "/_nuxt/-busH2xx.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-OwZ+h5qq2Jf7M+Sm7suZpKkAjzw\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 114,
    "path": "../public/_nuxt/-busH2xx.js"
  },
  "/_nuxt/03peLlU1.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-1oXUiTplVrPklqO319AiSph1/l0\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 114,
    "path": "../public/_nuxt/03peLlU1.js"
  },
  "/_nuxt/2apZgpGG.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6a-r8jqM8g8tm0xi8u9EjqqaXWxwtc\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 106,
    "path": "../public/_nuxt/2apZgpGG.js"
  },
  "/_nuxt/1TQxXQ6F.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"76-lkL2Y3r+vIwgUCe+Nix5UbS7oSM\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 118,
    "path": "../public/_nuxt/1TQxXQ6F.js"
  },
  "/_nuxt/3TDfCZtI.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-4BvE8SuCrQJzQpn4BzrrT8ENxJ0\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 120,
    "path": "../public/_nuxt/3TDfCZtI.js"
  },
  "/_nuxt/3FpyOT07.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"84-M8/eeoT5hfFp9WpfrAIxJg5qy64\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 132,
    "path": "../public/_nuxt/3FpyOT07.js"
  },
  "/_nuxt/3zMjYSZi.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-NAFz8abm6AizIzctQYG/6npzpEs\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 122,
    "path": "../public/_nuxt/3zMjYSZi.js"
  },
  "/_nuxt/5B6zfC8N.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-M0Ef6Ui2YO3MfRGBguT/kXhYC9Q\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 114,
    "path": "../public/_nuxt/5B6zfC8N.js"
  },
  "/_nuxt/02_020.CC1ABNmI.webp": {
    "type": "image/webp",
    "etag": "\"b2d88-hjOCm4h7XCQZTljyJPsRjDxd8y0\"",
    "mtime": "2026-09-28T12:17:37.609Z",
    "size": 732552,
    "path": "../public/_nuxt/02_020.CC1ABNmI.webp"
  },
  "/_nuxt/02_021.DJA8lALI.webp": {
    "type": "image/webp",
    "etag": "\"f76ba-pudWbTKN117ATKvqIsPG35otg8s\"",
    "mtime": "2026-09-28T12:17:37.609Z",
    "size": 1013434,
    "path": "../public/_nuxt/02_021.DJA8lALI.webp"
  },
  "/_nuxt/02_06.CFvRicEn.webp": {
    "type": "image/webp",
    "etag": "\"deabc-zbeXmwtpwWbRVHtAPfRl+WBZ7XI\"",
    "mtime": "2026-09-28T12:17:37.609Z",
    "size": 912060,
    "path": "../public/_nuxt/02_06.CFvRicEn.webp"
  },
  "/_nuxt/5EZ3Qdmd.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-XFYXs89Bxf9p50qNy5qipJmEbbI\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/5EZ3Qdmd.js"
  },
  "/_nuxt/5i3DtrM4.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-3H5xTVh8vun7YhjscKBqDofD/os\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 115,
    "path": "../public/_nuxt/5i3DtrM4.js"
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
    "mtime": "2026-09-28T12:17:37.893Z",
    "size": 1493498,
    "path": "../public/_nuxt/02_01.UzkPjOK8.webp"
  },
  "/_nuxt/02_04.fnJ9-MgU.webp": {
    "type": "image/webp",
    "etag": "\"1036a4-kfI6p0NDgWLNgtV2QKDdXQNUziE\"",
    "mtime": "2026-09-28T12:17:37.893Z",
    "size": 1062564,
    "path": "../public/_nuxt/02_04.fnJ9-MgU.webp"
  },
  "/_nuxt/02_05.CsQ5DQHF.webp": {
    "type": "image/webp",
    "etag": "\"100362-VH5l5OJBQFDoiVIPKtklirNgFc8\"",
    "mtime": "2026-09-28T12:17:37.893Z",
    "size": 1049442,
    "path": "../public/_nuxt/02_05.CsQ5DQHF.webp"
  },
  "/_nuxt/02_02.B9-_d6Xb.webp": {
    "type": "image/webp",
    "etag": "\"184bcc-H87O+loBNIoJJiWnBZUxMGR+xGA\"",
    "mtime": "2026-09-28T12:17:37.915Z",
    "size": 1592268,
    "path": "../public/_nuxt/02_02.B9-_d6Xb.webp"
  },
  "/_nuxt/5oesv7T_.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"80-PTDJpOyFfwsgEF9kQj4X4KJqPtw\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 128,
    "path": "../public/_nuxt/5oesv7T_.js"
  },
  "/_nuxt/7G5xgENt.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-SAlJXLVsLqosrCjlKYUhEdIk8jo\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 107,
    "path": "../public/_nuxt/7G5xgENt.js"
  },
  "/_nuxt/7ZVvbcLl.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"80-d33AlSFfhxF0r8SeAK+SsKlq7uE\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 128,
    "path": "../public/_nuxt/7ZVvbcLl.js"
  },
  "/_nuxt/64aNtLLl.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"76-GWqTOf7VzO/AUVqwQVvmoFLXzSw\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 118,
    "path": "../public/_nuxt/64aNtLLl.js"
  },
  "/_nuxt/6RK7C3br.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-js6gtTHE4QItfItWciHpn1Czpyk\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 119,
    "path": "../public/_nuxt/6RK7C3br.js"
  },
  "/_nuxt/8vEfg5nB.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-8GKoqD7mzKG7k5qJbR0NXZiUGJs\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 119,
    "path": "../public/_nuxt/8vEfg5nB.js"
  },
  "/_nuxt/9koOHbm0.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-CmF4O1reHJYlolnbhtEOviL2dVo\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 110,
    "path": "../public/_nuxt/9koOHbm0.js"
  },
  "/_nuxt/AmericanFavoriteScript.CHuQJG7O.woff2": {
    "type": "font/woff2",
    "etag": "\"ad94-2gaBwO46yzar5icsyEWAm2sWWPM\"",
    "mtime": "2026-09-28T12:17:37.578Z",
    "size": 44436,
    "path": "../public/_nuxt/AmericanFavoriteScript.CHuQJG7O.woff2"
  },
  "/_nuxt/a-6lRdAL.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-kkidUBm5nilLZEhGj/wDuYHv+00\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/a-6lRdAL.js"
  },
  "/_nuxt/A2fLMWEB.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6a-Fsd5AUuj1DxNpDuOg+2tkDJ/RNM\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 106,
    "path": "../public/_nuxt/A2fLMWEB.js"
  },
  "/_nuxt/AQ_c7JZ8.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-jypoPeRtTzbqLHADK5Te+7GxOLo\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/AQ_c7JZ8.js"
  },
  "/_nuxt/a3hHFPRZ.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"76-MYntlwYLCDGwxEEofe1hJ4LviRE\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 118,
    "path": "../public/_nuxt/a3hHFPRZ.js"
  },
  "/_nuxt/AtxEjnGi.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6c-nxz82du7k0AAAHLZ9behfv9V654\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 108,
    "path": "../public/_nuxt/AtxEjnGi.js"
  },
  "/_nuxt/B-M6nXR2.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-0p6tvV7uOGPTG71f7o3CHj+Mz1M\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 110,
    "path": "../public/_nuxt/B-M6nXR2.js"
  },
  "/_nuxt/B0LOfb9H.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-UrO46EZVwrAePHF851EnMFpT7hk\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 110,
    "path": "../public/_nuxt/B0LOfb9H.js"
  },
  "/_nuxt/B0MyywWP.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6f-RbKm3FDUQkMGnZC8xc9ncRniNX8\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 111,
    "path": "../public/_nuxt/B0MyywWP.js"
  },
  "/_nuxt/B0VW60Dv.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-sb6E7vqvVb87Su2npQ/FAZpfNVQ\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 110,
    "path": "../public/_nuxt/B0VW60Dv.js"
  },
  "/_nuxt/B1-2gE6L.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"85-W14xSugI0iykYSK+GNMdKbudVyg\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 133,
    "path": "../public/_nuxt/B1-2gE6L.js"
  },
  "/_nuxt/B0w2zlg4.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-0lGLqrt/UHsmq1ofG4o1ZDVqGEw\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/B0w2zlg4.js"
  },
  "/_nuxt/B2ud5KsC.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-gBHbspEMCLHGrqt/GJcH7EWUb88\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 110,
    "path": "../public/_nuxt/B2ud5KsC.js"
  },
  "/_nuxt/ASMR-Gara.BehVu7bJ.mp4": {
    "type": "video/mp4",
    "etag": "\"18052d-rXgJ0YWp1nUsatulWp9j4eltSU8\"",
    "mtime": "2026-09-28T12:17:37.915Z",
    "size": 1574189,
    "path": "../public/_nuxt/ASMR-Gara.BehVu7bJ.mp4"
  },
  "/_nuxt/B3ju47vf.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"70-LDSGTu8uMpRAsc0EQHLpPlur/6M\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 112,
    "path": "../public/_nuxt/B3ju47vf.js"
  },
  "/_nuxt/B4EIvlIm.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-hAk3DjgviszQuwL0fqktLhhrQCw\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 110,
    "path": "../public/_nuxt/B4EIvlIm.js"
  },
  "/_nuxt/B4u8vybT.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6a-OUnzz8sdNIkM2SKEtmtXdDREZ5s\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 106,
    "path": "../public/_nuxt/B4u8vybT.js"
  },
  "/_nuxt/B4Y70uYW.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-PKe9DsVSKRz6J98wavCgnrWftPI\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 113,
    "path": "../public/_nuxt/B4Y70uYW.js"
  },
  "/_nuxt/B76Zhx31.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"74-A4GlsQJk3IrdZmMIiM0a+ZCjqug\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 116,
    "path": "../public/_nuxt/B76Zhx31.js"
  },
  "/_nuxt/B7bcPaEg.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-Q+2LjmnZYC5weGb7oE99vA/qlRQ\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/B7bcPaEg.js"
  },
  "/_nuxt/B82r4RmE.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-HRw7yRrbrJEzGMLWQTwFuZBBvnU\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 113,
    "path": "../public/_nuxt/B82r4RmE.js"
  },
  "/_nuxt/B7OhLNWE.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-W+iqQ/IL6lFpAmGrrdoRFC6Hxd0\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 110,
    "path": "../public/_nuxt/B7OhLNWE.js"
  },
  "/_nuxt/B8J-gwHB.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-mBc+XvBeLK4aw0OdJk/6iwvzHdk\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/B8J-gwHB.js"
  },
  "/_nuxt/B8u0WKvc.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-x6ywsr+O+yRN3xTp5Yuw6xOBaRg\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 113,
    "path": "../public/_nuxt/B8u0WKvc.js"
  },
  "/_nuxt/B9uDxGZY.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-WGY+UAtjVKtJSgtCQ7aUlMxzu1Y\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 114,
    "path": "../public/_nuxt/B9uDxGZY.js"
  },
  "/_nuxt/BAlorL24.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-uY6xJhHFb3WpyL53tCnbDV70baI\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 114,
    "path": "../public/_nuxt/BAlorL24.js"
  },
  "/_nuxt/BanJOF-Z.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-At+gSCkNLGQT4oiy2PtcG2oX4nk\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/BanJOF-Z.js"
  },
  "/_nuxt/BayyTdrC.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"76-PERIRmyV3uUNxWrfO1ZEEJTf+s4\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 118,
    "path": "../public/_nuxt/BayyTdrC.js"
  },
  "/_nuxt/BAS_k3W3.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-dZNnSalXEBf6UHKQOEqLba5ZEw0\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/BAS_k3W3.js"
  },
  "/_nuxt/Bb7JNYq6.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-MLqLbtjnstzXh2QCY0GwUZZqsBU\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/Bb7JNYq6.js"
  },
  "/_nuxt/BBu3KRhP.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-s4k6nRvZXGKRJNwQmUGqsPp2VhA\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 114,
    "path": "../public/_nuxt/BBu3KRhP.js"
  },
  "/_nuxt/BCB7bZS_.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-UGXtdt0wc3ha1RHo71gN8wQymdY\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 113,
    "path": "../public/_nuxt/BCB7bZS_.js"
  },
  "/_nuxt/BCUQzN9i.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"76-O1Nl4xE3Vu5iTLVCYWS8eiP8NKo\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 118,
    "path": "../public/_nuxt/BCUQzN9i.js"
  },
  "/_nuxt/BD3QN5Xu.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-bOiiJQcIBEaUIxWLB+cR9QoMZls\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/BD3QN5Xu.js"
  },
  "/_nuxt/BCxLD9yZ.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-Wv7skdJOhn+NN5V3/Y95l2C2GYg\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 119,
    "path": "../public/_nuxt/BCxLD9yZ.js"
  },
  "/_nuxt/BddH99d1.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-aW8dfFULhY1qIhMjlGH5x3a0D3k\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 110,
    "path": "../public/_nuxt/BddH99d1.js"
  },
  "/_nuxt/BdVyA8ky.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6a-M3UXZeFZl5rxgCQfDlCMXMsWa14\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 106,
    "path": "../public/_nuxt/BdVyA8ky.js"
  },
  "/_nuxt/BDnShjQD.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-XTdPrq6vmy17LX3RFSY358zHBBM\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 107,
    "path": "../public/_nuxt/BDnShjQD.js"
  },
  "/_nuxt/BdZ3wQoT.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-GK0+8nadO7ZYiW1x+KuCWq6+cUY\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 114,
    "path": "../public/_nuxt/BdZ3wQoT.js"
  },
  "/_nuxt/BdzQ-NWp.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-rqgcPfaO3BjR/kA+cmPZGvZd3Lw\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 110,
    "path": "../public/_nuxt/BdzQ-NWp.js"
  },
  "/_nuxt/BF9lr2Du.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-gBHbspEMCLHGrqt/GJcH7EWUb88\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 110,
    "path": "../public/_nuxt/BF9lr2Du.js"
  },
  "/_nuxt/BEmzmbX3.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-hmvnjF9pLoYHUCV48tqNTmhcvVs\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 120,
    "path": "../public/_nuxt/BEmzmbX3.js"
  },
  "/_nuxt/BeOZk7Jt.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-fkX3JkV3KHjd1kC2bk23nzaRHrA\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/BeOZk7Jt.js"
  },
  "/_nuxt/BeX-Mm6o.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-6NYKquvL4Yg5E0Ymg5dPCB+mEzw\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 122,
    "path": "../public/_nuxt/BeX-Mm6o.js"
  },
  "/_nuxt/BF9y8Gj8.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-pammK2g4Abi1mGvfN86ZNSnGZts\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 114,
    "path": "../public/_nuxt/BF9y8Gj8.js"
  },
  "/_nuxt/BF9YS4sF.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-lXvGcZYBZon9ndTPeadQG+Dc25g\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 110,
    "path": "../public/_nuxt/BF9YS4sF.js"
  },
  "/_nuxt/BfwhReoN.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"74-OEpBfKYelFaa620xWc9P1F2Xwig\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 116,
    "path": "../public/_nuxt/BfwhReoN.js"
  },
  "/_nuxt/Bg6SS4Wb.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-SySR5mPWbd7TeZQoUstKisp54/o\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 119,
    "path": "../public/_nuxt/Bg6SS4Wb.js"
  },
  "/_nuxt/BGVS8tFa.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-5ICVl+cZBBDcbMBf76xj2c7AJKo\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 119,
    "path": "../public/_nuxt/BGVS8tFa.js"
  },
  "/_nuxt/BhPae0Wv.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-n2of4kMw/W+GxamHFHnDLIm/7Xk\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/BhPae0Wv.js"
  },
  "/_nuxt/BHhBvYV9.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-MIXCu+3ArX9+l35x8RWo5oO8590\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 107,
    "path": "../public/_nuxt/BHhBvYV9.js"
  },
  "/_nuxt/BiyQ26kd.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-bgVb8KTDAUXpfnhj3n9bZW3vhLo\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 110,
    "path": "../public/_nuxt/BiyQ26kd.js"
  },
  "/_nuxt/BjlQDZmM.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-J5VTp5O3Mbbp2c9B76dG6NsR1AY\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 107,
    "path": "../public/_nuxt/BjlQDZmM.js"
  },
  "/_nuxt/bjzcnJ8N.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-GLoHZ3dFei10jweA4VQgsA9YHGw\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 110,
    "path": "../public/_nuxt/bjzcnJ8N.js"
  },
  "/_nuxt/BJYAYw8b.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-+j+gAjxI5cyD7VIXVLIYmL1kakM\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/BJYAYw8b.js"
  },
  "/_nuxt/BkI0cGQl.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-ynOe1nXZRNRFR/tTyOJt28Z8+K4\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 110,
    "path": "../public/_nuxt/BkI0cGQl.js"
  },
  "/_nuxt/BKldC_ri.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6f-TmVFWIS5pFb7vtIrzV/p1Tl3mX4\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 111,
    "path": "../public/_nuxt/BKldC_ri.js"
  },
  "/_nuxt/Bko2tvw5.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"70-qYCs/m1KoJdFrQw3pg3QWJK/qpU\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 112,
    "path": "../public/_nuxt/Bko2tvw5.js"
  },
  "/_nuxt/BkLN1-16.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-SMAIzX7RTsUfkwPAeEtkvqgSRbs\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 120,
    "path": "../public/_nuxt/BkLN1-16.js"
  },
  "/_nuxt/BKt2f2of.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-X1ed83Ge+X0HYZcrmS+GRh5/O2I\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 110,
    "path": "../public/_nuxt/BKt2f2of.js"
  },
  "/_nuxt/BLbau4uJ.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7f-LCiojxrkD53JOoryTWcMY7pqv7Y\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 127,
    "path": "../public/_nuxt/BLbau4uJ.js"
  },
  "/_nuxt/BlCGP6yV.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-CF2+oy2lZfZyGLBL3jVD7Ek0cK8\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 113,
    "path": "../public/_nuxt/BlCGP6yV.js"
  },
  "/_nuxt/BlLNiLOB.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-T+RVSHI+a6ERYx9FIjSrSt9V6QY\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/BlLNiLOB.js"
  },
  "/_nuxt/BLlWtTvT.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"76-cLoNBuAfOHh/wYxf8WO9Nvw0UBw\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 118,
    "path": "../public/_nuxt/BLlWtTvT.js"
  },
  "/_nuxt/bM-pAEwK.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-DbGQTkdbOGoWAs8Y2dx3zrbsSjA\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/bM-pAEwK.js"
  },
  "/_nuxt/BMCkVwcv.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-LmD0wAf4RI7ofjyod0Ql4XmW2e0\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 119,
    "path": "../public/_nuxt/BMCkVwcv.js"
  },
  "/_nuxt/BMn-dbzs.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-FT1A7CgKRpTD+8VMEAdyb9YXJXo\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 122,
    "path": "../public/_nuxt/BMn-dbzs.js"
  },
  "/_nuxt/Bmq9w1s5.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-NHkfKjjf79ePA2rzBAZgyNDAsOY\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/Bmq9w1s5.js"
  },
  "/_nuxt/Bmqi4IOp.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-v2BxpXM1/jmJ7dDzXX+W+4b7CR0\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/Bmqi4IOp.js"
  },
  "/_nuxt/BNfIuXKV.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-PJ0G3Tpl0+sJBC4dkty2fyrcR2w\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 120,
    "path": "../public/_nuxt/BNfIuXKV.js"
  },
  "/_nuxt/BNikp5c5.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-DxG5MeXKQn3typ4+re7t1Eo7E2g\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/BNikp5c5.js"
  },
  "/_nuxt/BMvurDt_.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-RhCBZX+U0VjDq/9uwjvELVuHt2Y\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 114,
    "path": "../public/_nuxt/BMvurDt_.js"
  },
  "/_nuxt/BNOFUqF0.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-xSTuVJE8aEgjLDtPQX+KhMaZhzI\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 110,
    "path": "../public/_nuxt/BNOFUqF0.js"
  },
  "/_nuxt/BNwGMnh5.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"70-A7FJ+ruisI8XTfv7ncifT0XlJlk\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 112,
    "path": "../public/_nuxt/BNwGMnh5.js"
  },
  "/_nuxt/BNy6MKAt.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-xi2UsHE94lGi83Gg1dSyL66vm7A\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 110,
    "path": "../public/_nuxt/BNy6MKAt.js"
  },
  "/_nuxt/BN_Tu4RW.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-bD/hBkQzF7GrtQTKajYsGujuF9Q\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 119,
    "path": "../public/_nuxt/BN_Tu4RW.js"
  },
  "/_nuxt/Bp4KBww2.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-NxdwnwkneQq0WrqJXPqU9XT0D0c\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 110,
    "path": "../public/_nuxt/Bp4KBww2.js"
  },
  "/_nuxt/BPPJ-X0f.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-2pDacTbqCkDeFSry2yjSvFinM/8\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 110,
    "path": "../public/_nuxt/BPPJ-X0f.js"
  },
  "/_nuxt/Bpt7HFgN.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-iyL6hrSyzZsvzs1rOON5TYoQVc0\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 107,
    "path": "../public/_nuxt/Bpt7HFgN.js"
  },
  "/_nuxt/BP_2GkDo.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-71bwnqC2HALwcWNfZVPyF4DMshQ\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 110,
    "path": "../public/_nuxt/BP_2GkDo.js"
  },
  "/_nuxt/BqQuAQGq.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-CdnJbsqY+kcEJz0IFAWa6uNVEbQ\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 122,
    "path": "../public/_nuxt/BqQuAQGq.js"
  },
  "/_nuxt/BqCjnaYt.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-+Rd6N2HR5PM1zChkl0DwAIV1Bvw\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 110,
    "path": "../public/_nuxt/BqCjnaYt.js"
  },
  "/_nuxt/BP8jyfZY.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"1815-VRWdCSbLs0XOYU14sqJTGrwmJRM\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 6165,
    "path": "../public/_nuxt/BP8jyfZY.js"
  },
  "/_nuxt/BQRTvxg5.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-+pjEsgFAYbowgXCR199gyAIxgSk\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 120,
    "path": "../public/_nuxt/BQRTvxg5.js"
  },
  "/_nuxt/BqY6Tn69.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-xl5AF96Z70HeoEj3IROYkvmFRKQ\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/BqY6Tn69.js"
  },
  "/_nuxt/Br0nj1Ih.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-GXavBvWBrMGdVhAWqcpDKZtTGQw\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 119,
    "path": "../public/_nuxt/Br0nj1Ih.js"
  },
  "/_nuxt/BRainTX9.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-PTByRMkuSK0OrYFPpTByQNo1qqA\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 107,
    "path": "../public/_nuxt/BRainTX9.js"
  },
  "/_nuxt/BrmCXRwk.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"80-snncYbjIiFMEWTXXHuY3+8c6xgE\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 128,
    "path": "../public/_nuxt/BrmCXRwk.js"
  },
  "/_nuxt/BTjOtKLC.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-P/u7i5gPG1rvGjGr7LhhBuU8sSw\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 119,
    "path": "../public/_nuxt/BTjOtKLC.js"
  },
  "/_nuxt/BtamTzRD.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-sxi5omKXrt6i4PnZFQXEpV210ss\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 110,
    "path": "../public/_nuxt/BtamTzRD.js"
  },
  "/_nuxt/BtLtCxgf.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-t/iTmGgUCQrXbd5+D/BnGgtW4K0\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 114,
    "path": "../public/_nuxt/BtLtCxgf.js"
  },
  "/_nuxt/BTY0Gz96.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6c-z7UUTthLCIimoYAono1YsxTEnXw\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 108,
    "path": "../public/_nuxt/BTY0Gz96.js"
  },
  "/_nuxt/BU0Ly8my.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6f-hc5WnNpejw9AB/viBHScjZ7Iw8I\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 111,
    "path": "../public/_nuxt/BU0Ly8my.js"
  },
  "/_nuxt/BVAOFsF3.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-qFuVCitJGRnlJyx5Tufn59GGOds\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/BVAOFsF3.js"
  },
  "/_nuxt/BVE7Eqz8.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-yt3IkOvbzsldye6fp7CLwpCTamg\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/BVE7Eqz8.js"
  },
  "/_nuxt/BvExopgk.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-LL/sba/fvwYiGyNZLmRuu/D9QBU\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/BvExopgk.js"
  },
  "/_nuxt/BvgaGHup.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"79-qhzWPdw8rXDe9MwaXyn3ZoD2WaE\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 121,
    "path": "../public/_nuxt/BvgaGHup.js"
  },
  "/_nuxt/BvVI3v3t.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6d-Yl8KkaFk8kiJ8EmFFwBNA+PDYww\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 109,
    "path": "../public/_nuxt/BvVI3v3t.js"
  },
  "/_nuxt/BVhO9Dj8.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-SuyvqZzmpi4xp9QHDlayorCwEyo\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 110,
    "path": "../public/_nuxt/BVhO9Dj8.js"
  },
  "/_nuxt/Bv_OvzT0.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-c2W5YIbDnJXOQWGvo+AtSn33pD4\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 110,
    "path": "../public/_nuxt/Bv_OvzT0.js"
  },
  "/_nuxt/BVxLVdLB.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-woFa+KJ9YROAla1yyYt+p2+2R94\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 122,
    "path": "../public/_nuxt/BVxLVdLB.js"
  },
  "/_nuxt/BWpxbC2u.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-WU4y6ZWzdZFNiO6gKlT3X2VNUYE\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/BWpxbC2u.js"
  },
  "/_nuxt/BwP7Odd1.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"76-Uj025FScNO1F5nFej/V8kUwwTIo\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 118,
    "path": "../public/_nuxt/BwP7Odd1.js"
  },
  "/_nuxt/BWyvrGY-.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"70-906ycL2uLODQAbLFs34n8OMKmRM\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 112,
    "path": "../public/_nuxt/BWyvrGY-.js"
  },
  "/_nuxt/BXQDjvKr.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"70-DJZP9rXP03Qh2jBaJHyARFgRg7k\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 112,
    "path": "../public/_nuxt/BXQDjvKr.js"
  },
  "/_nuxt/BXREO1x-.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6f-RHGKoAiX3Hq5FP5leDare9rjkRs\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 111,
    "path": "../public/_nuxt/BXREO1x-.js"
  },
  "/_nuxt/BXqnEsrP.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-Hwijy9GVA1oHRqqAoY8E/wiAWLc\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 114,
    "path": "../public/_nuxt/BXqnEsrP.js"
  },
  "/_nuxt/BybfkGUZ.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"74-8tVCUzp/E3kUOoFmpJeZGL1U+Ok\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 116,
    "path": "../public/_nuxt/BybfkGUZ.js"
  },
  "/_nuxt/BYK4DuGZ.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6f-pzSjYDCHazhGsa3cARGP7VU585s\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 111,
    "path": "../public/_nuxt/BYK4DuGZ.js"
  },
  "/_nuxt/BysggM4K.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-8EET7QRpdZrSFMfKAyqzLjkKRNs\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 110,
    "path": "../public/_nuxt/BysggM4K.js"
  },
  "/_nuxt/BzOLXp3T.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-jrGuyOVHIAyn7sH9Zut1pzE7hO4\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/BzOLXp3T.js"
  },
  "/_nuxt/BztJPIjd.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-q9poBOLRwYXCyW1mASgmZAAit90\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 114,
    "path": "../public/_nuxt/BztJPIjd.js"
  },
  "/_nuxt/BzYBnY4K.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-UUchSzp/2eu2038EBphNGEs12VA\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 107,
    "path": "../public/_nuxt/BzYBnY4K.js"
  },
  "/_nuxt/B_KWpuUu.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-+AnKDughOBy2ICS+X+/j9piOnis\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 114,
    "path": "../public/_nuxt/B_KWpuUu.js"
  },
  "/_nuxt/C--4TD-K.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6f-FIxQp42YrU+jwRKNCG3k3YDGvA8\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 111,
    "path": "../public/_nuxt/C--4TD-K.js"
  },
  "/_nuxt/C1NSXozF.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7f-lfq12tBV9oeJV7/eTd9HloLyILc\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 127,
    "path": "../public/_nuxt/C1NSXozF.js"
  },
  "/_nuxt/C0QxYqHJ.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-S7VxiyNeziJpf+6k6DKsyDm2x/A\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 120,
    "path": "../public/_nuxt/C0QxYqHJ.js"
  },
  "/_nuxt/c1P1CmHZ.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-gRkYAEZ9Ub1Vat3hwkRgtBlkP1k\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/c1P1CmHZ.js"
  },
  "/_nuxt/C3bPD7Pm.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-aW8dfFULhY1qIhMjlGH5x3a0D3k\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 110,
    "path": "../public/_nuxt/C3bPD7Pm.js"
  },
  "/_nuxt/C2fipL7h.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6a-JY9b1/fR7rzOlcOb8ZQGYSrpThE\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 106,
    "path": "../public/_nuxt/C2fipL7h.js"
  },
  "/_nuxt/C2tH_Jo8.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-HhaGgk4imC7gjIqeRup85dVfjFc\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/C2tH_Jo8.js"
  },
  "/_nuxt/C3KwjLSI.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-7QAWA40SaosuFdFes4yu9sLlymo\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 119,
    "path": "../public/_nuxt/C3KwjLSI.js"
  },
  "/_nuxt/C3RFj0Jm.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6d-Yl8KkaFk8kiJ8EmFFwBNA+PDYww\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 109,
    "path": "../public/_nuxt/C3RFj0Jm.js"
  },
  "/_nuxt/C3fidEON.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"70-P5PkHdsKcjeKjq2PfCuideJbW3c\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 112,
    "path": "../public/_nuxt/C3fidEON.js"
  },
  "/_nuxt/C3PQHnAR.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6a-6TAkQIHe+hxKs7B2A1jMIip1c1c\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 106,
    "path": "../public/_nuxt/C3PQHnAR.js"
  },
  "/_nuxt/C3PYRDmC.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6a-JctHxUK+f0rZW94er8/z9rtpzu8\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 106,
    "path": "../public/_nuxt/C3PYRDmC.js"
  },
  "/_nuxt/C4oJcWOr.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-KRNT4qYmSYgpllZnsWO2z8nZyUA\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/C4oJcWOr.js"
  },
  "/_nuxt/C4iYip0L.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"70-+pEFsSM+O8GBpFBpd2pxELLcl9o\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 112,
    "path": "../public/_nuxt/C4iYip0L.js"
  },
  "/_nuxt/C4XDZMRv.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-T791J8F/+nZ+BlZccSu3CB3CFFw\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 119,
    "path": "../public/_nuxt/C4XDZMRv.js"
  },
  "/_nuxt/C5mQxzeb.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-3k2KiNaMgRf3cDKdRXif78kNz64\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 119,
    "path": "../public/_nuxt/C5mQxzeb.js"
  },
  "/_nuxt/C7ZN-9a0.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-hAcUw+RLzLEf2tx6jpcUaTYulxA\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 120,
    "path": "../public/_nuxt/C7ZN-9a0.js"
  },
  "/_nuxt/C66RgGYx.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-RnrAEFZxLaOPNplxVWcXaxyb7OQ\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 107,
    "path": "../public/_nuxt/C66RgGYx.js"
  },
  "/_nuxt/C8rSH0y6.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-vDi0fL7wDjL2fROM3GeI0N5FC7E\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 114,
    "path": "../public/_nuxt/C8rSH0y6.js"
  },
  "/_nuxt/C8_kTyVY.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-MKN433wFOxlJ5zEqxar1Mn4ARNE\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/C8_kTyVY.js"
  },
  "/_nuxt/Ca-11Wzn.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-nkQfB7QlghJfnD+kBxX62Fl4AgA\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 119,
    "path": "../public/_nuxt/Ca-11Wzn.js"
  },
  "/_nuxt/CAR7.s6CL6QYq.webp": {
    "type": "image/webp",
    "etag": "\"69338-ND42OkRkYFIirLw4Y5ayu5zFWWI\"",
    "mtime": "2026-09-28T12:17:37.578Z",
    "size": 430904,
    "path": "../public/_nuxt/CAR7.s6CL6QYq.webp"
  },
  "/_nuxt/CA6cZALg.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"80-b89a4EZdfXh4N6AjfW4grSQg7dM\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 128,
    "path": "../public/_nuxt/CA6cZALg.js"
  },
  "/_nuxt/CaE7PhIa.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"80-YDbFRFtczW2am9rrsWP8vSMJkHU\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 128,
    "path": "../public/_nuxt/CaE7PhIa.js"
  },
  "/_nuxt/CAR1.CfAaLoK1.webp": {
    "type": "image/webp",
    "etag": "\"98c4a-xjLnLoJSThu5Fh2U4ODy+vCryZY\"",
    "mtime": "2026-09-28T12:17:37.609Z",
    "size": 625738,
    "path": "../public/_nuxt/CAR1.CfAaLoK1.webp"
  },
  "/_nuxt/CAR11.DIfiLRDk.webp": {
    "type": "image/webp",
    "etag": "\"fd6ac-LF9e40X8/r1XU6MTVnktGF2pDt4\"",
    "mtime": "2026-09-28T12:17:37.610Z",
    "size": 1037996,
    "path": "../public/_nuxt/CAR11.DIfiLRDk.webp"
  },
  "/_nuxt/CbLAL9lJ.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-8NZ7PvC65k9qE6dDA1FqutEn5gs\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 113,
    "path": "../public/_nuxt/CbLAL9lJ.js"
  },
  "/_nuxt/CBY5e6mY.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6a-jnG9d0jascQx1fincpIJ5Lj2Tvs\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 106,
    "path": "../public/_nuxt/CBY5e6mY.js"
  },
  "/_nuxt/CC54Gjqz.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-/7aWGNERP/S47QSkaXjczOhCOhE\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/CC54Gjqz.js"
  },
  "/_nuxt/CcbKSEzp.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-YH+TsY/ee4x1jhzaVz2D7fatTVs\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/CcbKSEzp.js"
  },
  "/_nuxt/CcmcPfwp.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"80-aXWiPviXtjCgPPc4DUn+lB33kUI\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 128,
    "path": "../public/_nuxt/CcmcPfwp.js"
  },
  "/_nuxt/CazYgNM4.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"14f4-zR0s9fp3e2EfnMzTelTKiNG541Q\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 5364,
    "path": "../public/_nuxt/CazYgNM4.js"
  },
  "/_nuxt/Cd6Zv895.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-rMtC2mawi3Y/OhXDX/futu7y0Hw\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 110,
    "path": "../public/_nuxt/Cd6Zv895.js"
  },
  "/_nuxt/CE15wg5g.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-OF1IuzhPCp3Vjs2FCmS3LGL9C5c\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 113,
    "path": "../public/_nuxt/CE15wg5g.js"
  },
  "/_nuxt/CEIXKwDv.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-T+hqq7lK/AUmqERw8AFuJbMt5bE\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/CEIXKwDv.js"
  },
  "/_nuxt/CeA_AIA3.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-n73hlNfdZMN0wQqJJCdwBxEC+qQ\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 114,
    "path": "../public/_nuxt/CeA_AIA3.js"
  },
  "/_nuxt/CE5Snwmd.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-FCz0Urm7mhizT0lLw5MszcpL6t8\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 122,
    "path": "../public/_nuxt/CE5Snwmd.js"
  },
  "/_nuxt/Cf2lm2vZ.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"80-jToj6Fpui4xpBN1WWX8gjnhrptw\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 128,
    "path": "../public/_nuxt/Cf2lm2vZ.js"
  },
  "/_nuxt/CfRGQJF1.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-Mw3sgAitGJhXOFnZj+40CVfB3UE\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 113,
    "path": "../public/_nuxt/CfRGQJF1.js"
  },
  "/_nuxt/CfFkaFCu.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-nqXu4qTzMQxFzkZbKDYvmDJbGYM\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 119,
    "path": "../public/_nuxt/CfFkaFCu.js"
  },
  "/_nuxt/Cgn2tUY5.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-2i4Ro20gLarlnzQa90ip/89qQzo\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 122,
    "path": "../public/_nuxt/Cgn2tUY5.js"
  },
  "/_nuxt/CHVS6ukd.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-rMtC2mawi3Y/OhXDX/futu7y0Hw\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 110,
    "path": "../public/_nuxt/CHVS6ukd.js"
  },
  "/_nuxt/ChYMowXn.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-bgVb8KTDAUXpfnhj3n9bZW3vhLo\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 110,
    "path": "../public/_nuxt/ChYMowXn.js"
  },
  "/_nuxt/CGrIMdAV.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6a-n7i3uhVvbSKhbEoYC3ciByDntv0\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 106,
    "path": "../public/_nuxt/CGrIMdAV.js"
  },
  "/_nuxt/Ch7XCB4N.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-WtgyZDUC1HRcctZ2S6knHV0VFFU\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 110,
    "path": "../public/_nuxt/Ch7XCB4N.js"
  },
  "/_nuxt/Chqoxm5g.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-5OUb3v+tiYrCgWNX40R9sw7gjVc\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 113,
    "path": "../public/_nuxt/Chqoxm5g.js"
  },
  "/_nuxt/CimZlPR7.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-J5VTp5O3Mbbp2c9B76dG6NsR1AY\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 107,
    "path": "../public/_nuxt/CimZlPR7.js"
  },
  "/_nuxt/CiEdU7Fo.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"69-p6527c88RJroWGej7KbE9AGuXeI\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 105,
    "path": "../public/_nuxt/CiEdU7Fo.js"
  },
  "/_nuxt/CIFnZHZ0.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-seGICRoLNzpGYp86yiPpaGNpvzI\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 120,
    "path": "../public/_nuxt/CIFnZHZ0.js"
  },
  "/_nuxt/CIT77YrY.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"75-UpQu/cBDXOVFOIye+VPjnLyi/jY\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 117,
    "path": "../public/_nuxt/CIT77YrY.js"
  },
  "/_nuxt/CIXX18-U.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-QxtqmjFRiV0++s1jWS+NZQhgSgg\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 107,
    "path": "../public/_nuxt/CIXX18-U.js"
  },
  "/_nuxt/CJfw57Ow.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-KEvUTETyRRAeZxrcjcrpOlteUK4\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/CJfw57Ow.js"
  },
  "/_nuxt/CJqKBLGX.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-eibDdsX5EhLZYWNTpmM7LvKHxSg\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/CJqKBLGX.js"
  },
  "/_nuxt/CJxCG_ti.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-YEHIQ0FaVa3oQgcj+057r5jjPr8\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 113,
    "path": "../public/_nuxt/CJxCG_ti.js"
  },
  "/_nuxt/CKfbzdgU.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-0p6tvV7uOGPTG71f7o3CHj+Mz1M\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 110,
    "path": "../public/_nuxt/CKfbzdgU.js"
  },
  "/_nuxt/CJVN4S77.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-TTBY0SxvE1E0M8c3asWlclsAvbc\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 119,
    "path": "../public/_nuxt/CJVN4S77.js"
  },
  "/_nuxt/CJ_BBQW7.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-F0Dt21SUso9Z9O2RlXp8y95Q9+g\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 107,
    "path": "../public/_nuxt/CJ_BBQW7.js"
  },
  "/_nuxt/Ckf-6rwS.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-Swv7LEbWP7rt2tui6egOWpP7IVA\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 115,
    "path": "../public/_nuxt/Ckf-6rwS.js"
  },
  "/_nuxt/CKiJIt-W.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-cfIxxf7YjHdv4C+7/6uwwc3MXmo\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/CKiJIt-W.js"
  },
  "/_nuxt/CKxND_5L.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-xFoN/tICHeP6ji53/HhlyeMbcyk\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/CKxND_5L.js"
  },
  "/_nuxt/CKfLSAQ_.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-g/Ndgu78uaq0sXWpRLyI4Lll38I\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 114,
    "path": "../public/_nuxt/CKfLSAQ_.js"
  },
  "/_nuxt/Cl8-lkl-.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-mk86ypuK3yK+BqjnGNEi+uqT0Cc\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/Cl8-lkl-.js"
  },
  "/_nuxt/ClDYYMVA.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-wzbCIQnVhP+SRuQeGMN1J/47OxY\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/ClDYYMVA.js"
  },
  "/_nuxt/Cl9A9j2i.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6a-uFD4O9hWRWFWj1YZgSm31wuTjSk\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 106,
    "path": "../public/_nuxt/Cl9A9j2i.js"
  },
  "/_nuxt/CLQjbXXX.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-Ec8MveyfxfHdk8lhLUNt51OPvfc\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 120,
    "path": "../public/_nuxt/CLQjbXXX.js"
  },
  "/_nuxt/ClY2CO4T.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7f-1lONM0Pri2nXFhmh4PvIZYEkBCc\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 127,
    "path": "../public/_nuxt/ClY2CO4T.js"
  },
  "/_nuxt/CN1jIs7F.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-iyL6hrSyzZsvzs1rOON5TYoQVc0\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 107,
    "path": "../public/_nuxt/CN1jIs7F.js"
  },
  "/_nuxt/CmjoFR5P.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-4jPiZC28RXz5oTCDs8Iza7qMF50\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 119,
    "path": "../public/_nuxt/CmjoFR5P.js"
  },
  "/_nuxt/CMy-tZHG.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-iaa2d/frfCkVt/PFT7Sq6Cc0rqE\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 114,
    "path": "../public/_nuxt/CMy-tZHG.js"
  },
  "/_nuxt/CM7D-9p9.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-4jtL1tuEXQlFS3yOsMHwl70heNA\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/CM7D-9p9.js"
  },
  "/_nuxt/Cn4WTA6m.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"80-y2HFX8iyelN3cbq93PSR8uB+DSA\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 128,
    "path": "../public/_nuxt/Cn4WTA6m.js"
  },
  "/_nuxt/CNaZsWRk.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-Qmr4SUDFcJEAi9PT3FLyi/oJL6s\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/CNaZsWRk.js"
  },
  "/_nuxt/CNhu9baQ.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-L+8i/cjZE76lCIHyjBjAkrPhaCQ\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 113,
    "path": "../public/_nuxt/CNhu9baQ.js"
  },
  "/_nuxt/Cnuu6Feg.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-xHiAY6oluEqeWl0SuaEtV9khddY\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 107,
    "path": "../public/_nuxt/Cnuu6Feg.js"
  },
  "/_nuxt/CnX5MaYc.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-z/xvFyu8O/YHfLETzTM7rpyApMI\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 110,
    "path": "../public/_nuxt/CnX5MaYc.js"
  },
  "/_nuxt/cover.7ceMDOgG.webp": {
    "type": "image/webp",
    "etag": "\"3ee22-/OlANjjdc6lRPd9an7KyiBV+QVY\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 257570,
    "path": "../public/_nuxt/cover.7ceMDOgG.webp"
  },
  "/_nuxt/Cov3BCny.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-7W3ZZ8zPMPcXogl3g6bbV3bZ+Ps\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 110,
    "path": "../public/_nuxt/Cov3BCny.js"
  },
  "/_nuxt/COsTg9Bo.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-TIr528iqQh6pOk2p7kf3VzaMzqs\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/COsTg9Bo.js"
  },
  "/_nuxt/cover.BKPcW-dq.webp": {
    "type": "image/webp",
    "etag": "\"57f86-VyzxBN6E4VCfCdn3njraEiY4CDw\"",
    "mtime": "2026-09-28T12:17:37.579Z",
    "size": 360326,
    "path": "../public/_nuxt/cover.BKPcW-dq.webp"
  },
  "/_nuxt/COEZYdae.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6a-EQDbQQ8OZB18hd5CBftbFH4V/a0\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 106,
    "path": "../public/_nuxt/COEZYdae.js"
  },
  "/_nuxt/cover.ChTDDioM.webp": {
    "type": "image/webp",
    "etag": "\"16476-HR25Rgy/HZSeY4UAG0kye5yhGxs\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 91254,
    "path": "../public/_nuxt/cover.ChTDDioM.webp"
  },
  "/_nuxt/cover.CaVQKLim.webp": {
    "type": "image/webp",
    "etag": "\"bae08-rHBo+2b6o2M3S3c7egKu2IeNNwU\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 765448,
    "path": "../public/_nuxt/cover.CaVQKLim.webp"
  },
  "/_nuxt/cover.0yX1GJn1.mp4": {
    "type": "video/mp4",
    "etag": "\"1664b4-XUvsbLH+9TKo2Iil5Oz96EDmHeM\"",
    "mtime": "2026-09-28T12:17:37.893Z",
    "size": 1467572,
    "path": "../public/_nuxt/cover.0yX1GJn1.mp4"
  },
  "/_nuxt/cover.Cimrt0SM.webp": {
    "type": "image/webp",
    "etag": "\"62fbe-qKEx0FHCdGHUYW744vJTl6+mubM\"",
    "mtime": "2026-09-28T12:17:37.578Z",
    "size": 405438,
    "path": "../public/_nuxt/cover.Cimrt0SM.webp"
  },
  "/_nuxt/cover.CxiBEX1E.jpg": {
    "type": "image/jpeg",
    "etag": "\"4b437-jloMA3Q2//01aAywFK0Z6BKgElA\"",
    "mtime": "2026-09-28T12:17:37.580Z",
    "size": 308279,
    "path": "../public/_nuxt/cover.CxiBEX1E.jpg"
  },
  "/_nuxt/cover.CiP-YfJb.webp": {
    "type": "image/webp",
    "etag": "\"e28ba-QqcMl/zKVUrUIUFjXw0CffZC+NE\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 927930,
    "path": "../public/_nuxt/cover.CiP-YfJb.webp"
  },
  "/_nuxt/cover.ClBGkUTF.jpg": {
    "type": "image/jpeg",
    "etag": "\"8df29-7BOY6jpgQSHNavDfldMtB7HttJA\"",
    "mtime": "2026-09-28T12:17:37.610Z",
    "size": 581417,
    "path": "../public/_nuxt/cover.ClBGkUTF.jpg"
  },
  "/_nuxt/cover.CO4JoPds.webp": {
    "type": "image/webp",
    "etag": "\"e3808-JPtxyAgE2a6tu4179iFyp/ze2O8\"",
    "mtime": "2026-09-28T12:17:37.609Z",
    "size": 931848,
    "path": "../public/_nuxt/cover.CO4JoPds.webp"
  },
  "/_nuxt/cover.DAQl52_n.jpg": {
    "type": "image/jpeg",
    "etag": "\"56bf3-1MBIlnBHmRcociziQHFOdythFlM\"",
    "mtime": "2026-09-28T12:17:37.579Z",
    "size": 355315,
    "path": "../public/_nuxt/cover.DAQl52_n.jpg"
  },
  "/_nuxt/cover.DxYdqjXM.webp": {
    "type": "image/webp",
    "etag": "\"79ffe-NLz/R73zQfnluvl45pHreeQcQVE\"",
    "mtime": "2026-09-28T12:17:37.580Z",
    "size": 499710,
    "path": "../public/_nuxt/cover.DxYdqjXM.webp"
  },
  "/_nuxt/cover.D38fduN5.webp": {
    "type": "image/webp",
    "etag": "\"bff88-kyi2i7/3CLJQ5qTZCmZMVPRANdg\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 786312,
    "path": "../public/_nuxt/cover.D38fduN5.webp"
  },
  "/_nuxt/cover.lZMCPWon.webp": {
    "type": "image/webp",
    "etag": "\"5ecf6-0nioeVVGmT/AjmO2CoN5IoESi1I\"",
    "mtime": "2026-09-28T12:17:37.583Z",
    "size": 388342,
    "path": "../public/_nuxt/cover.lZMCPWon.webp"
  },
  "/_nuxt/cover.CRTP11wM.webp": {
    "type": "image/webp",
    "etag": "\"12fdc8-8jt/aFAMc7tOULQGr0RE1+AC/KE\"",
    "mtime": "2026-09-28T12:17:37.894Z",
    "size": 1244616,
    "path": "../public/_nuxt/cover.CRTP11wM.webp"
  },
  "/_nuxt/cover.DT-HegK-.webp": {
    "type": "image/webp",
    "etag": "\"b06ec-nJSYLHRG2ghi0hwKJElW8ODj3GI\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 722668,
    "path": "../public/_nuxt/cover.DT-HegK-.webp"
  },
  "/_nuxt/cover.XkQNWBiL.webp": {
    "type": "image/webp",
    "etag": "\"586d4-P2wgxrY5cFebB/9iSS53TobAmks\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 362196,
    "path": "../public/_nuxt/cover.XkQNWBiL.webp"
  },
  "/_nuxt/cover.BpIha6Ys.jpg": {
    "type": "image/jpeg",
    "etag": "\"256c0a-iAfYBSRnU88cJDVzp6WsuWh7ngQ\"",
    "mtime": "2026-09-28T12:17:37.920Z",
    "size": 2452490,
    "path": "../public/_nuxt/cover.BpIha6Ys.jpg"
  },
  "/_nuxt/cover.BATmarDZ.gif": {
    "type": "image/gif",
    "etag": "\"2c2109-ut9h0RcqfIxm6v7cKjFTP8MzLiY\"",
    "mtime": "2026-09-28T12:17:37.920Z",
    "size": 2892041,
    "path": "../public/_nuxt/cover.BATmarDZ.gif"
  },
  "/_nuxt/CP2OKeEZ.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-k27CRGb3KGseBiTlX7Eoi9UCzWY\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 107,
    "path": "../public/_nuxt/CP2OKeEZ.js"
  },
  "/_nuxt/Cp74kZM7.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"80-+bWg83Bi542AxjGDMtUE7GzprLc\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 128,
    "path": "../public/_nuxt/Cp74kZM7.js"
  },
  "/_nuxt/CpafN4aD.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-dZcEUUyz7TZzngl83B5q/rWpdKc\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/CpafN4aD.js"
  },
  "/_nuxt/CP6Ykz4I.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-oz/Vcf2j/blJK2UuqNGeTurHm7Y\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 110,
    "path": "../public/_nuxt/CP6Ykz4I.js"
  },
  "/_nuxt/cover.D8RHNoUY.webp": {
    "type": "image/webp",
    "etag": "\"1dc830-I9bRpmxeCB3Ce5rbS5h3yqfMirI\"",
    "mtime": "2026-09-28T12:17:37.915Z",
    "size": 1951792,
    "path": "../public/_nuxt/cover.D8RHNoUY.webp"
  },
  "/_nuxt/cover.DeCBpyt9.mp4": {
    "type": "video/mp4",
    "etag": "\"194af1-Yb6hWIGQxrJUy5+kuQqeMykJftw\"",
    "mtime": "2026-09-28T12:17:37.915Z",
    "size": 1657585,
    "path": "../public/_nuxt/cover.DeCBpyt9.mp4"
  },
  "/_nuxt/CphvekiE.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-7NagoafzgB4Hv6CEdVl0ByB3iJs\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 119,
    "path": "../public/_nuxt/CphvekiE.js"
  },
  "/_nuxt/CPWZyEhA.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-Eo18I4K1bCwNAA/o7FfnHgYlWN8\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 107,
    "path": "../public/_nuxt/CPWZyEhA.js"
  },
  "/_nuxt/CPyTkZBK.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"70-O7BgSggVaL5HGeqbDG2wC8Mn/rY\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 112,
    "path": "../public/_nuxt/CPyTkZBK.js"
  },
  "/_nuxt/CPZT2u03.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-thvoabkYo70HVVp7yHE+sBF3y28\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 114,
    "path": "../public/_nuxt/CPZT2u03.js"
  },
  "/_nuxt/CpsRHu6l.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"797-Ag78b+wmAWKScuDwLFAfxQAYXp0\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 1943,
    "path": "../public/_nuxt/CpsRHu6l.js"
  },
  "/_nuxt/CQ0pTFOY.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-mGSSLLesfHHTIU0/HbWI30ErZkw\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 120,
    "path": "../public/_nuxt/CQ0pTFOY.js"
  },
  "/_nuxt/CQ3ibvNF.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-CTmEaOc7n8cWy0nfqFf3VAq/1U8\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 107,
    "path": "../public/_nuxt/CQ3ibvNF.js"
  },
  "/_nuxt/CqoK6hzZ.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6a-ybGiQSi+BIa/Gc6W+Ro3QhICerQ\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 106,
    "path": "../public/_nuxt/CqoK6hzZ.js"
  },
  "/_nuxt/CqyjMFxS.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-Dbe9OLuDKtXSZmkGzocmddHqMV4\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/CqyjMFxS.js"
  },
  "/_nuxt/CR4t203m.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-mQQJW5AHWINmJ7l8TIXKJGQUPb8\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/CR4t203m.js"
  },
  "/_nuxt/Cr66_720.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-1X+6q+WFu4HzMou4fX8QRqUQz0o\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 119,
    "path": "../public/_nuxt/Cr66_720.js"
  },
  "/_nuxt/CRbO9t_-.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-DvVx2f47OJuIOTVCGIbu9+o9w20\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 107,
    "path": "../public/_nuxt/CRbO9t_-.js"
  },
  "/_nuxt/Creg8edA.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6f-Nl7ATbum93TBeQEb4rW0BNeY13E\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 111,
    "path": "../public/_nuxt/Creg8edA.js"
  },
  "/_nuxt/CrPj2GVl.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-u6L50vtyefqhzI+FskhiSp5cT6k\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 119,
    "path": "../public/_nuxt/CrPj2GVl.js"
  },
  "/_nuxt/CS27akg9.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-LWFa2Owwz9uG0r53HpcSt67AU6U\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/CS27akg9.js"
  },
  "/_nuxt/CskvFnwS.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-TNNW83aBskQjIvm0OYQlK7T6Bc8\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 122,
    "path": "../public/_nuxt/CskvFnwS.js"
  },
  "/_nuxt/Csr1r5Av.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-IKB055E0KEiN0OltIru3dsXxYuw\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 114,
    "path": "../public/_nuxt/Csr1r5Av.js"
  },
  "/_nuxt/cover.CxMhcwUC.mp4": {
    "type": "video/mp4",
    "etag": "\"469029-yQNV8SO8FMYCaYrzeAt+0VSexcA\"",
    "mtime": "2026-09-28T12:17:37.921Z",
    "size": 4624425,
    "path": "../public/_nuxt/cover.CxMhcwUC.mp4"
  },
  "/_nuxt/CssjEIjx.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"70-lhIPyex/+nQfZf7EzOVK+IMkjFo\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 112,
    "path": "../public/_nuxt/CssjEIjx.js"
  },
  "/_nuxt/CtfzkEOP.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-QiqpwoJDbsXXvsQboYuVIAxtWos\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 107,
    "path": "../public/_nuxt/CtfzkEOP.js"
  },
  "/_nuxt/Cs_sFGog.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-Ylqch/sWrKb3ZPacpfkJ/9WJXEw\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 119,
    "path": "../public/_nuxt/Cs_sFGog.js"
  },
  "/_nuxt/CtIthEmo.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"75-YBG3eI+UJQt4GQO/a8zEZ6daaE8\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 117,
    "path": "../public/_nuxt/CtIthEmo.js"
  },
  "/_nuxt/CUlJdr9F.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-Jc0iDK4dOx8gKyjguOkC2yOScTc\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/CUlJdr9F.js"
  },
  "/_nuxt/CTJBREMr.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-Fg0qQykYeArYgp2a3g4egB0t/Zs\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/CTJBREMr.js"
  },
  "/_nuxt/CTmm2nR8.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-v2ncIJwMcdZHBZWaFCqgXFL14Dw\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 119,
    "path": "../public/_nuxt/CTmm2nR8.js"
  },
  "/_nuxt/CuMGwE3c.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6c-jtx13OUwX8QLJ9wt6kW13Qab0Dk\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 108,
    "path": "../public/_nuxt/CuMGwE3c.js"
  },
  "/_nuxt/CV2OhAWd.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"70-7n31nSBuDz2tVeChhccCVzXTvOg\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 112,
    "path": "../public/_nuxt/CV2OhAWd.js"
  },
  "/_nuxt/CvocXXkK.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-t4gb7Ye0HjtjUJVypGqiOCKpxtg\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 122,
    "path": "../public/_nuxt/CvocXXkK.js"
  },
  "/_nuxt/CVx5vVf6.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-jxZF27IHlLWrK/OP9GxNJ/tc2SU\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 114,
    "path": "../public/_nuxt/CVx5vVf6.js"
  },
  "/_nuxt/CvXUpK4B.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-R+STgYlBl+eZkoBKC6UmDuVxzfA\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/CvXUpK4B.js"
  },
  "/_nuxt/CX6U-Jl2.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-2pDacTbqCkDeFSry2yjSvFinM/8\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 110,
    "path": "../public/_nuxt/CX6U-Jl2.js"
  },
  "/_nuxt/CW03aXtK.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-2I0cX/gqVnGjbYMwh+pDZzaz9U0\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 110,
    "path": "../public/_nuxt/CW03aXtK.js"
  },
  "/_nuxt/CWmestt_.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"70-VdG2SPbh8xmUPNKY2qmGewWPF+s\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 112,
    "path": "../public/_nuxt/CWmestt_.js"
  },
  "/_nuxt/CWWkJAGZ.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-Fbi79BUmkPkWRHnwaR6sSYXgdLQ\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/CWWkJAGZ.js"
  },
  "/_nuxt/CX8btkhK.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-SueUR5xGyqepnatTyK3EdjEvEXg\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 119,
    "path": "../public/_nuxt/CX8btkhK.js"
  },
  "/_nuxt/Cx9rQIPP.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-1u8FkZHySi2QxOsajwJLr/xmHsY\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 110,
    "path": "../public/_nuxt/Cx9rQIPP.js"
  },
  "/_nuxt/Cy3fw8Y3.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-v0SzC9QFccikIBuTLv1wT+t8Vyg\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 114,
    "path": "../public/_nuxt/Cy3fw8Y3.js"
  },
  "/_nuxt/CYPLiB4E.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6a-2+jHscaQvvx9okHxDlDHO4GNg6c\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 106,
    "path": "../public/_nuxt/CYPLiB4E.js"
  },
  "/_nuxt/CZbJd-Qe.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-Iuc7BpmRiCWXNWOzWRfcPNwKGsg\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 115,
    "path": "../public/_nuxt/CZbJd-Qe.js"
  },
  "/_nuxt/cover.BJ_p9HYa.mp4": {
    "type": "video/mp4",
    "etag": "\"7cccb3-18JAFkajcM17yY0lKAibwYGg3KA\"",
    "mtime": "2026-09-28T12:17:37.923Z",
    "size": 8178867,
    "path": "../public/_nuxt/cover.BJ_p9HYa.mp4"
  },
  "/_nuxt/CzDEUSYu.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6c-1T0TemdOHQSN7VaJpY4sS3EL0qA\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 108,
    "path": "../public/_nuxt/CzDEUSYu.js"
  },
  "/_nuxt/Cx928EFH.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"1932-ZfIxp5jeUe6f0lb1JMNdW8ptKwg\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 6450,
    "path": "../public/_nuxt/Cx928EFH.js"
  },
  "/_nuxt/CzNszyc0.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-TIBzRCl4z2FCNl7sYwUKfJXiBAM\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 114,
    "path": "../public/_nuxt/CzNszyc0.js"
  },
  "/_nuxt/C_fiaJTy.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-4yhyrhi7/oeVxzsFEUAaz3+bt1Q\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 110,
    "path": "../public/_nuxt/C_fiaJTy.js"
  },
  "/_nuxt/C_00Nck6.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"84-TBALJ2N8jSNOte9clxNdmgYi7bg\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 132,
    "path": "../public/_nuxt/C_00Nck6.js"
  },
  "/_nuxt/CzFCSDhk.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"d45-AbduDHzxOwJ7AHv8sKrXzef7V4g\"",
    "mtime": "2026-09-28T12:17:37.596Z",
    "size": 3397,
    "path": "../public/_nuxt/CzFCSDhk.js"
  },
  "/_nuxt/C_zxyE4s.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-l2yOW7on5YFem90akODySwlbrdI\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 119,
    "path": "../public/_nuxt/C_zxyE4s.js"
  },
  "/_nuxt/D0KaTYa3.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-lXvGcZYBZon9ndTPeadQG+Dc25g\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 110,
    "path": "../public/_nuxt/D0KaTYa3.js"
  },
  "/_nuxt/D-IFXPpk.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-fYiU+yApJ/5JX5wnIFsF2CM9mnY\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/D-IFXPpk.js"
  },
  "/_nuxt/D-pK0CKt.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-Ni288cetE7R0pgvxqLCZGbmhxgc\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 114,
    "path": "../public/_nuxt/D-pK0CKt.js"
  },
  "/_nuxt/D1W_T-xj.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-k27CRGb3KGseBiTlX7Eoi9UCzWY\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 107,
    "path": "../public/_nuxt/D1W_T-xj.js"
  },
  "/_nuxt/D-TKS7WZ.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-X7HXPtLvYEOTpKg5mZPzmez4doE\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 114,
    "path": "../public/_nuxt/D-TKS7WZ.js"
  },
  "/_nuxt/D0zHsG94.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-lb6hpVohZ0+if1+b4Ddo2GOFtP0\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 114,
    "path": "../public/_nuxt/D0zHsG94.js"
  },
  "/_nuxt/D21733BJ.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-+CtTo1eWD3TFz3Bw9GWOfv5gfTg\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 114,
    "path": "../public/_nuxt/D21733BJ.js"
  },
  "/_nuxt/D2i7E8Q-.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-GRSRnkEMGCX7wA1vw7ITpribK7I\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/D2i7E8Q-.js"
  },
  "/_nuxt/cover.DOD4l8zJ.mp4": {
    "type": "video/mp4",
    "etag": "\"7e5935-2oH85kWP9kUijzTwxOO499ZvtLM\"",
    "mtime": "2026-09-28T12:17:37.923Z",
    "size": 8280373,
    "path": "../public/_nuxt/cover.DOD4l8zJ.mp4"
  },
  "/_nuxt/D3FtJ3Aw.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-7W3ZZ8zPMPcXogl3g6bbV3bZ+Ps\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 110,
    "path": "../public/_nuxt/D3FtJ3Aw.js"
  },
  "/_nuxt/D2Q3DVim.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-eRpSowvlXf234Vaqclw5NBQDgPI\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/D2Q3DVim.js"
  },
  "/_nuxt/D3CGzUJg.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-7MfcjYW5NWGwKX+mNUBYv2s2rmk\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 114,
    "path": "../public/_nuxt/D3CGzUJg.js"
  },
  "/_nuxt/D3e9cWki.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-LR+SBC/dwY+Pxj7DKxHWkREmwwg\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 110,
    "path": "../public/_nuxt/D3e9cWki.js"
  },
  "/_nuxt/D4sg5Uio.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"75-sONl7y9g+U6Bg3wVxXzs4F/xn1k\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 117,
    "path": "../public/_nuxt/D4sg5Uio.js"
  },
  "/_nuxt/D5eRgFTP.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-SuyvqZzmpi4xp9QHDlayorCwEyo\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 110,
    "path": "../public/_nuxt/D5eRgFTP.js"
  },
  "/_nuxt/D5QhTu4t.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-CaqlNnnM/TnB2iL986y76KuY+xk\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/D5QhTu4t.js"
  },
  "/_nuxt/D6aRNtmH.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-z8eiQOOrbDEq7CZkoUrv9R+Yh74\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/D6aRNtmH.js"
  },
  "/_nuxt/D7owXVMf.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-kJ4ptW9lMYaX5mgVo0vWdQ8Mi0Q\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 120,
    "path": "../public/_nuxt/D7owXVMf.js"
  },
  "/_nuxt/D7Avl6HF.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-I80FrtvHwuwWOt7ClWLUOOgNDoc\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 119,
    "path": "../public/_nuxt/D7Avl6HF.js"
  },
  "/_nuxt/D86c-WWu.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-c2W5YIbDnJXOQWGvo+AtSn33pD4\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 110,
    "path": "../public/_nuxt/D86c-WWu.js"
  },
  "/_nuxt/D7Q-Tm7e.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-9pNK+z/v5l54o+BGor87i7NzaeI\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 107,
    "path": "../public/_nuxt/D7Q-Tm7e.js"
  },
  "/_nuxt/D85dVSPo.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-ZKqFa4Z4N3p3MGYHXLKG+OsB4NY\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 119,
    "path": "../public/_nuxt/D85dVSPo.js"
  },
  "/_nuxt/D8LGCEDh.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-xSTuVJE8aEgjLDtPQX+KhMaZhzI\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 110,
    "path": "../public/_nuxt/D8LGCEDh.js"
  },
  "/_nuxt/D8DHYPe8.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-ghA4umCOQDHsBV/545tmbtOLYDw\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 114,
    "path": "../public/_nuxt/D8DHYPe8.js"
  },
  "/_nuxt/D9fIJ7f3.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-F0Dt21SUso9Z9O2RlXp8y95Q9+g\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 107,
    "path": "../public/_nuxt/D9fIJ7f3.js"
  },
  "/_nuxt/D8mQ1nda.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-uXGhd9vMInF6wLTwdRIEirKUOH8\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 110,
    "path": "../public/_nuxt/D8mQ1nda.js"
  },
  "/_nuxt/D8w2kqf-.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-4XfRz8rfwzorWh8hhafiTwhv+Gk\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 110,
    "path": "../public/_nuxt/D8w2kqf-.js"
  },
  "/_nuxt/D9F_xDAx.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"80-Oufb67vzv464X+NONv3Ff9stkHg\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 128,
    "path": "../public/_nuxt/D9F_xDAx.js"
  },
  "/_nuxt/D9g-3oJE.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"76-zhP3We5vQAd3Sc/TDGR2Awe8OCc\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 118,
    "path": "../public/_nuxt/D9g-3oJE.js"
  },
  "/_nuxt/D9gNvd23.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-Kamnd1/kuq91lM7cxHCDCMTPALw\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 119,
    "path": "../public/_nuxt/D9gNvd23.js"
  },
  "/_nuxt/Dbp37h3K.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6c-1T0TemdOHQSN7VaJpY4sS3EL0qA\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 108,
    "path": "../public/_nuxt/Dbp37h3K.js"
  },
  "/_nuxt/D9vdrx83.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-hoXNZy1dN7LbwTWB7OL18Y3TBL0\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 114,
    "path": "../public/_nuxt/D9vdrx83.js"
  },
  "/_nuxt/D9Wf1i-B.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-X7JcUPdtTkjWmZXpv4Gc3xtrnQY\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/D9Wf1i-B.js"
  },
  "/_nuxt/D9WHeR3r.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-YyFmjvfB5QxKamXekDpM8+fdNQU\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/D9WHeR3r.js"
  },
  "/_nuxt/DC4fVH0j.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"85-b8DpDcqKmkaJQVSqzepo+KTnHs0\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 133,
    "path": "../public/_nuxt/DC4fVH0j.js"
  },
  "/_nuxt/Dcgoae_q.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-q9hZWsIOD94N6i3N2cuvEjryavU\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/Dcgoae_q.js"
  },
  "/_nuxt/DCsAV_CK.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-xUxLR50aRMRFVsCbwCteDc2ONsE\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 110,
    "path": "../public/_nuxt/DCsAV_CK.js"
  },
  "/_nuxt/DcXpOkzw.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-Lv/us0k4zaVqHNAYP/xqcLyoUCk\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/DcXpOkzw.js"
  },
  "/_nuxt/DcYeEq6c.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-GIjZYSJdRJpIn/RvsPzUkqOa1eY\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 119,
    "path": "../public/_nuxt/DcYeEq6c.js"
  },
  "/_nuxt/DDhktxkV.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-fqYawrWIpYHzO8Mz01EIi6S9/+0\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/DDhktxkV.js"
  },
  "/_nuxt/DD7RCrGA.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-3+YEYTHsI755sarHcylfBggMsAo\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 110,
    "path": "../public/_nuxt/DD7RCrGA.js"
  },
  "/_nuxt/06_LAVORAZIONI_2.DrS4Iar7.mp4": {
    "type": "video/mp4",
    "etag": "\"20733f5-f/0IrHtFsql9jWMypQVFBYQQP9U\"",
    "mtime": "2026-09-28T12:17:37.930Z",
    "size": 34026485,
    "path": "../public/_nuxt/06_LAVORAZIONI_2.DrS4Iar7.mp4"
  },
  "/_nuxt/DELG--VZ.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-pARwf/1YhPdXZuZPrvz12bVJEBI\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 119,
    "path": "../public/_nuxt/DELG--VZ.js"
  },
  "/_nuxt/DePk9nnN.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-B+/8B7cvnQmwJoFcBuNo7t3SZ1g\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 114,
    "path": "../public/_nuxt/DePk9nnN.js"
  },
  "/_nuxt/Df76J0OP.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-X1ed83Ge+X0HYZcrmS+GRh5/O2I\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 110,
    "path": "../public/_nuxt/Df76J0OP.js"
  },
  "/_nuxt/DeZLu3nj.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"10aae-wMEODPRrgihUwHFYajNCuIlFuNs\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 68270,
    "path": "../public/_nuxt/DeZLu3nj.js"
  },
  "/_nuxt/DFdDVW52.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-uXGhd9vMInF6wLTwdRIEirKUOH8\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 110,
    "path": "../public/_nuxt/DFdDVW52.js"
  },
  "/_nuxt/DfB83VUz.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-2nwyERaMEUXol7IsWGaYiONSMbM\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 114,
    "path": "../public/_nuxt/DfB83VUz.js"
  },
  "/_nuxt/DfaY7CDK.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6a-tPatzIdjrN+G3eYXuLtFPq8ADf8\"",
    "mtime": "2026-09-28T12:17:37.608Z",
    "size": 106,
    "path": "../public/_nuxt/DfaY7CDK.js"
  },
  "/_nuxt/DBo4MeDU.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"2e3e0-asu42y4lg/OT9HvWpIabNI0r/6I\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 189408,
    "path": "../public/_nuxt/DBo4MeDU.js"
  },
  "/_nuxt/DGa2FPz0.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-lrmuYpXtpm0gejpwId4goyK1Wi4\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 114,
    "path": "../public/_nuxt/DGa2FPz0.js"
  },
  "/_nuxt/Dgnq3WWc.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-hiTwb4PmJmUkSoNJevGaWANVMIw\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 113,
    "path": "../public/_nuxt/Dgnq3WWc.js"
  },
  "/_nuxt/DGNtWuNn.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"84-5xn5I4idQtjBgB+lweKuyaHcZSU\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 132,
    "path": "../public/_nuxt/DGNtWuNn.js"
  },
  "/_nuxt/DHiICEJs.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-QC/ls9r/6XpwKtSCKRXAy2RVU5A\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 119,
    "path": "../public/_nuxt/DHiICEJs.js"
  },
  "/_nuxt/Dettagli-B2B-3.DdOoLmC8.mp4": {
    "type": "video/mp4",
    "etag": "\"1bfeae-FK2hrvkrc0KKIeeL0LaP103HP/k\"",
    "mtime": "2026-09-28T12:17:37.915Z",
    "size": 1834670,
    "path": "../public/_nuxt/Dettagli-B2B-3.DdOoLmC8.mp4"
  },
  "/_nuxt/Dettagli-B2B.DpCRxc4S.mp4": {
    "type": "video/mp4",
    "etag": "\"1c9d2a-o8imehKVv8KNbb1hSI3/sVTe1MM\"",
    "mtime": "2026-09-28T12:17:37.915Z",
    "size": 1875242,
    "path": "../public/_nuxt/Dettagli-B2B.DpCRxc4S.mp4"
  },
  "/_nuxt/DI2_gXqB.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-XPLx9J2in5LwOTEOK//K6CG15WQ\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/DI2_gXqB.js"
  },
  "/_nuxt/DIsrKPuS.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"69-AVT/GRWnjmmTA8kyceXUNXAFOFU\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 105,
    "path": "../public/_nuxt/DIsrKPuS.js"
  },
  "/_nuxt/DiW6vLtg.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"74-07amURCMKbqlk4OLm+rEwvkT9Jk\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 116,
    "path": "../public/_nuxt/DiW6vLtg.js"
  },
  "/_nuxt/Diz1Y-y2.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-rQce0qcR0GZ9chhVZy5YOecE4Qc\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 119,
    "path": "../public/_nuxt/Diz1Y-y2.js"
  },
  "/_nuxt/Dj2hyhkp.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"84-k38dIBMPb9iVuCURTwRO5sF3KUQ\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 132,
    "path": "../public/_nuxt/Dj2hyhkp.js"
  },
  "/_nuxt/DJ7d7Skx.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-yP2PVzYWSpGeYXrq5AwQu35KU3k\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 114,
    "path": "../public/_nuxt/DJ7d7Skx.js"
  },
  "/_nuxt/DjTvIAiU.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-tPYeAptCw6+Iq7QwFUr3aWhtN3M\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/DjTvIAiU.js"
  },
  "/_nuxt/DKp9Pbsr.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-pzucYjNwS0E2jZhVJsZZLYTGGfM\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 113,
    "path": "../public/_nuxt/DKp9Pbsr.js"
  },
  "/_nuxt/DKyxMmU3.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-T85Md5dSVqTqIDvahXN3NWRDhKM\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/DKyxMmU3.js"
  },
  "/_nuxt/DlAUqK2U.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"5b-eFCz/UrraTh721pgAl0VxBNR1es\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 91,
    "path": "../public/_nuxt/DlAUqK2U.js"
  },
  "/_nuxt/DLAoCURk.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-IRIt047DGW0pOhmqs1dU41AilmI\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 120,
    "path": "../public/_nuxt/DLAoCURk.js"
  },
  "/_nuxt/DL5povNM.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-nTkRsXhJcrbobY+hjICRBf+mykM\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 122,
    "path": "../public/_nuxt/DL5povNM.js"
  },
  "/_nuxt/DLU3v8h2.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-v2U9O32Xqi14r2kZL1Kr05K6Suc\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 122,
    "path": "../public/_nuxt/DLU3v8h2.js"
  },
  "/_nuxt/DLdvvA-i.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-GUyWxMIYuNrJ9Z1O0U/ubg7Y2gM\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 110,
    "path": "../public/_nuxt/DLdvvA-i.js"
  },
  "/_nuxt/DmaBRYTm.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"75-UA73EJsGuNrwvMR5avTsDX1JSDo\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 117,
    "path": "../public/_nuxt/DmaBRYTm.js"
  },
  "/_nuxt/DM4yMXhh.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-Isbi9OpqVA4+VFLmXZosv2LQaqc\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 110,
    "path": "../public/_nuxt/DM4yMXhh.js"
  },
  "/_nuxt/DmGQtuOQ.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-/79WgZ5VprreQXH3vu1Dq6UBpoY\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 119,
    "path": "../public/_nuxt/DmGQtuOQ.js"
  },
  "/_nuxt/Dmzs9V8r.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-2I0cX/gqVnGjbYMwh+pDZzaz9U0\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 110,
    "path": "../public/_nuxt/Dmzs9V8r.js"
  },
  "/_nuxt/DMRccb0d.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-4EKc3owXsEOazYmpRuMtLAeQ/sY\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 110,
    "path": "../public/_nuxt/DMRccb0d.js"
  },
  "/_nuxt/DnFchfPu.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-R1Lh23Df5qohwc4LYt4bOmdKQuc\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 122,
    "path": "../public/_nuxt/DnFchfPu.js"
  },
  "/_nuxt/DmSX8FpZ.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-K1bT8ciSqfa6QnCdq6AruOGupn4\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 114,
    "path": "../public/_nuxt/DmSX8FpZ.js"
  },
  "/_nuxt/DO9Ws8rN.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-9gGL5YzIMT8RsoKEnCMAy0YziH4\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 119,
    "path": "../public/_nuxt/DO9Ws8rN.js"
  },
  "/_nuxt/DnmNHREC.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-G7c5kTr6D4ESESYTaLgpetwa8mE\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 122,
    "path": "../public/_nuxt/DnmNHREC.js"
  },
  "/_nuxt/DP3JczNK.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6c-K6HjNimMhDpdZ4OkYA1EKoZl3IQ\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 108,
    "path": "../public/_nuxt/DP3JczNK.js"
  },
  "/_nuxt/DoX-ipy2.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"85-PJaW9jsX9kwR0Sojy58dJ+qs2Zw\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 133,
    "path": "../public/_nuxt/DoX-ipy2.js"
  },
  "/_nuxt/DOyVd9tH.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-PZwHBAck6DKQhzyQrgka94bkElE\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/DOyVd9tH.js"
  },
  "/_nuxt/DoQPdURd.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-/OxUGa0Qq8sy9A7U1fdUkYjHzPc\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 110,
    "path": "../public/_nuxt/DoQPdURd.js"
  },
  "/_nuxt/DQ9qB5U5.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-Isbi9OpqVA4+VFLmXZosv2LQaqc\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 110,
    "path": "../public/_nuxt/DQ9qB5U5.js"
  },
  "/_nuxt/DQz4DqoO.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-GUyWxMIYuNrJ9Z1O0U/ubg7Y2gM\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 110,
    "path": "../public/_nuxt/DQz4DqoO.js"
  },
  "/_nuxt/DPGGTdoo.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-Nq0rFFd0pFhbX+9XpNQT8trCVwI\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 110,
    "path": "../public/_nuxt/DPGGTdoo.js"
  },
  "/_nuxt/DpDlEBil.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"70-d1EanpdQEQ1eeft7NyCQWxmVDes\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 112,
    "path": "../public/_nuxt/DpDlEBil.js"
  },
  "/_nuxt/DrAD2HPw.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-Av8/LbyERxuNqf8DBJt2AKq6BRw\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/DrAD2HPw.js"
  },
  "/_nuxt/DreLl2GQ.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7f-kzgrZJEgFYruT0UujhNG7hWCcqM\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 127,
    "path": "../public/_nuxt/DreLl2GQ.js"
  },
  "/_nuxt/DsfqF0CT.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-1u8FkZHySi2QxOsajwJLr/xmHsY\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 110,
    "path": "../public/_nuxt/DsfqF0CT.js"
  },
  "/_nuxt/Dsb1A8zT.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-g9/pIWKmwWfRfJK765BHhiR27Hw\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 113,
    "path": "../public/_nuxt/Dsb1A8zT.js"
  },
  "/_nuxt/Ds-1WEtK.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-C3uED2KbV+a5nlEydOfpOmiY+f4\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 107,
    "path": "../public/_nuxt/Ds-1WEtK.js"
  },
  "/_nuxt/Ds8TzIIl.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-Bs5MSODq/8XVNSJy0mx7/C2/14Q\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 120,
    "path": "../public/_nuxt/Ds8TzIIl.js"
  },
  "/_nuxt/DsJ224Zu.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-C/konfLqMrF5i4iuo8mO0QXMFP0\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 122,
    "path": "../public/_nuxt/DsJ224Zu.js"
  },
  "/_nuxt/DsQj2qD0.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-+aRGplTs89u+PWJxjgI4cwn/qLM\"",
    "mtime": "2026-09-28T12:17:37.608Z",
    "size": 107,
    "path": "../public/_nuxt/DsQj2qD0.js"
  },
  "/_nuxt/DtvID8-x.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"74-UNTwIYH/IFrVQFX4CKds9Uh1bd8\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 116,
    "path": "../public/_nuxt/DtvID8-x.js"
  },
  "/_nuxt/Dtn6CI1_.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"76-UXfbl+eC91LXKx3fy4pzXLy7doY\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 118,
    "path": "../public/_nuxt/Dtn6CI1_.js"
  },
  "/_nuxt/DTMqOwFD.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-yzJtZkYp/+ZJJr/Y/XGP+QtN6aI\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/DTMqOwFD.js"
  },
  "/_nuxt/DUiDqCfO.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-hZYPfIa9sbZC+MJnMf4ySFbny2w\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 114,
    "path": "../public/_nuxt/DUiDqCfO.js"
  },
  "/_nuxt/DVHv1HXp.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-U6eAbpAQTePrWbJuRORcV1w6QLQ\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/DVHv1HXp.js"
  },
  "/_nuxt/DUylJlWh.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-NUWHCW+h/nuefHkhPXZNg/9MSKE\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 114,
    "path": "../public/_nuxt/DUylJlWh.js"
  },
  "/_nuxt/DUVVe7Ov.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-gOw4DlErcq22Cp6wVLjXsCtM3Ak\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 107,
    "path": "../public/_nuxt/DUVVe7Ov.js"
  },
  "/_nuxt/DWDXuAOo.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-aK9fVSnkRwOAumBtHGey0wH17Ts\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 120,
    "path": "../public/_nuxt/DWDXuAOo.js"
  },
  "/_nuxt/DWEJfPYI.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-P98i7lGSsMI1pk8iUgcd1A27QQo\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 114,
    "path": "../public/_nuxt/DWEJfPYI.js"
  },
  "/_nuxt/DWGdLzwy.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"75-MVoRiTWIgxPwglKwYTjJB/dB7QM\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 117,
    "path": "../public/_nuxt/DWGdLzwy.js"
  },
  "/_nuxt/DwD8S0jr.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-2VxcPUv9kVY1XgGACvOjFpsUXBo\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 120,
    "path": "../public/_nuxt/DwD8S0jr.js"
  },
  "/_nuxt/DWhSg-JW.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-8Ei8mFbrRowEyRy7N+r3Dr+2+dc\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/DWhSg-JW.js"
  },
  "/_nuxt/cover.DYQJrCiC.png": {
    "type": "image/png",
    "etag": "\"105808c-nFeWoUO47RZPtzrnBbVLLmdcixc\"",
    "mtime": "2026-09-28T12:17:37.926Z",
    "size": 17137804,
    "path": "../public/_nuxt/cover.DYQJrCiC.png"
  },
  "/_nuxt/DWYzU1IA.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-aK1/oZtUGJlAJUq+aQIAk1GEEGQ\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 120,
    "path": "../public/_nuxt/DWYzU1IA.js"
  },
  "/_nuxt/DWpiyou3.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"74-wIIB9PeEmIqFUZl7BTTq1tLNKIo\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 116,
    "path": "../public/_nuxt/DWpiyou3.js"
  },
  "/_nuxt/DwNiYOT2.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"76-+7VLuDh0F+XuE1lZbwvzNJ+ZKnU\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 118,
    "path": "../public/_nuxt/DwNiYOT2.js"
  },
  "/_nuxt/DWzjLKdg.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"76-pmEdtnfub9rB7TO/9N7FFdgj2fE\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 118,
    "path": "../public/_nuxt/DWzjLKdg.js"
  },
  "/_nuxt/Dx44p2qi.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-KQpuD2jILqojET4AQisizg7pqDc\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 114,
    "path": "../public/_nuxt/Dx44p2qi.js"
  },
  "/_nuxt/DxxGYCCl.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-puzfH7J6ub01x+S/EqVA4C745g4\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 114,
    "path": "../public/_nuxt/DxxGYCCl.js"
  },
  "/_nuxt/DxyQbuUw.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-HpvdLCwgHYbSbMrFxFhuP7RNbL4\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 122,
    "path": "../public/_nuxt/DxyQbuUw.js"
  },
  "/_nuxt/DyGn2AJG.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6a-ybGiQSi+BIa/Gc6W+Ro3QhICerQ\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 106,
    "path": "../public/_nuxt/DyGn2AJG.js"
  },
  "/_nuxt/DyU3FAJm.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-xUxLR50aRMRFVsCbwCteDc2ONsE\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 110,
    "path": "../public/_nuxt/DyU3FAJm.js"
  },
  "/_nuxt/DyA5PwZ3.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-my3r+iTZc4FY1SCo2mt7jnUHuq4\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 119,
    "path": "../public/_nuxt/DyA5PwZ3.js"
  },
  "/_nuxt/DyqDMplE.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-k8EJ4RqllDhJCNp4cSk1cXbRdu8\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/DyqDMplE.js"
  },
  "/_nuxt/D_T2y3Yb.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-NxdwnwkneQq0WrqJXPqU9XT0D0c\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 110,
    "path": "../public/_nuxt/D_T2y3Yb.js"
  },
  "/_nuxt/DZl9SPES.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-EtXkx8GFgrh2Io7Is94YPwLwCjw\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 110,
    "path": "../public/_nuxt/DZl9SPES.js"
  },
  "/_nuxt/D_FyekbC.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-HYpe/1VkKoP9hXXOCYTpO8vkuf8\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 110,
    "path": "../public/_nuxt/D_FyekbC.js"
  },
  "/_nuxt/entry.BG5gjr-A.css": {
    "type": "text/css; charset=utf-8",
    "etag": "\"6d-t9oMXxXvlemgyaSiz9WjxFlDIBw\"",
    "mtime": "2026-09-28T12:17:37.596Z",
    "size": 109,
    "path": "../public/_nuxt/entry.BG5gjr-A.css"
  },
  "/_nuxt/EpPzaCtU.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-sxi5omKXrt6i4PnZFQXEpV210ss\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 110,
    "path": "../public/_nuxt/EpPzaCtU.js"
  },
  "/_nuxt/error-404.DL_4WIao.css": {
    "type": "text/css; charset=utf-8",
    "etag": "\"dca-KnjyV0UbpsrliiJzZx69defY74k\"",
    "mtime": "2026-09-28T12:17:37.596Z",
    "size": 3530,
    "path": "../public/_nuxt/error-404.DL_4WIao.css"
  },
  "/_nuxt/error-500.I1Dtv2V5.css": {
    "type": "text/css; charset=utf-8",
    "etag": "\"75a-vEGyJqldBVJrnMfcLsrGaHcxYl0\"",
    "mtime": "2026-09-28T12:17:37.596Z",
    "size": 1882,
    "path": "../public/_nuxt/error-500.I1Dtv2V5.css"
  },
  "/_nuxt/e7GQHNMR.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-WqTHn4YKbYVVRREt9bmauQg3lJE\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/e7GQHNMR.js"
  },
  "/_nuxt/et5aroo2.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-q5zBfq+09pTgWHO6L5PJEmwI/GY\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/et5aroo2.js"
  },
  "/_nuxt/eugz96Rz.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-GLoHZ3dFei10jweA4VQgsA9YHGw\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 110,
    "path": "../public/_nuxt/eugz96Rz.js"
  },
  "/_nuxt/EvjFcexN.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-C5EwGA/f2TtgBt0hiznvCaOAp5Y\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 114,
    "path": "../public/_nuxt/EvjFcexN.js"
  },
  "/_nuxt/fragile_1.BInGzSuV.webp": {
    "type": "image/webp",
    "etag": "\"b5e40-UkPw0Y2MazfiX8sdVjz6Al0PuFs\"",
    "mtime": "2026-09-28T12:17:37.610Z",
    "size": 745024,
    "path": "../public/_nuxt/fragile_1.BInGzSuV.webp"
  },
  "/_nuxt/fragile_11.C2nZ33KK.webp": {
    "type": "image/webp",
    "etag": "\"c1456-Jlw5sIpP4trYKHnznF3x2WsdB6k\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 791638,
    "path": "../public/_nuxt/fragile_11.C2nZ33KK.webp"
  },
  "/_nuxt/fragile_10.DD2ApxVb.webp": {
    "type": "image/webp",
    "etag": "\"eda18-ug57Bvemf6U2pIW5rb2wIT3JVuM\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 973336,
    "path": "../public/_nuxt/fragile_10.DD2ApxVb.webp"
  },
  "/_nuxt/EQOsSEBE.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"23ae-XeVqoKjo0ftRu1FfT4+TFXmVCKw\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 9134,
    "path": "../public/_nuxt/EQOsSEBE.js"
  },
  "/_nuxt/fragile_12.U2gUXP6g.webp": {
    "type": "image/webp",
    "etag": "\"c9968-lPEfzNmS1Yy8bLiB2tMuYDikv0g\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 825704,
    "path": "../public/_nuxt/fragile_12.U2gUXP6g.webp"
  },
  "/_nuxt/FFIKCSG2.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-9MQIKF2dVbOEp/+ya7reXVvDFoo\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/FFIKCSG2.js"
  },
  "/_nuxt/fragile_14.BwE0wvr9.webp": {
    "type": "image/webp",
    "etag": "\"aba2c-xUlvyFLZ7O7dihAvHsHqHbpG8z8\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 703020,
    "path": "../public/_nuxt/fragile_14.BwE0wvr9.webp"
  },
  "/_nuxt/fragile_13.DENN5SWl.webp": {
    "type": "image/webp",
    "etag": "\"c6cce-DQR523uBr7SApCh5SyKNfkdiccI\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 814286,
    "path": "../public/_nuxt/fragile_13.DENN5SWl.webp"
  },
  "/_nuxt/fragile_15.DGBJSrFO.webp": {
    "type": "image/webp",
    "etag": "\"c4004-D2k8se5fXKJJtRrubgCD0a/SfYc\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 802820,
    "path": "../public/_nuxt/fragile_15.DGBJSrFO.webp"
  },
  "/_nuxt/fragile_16.CiROaqSG.webp": {
    "type": "image/webp",
    "etag": "\"bcdee-10wp+qJSWIfztBQSKyxwCdn4yic\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 773614,
    "path": "../public/_nuxt/fragile_16.CiROaqSG.webp"
  },
  "/_nuxt/fragile_17.BdK3A_gg.webp": {
    "type": "image/webp",
    "etag": "\"bee9c-7qRS1spflnNlz0dU165+hd/xf1A\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 781980,
    "path": "../public/_nuxt/fragile_17.BdK3A_gg.webp"
  },
  "/_nuxt/fragile_18.VvhRrGo7.webp": {
    "type": "image/webp",
    "etag": "\"b771e-0JeEHtnwheDVBddzmE+O2nssVeo\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 751390,
    "path": "../public/_nuxt/fragile_18.VvhRrGo7.webp"
  },
  "/_nuxt/fragile_19.DAZlOwLh.webp": {
    "type": "image/webp",
    "etag": "\"b9176-vOZDbSC1meQjvNcxhKH6vYfYJ50\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 758134,
    "path": "../public/_nuxt/fragile_19.DAZlOwLh.webp"
  },
  "/_nuxt/fragile_2.ry4bl73r.webp": {
    "type": "image/webp",
    "etag": "\"dca14-YewP70GA8J2D6Php69LuwGbQUd0\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 903700,
    "path": "../public/_nuxt/fragile_2.ry4bl73r.webp"
  },
  "/_nuxt/fragile_20.CEIDH902.webp": {
    "type": "image/webp",
    "etag": "\"90b98-ENf6Yvjj8DJ/S8LG/nqrqLe106k\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 592792,
    "path": "../public/_nuxt/fragile_20.CEIDH902.webp"
  },
  "/_nuxt/fragile_21.Dc2Ql6Dn.webp": {
    "type": "image/webp",
    "etag": "\"c2b7c-qJ/fWfZAAVUM1v82gFfvkWc3ajo\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 797564,
    "path": "../public/_nuxt/fragile_21.Dc2Ql6Dn.webp"
  },
  "/_nuxt/fragile_22.Bi-5zxwq.webp": {
    "type": "image/webp",
    "etag": "\"ebb4e-vRDjfT8pu53rs/EomyDYCLH4grQ\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 965454,
    "path": "../public/_nuxt/fragile_22.Bi-5zxwq.webp"
  },
  "/_nuxt/fragile_3.p5jhQa2X.webp": {
    "type": "image/webp",
    "etag": "\"af106-qcLKTDkULmajCToxcE4Jd46oATM\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 717062,
    "path": "../public/_nuxt/fragile_3.p5jhQa2X.webp"
  },
  "/_nuxt/fragile_5.BFKFnNHY.webp": {
    "type": "image/webp",
    "etag": "\"ce2ba-eLyPezuxyevuUubr+UEKlPuiOfU\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 844474,
    "path": "../public/_nuxt/fragile_5.BFKFnNHY.webp"
  },
  "/_nuxt/fragile_4.DMeTVzyw.webp": {
    "type": "image/webp",
    "etag": "\"82b36-+d11dmrbyE/K1tLavMPUxCTUKbg\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 535350,
    "path": "../public/_nuxt/fragile_4.DMeTVzyw.webp"
  },
  "/_nuxt/fragile_6.BGx-vMjJ.webp": {
    "type": "image/webp",
    "etag": "\"c2db6-9uR4B6RqqANaXzRSWI5VeYme3iI\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 798134,
    "path": "../public/_nuxt/fragile_6.BGx-vMjJ.webp"
  },
  "/_nuxt/fragile_7.CDyOkS-7.webp": {
    "type": "image/webp",
    "etag": "\"c6b14-1CwRNB4wRPkZE4vkOeuoEkb2qC4\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 813844,
    "path": "../public/_nuxt/fragile_7.CDyOkS-7.webp"
  },
  "/_nuxt/fragile_8.C4_Fd_f6.webp": {
    "type": "image/webp",
    "etag": "\"9734a-VVwitH0P6p/wXo1lsAyPahLgHzI\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 619338,
    "path": "../public/_nuxt/fragile_8.C4_Fd_f6.webp"
  },
  "/_nuxt/fragile_9.CPnadO7F.webp": {
    "type": "image/webp",
    "etag": "\"acb36-Qw3XnyufMDO50aW+nuffujOGojg\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 707382,
    "path": "../public/_nuxt/fragile_9.CPnadO7F.webp"
  },
  "/_nuxt/G1x8cdlv.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-s+zCAxUZkBqVS9GwsMM0GrzeUXk\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/G1x8cdlv.js"
  },
  "/_nuxt/heysport_01.BM9NsltV.webp": {
    "type": "image/webp",
    "etag": "\"606f6-r0JSNeuWVkZYFIVt4NRmsxByeZE\"",
    "mtime": "2026-09-28T12:17:37.579Z",
    "size": 394998,
    "path": "../public/_nuxt/heysport_01.BM9NsltV.webp"
  },
  "/_nuxt/heysport_010.CI9Laai8.webp": {
    "type": "image/webp",
    "etag": "\"64460-6CkyY4BBD7IWpMIbBFpr6tgeTVc\"",
    "mtime": "2026-09-28T12:17:37.579Z",
    "size": 410720,
    "path": "../public/_nuxt/heysport_010.CI9Laai8.webp"
  },
  "/_nuxt/G61lCIQn.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-pZQfuariUMNBW7wt2ZHMv0Y8B5s\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 114,
    "path": "../public/_nuxt/G61lCIQn.js"
  },
  "/_nuxt/heysport_011.lPGaFJYU.webp": {
    "type": "image/webp",
    "etag": "\"589c0-W3YI/M8QGruu1xhi0Rj795uunb0\"",
    "mtime": "2026-09-28T12:17:37.579Z",
    "size": 362944,
    "path": "../public/_nuxt/heysport_011.lPGaFJYU.webp"
  },
  "/_nuxt/heysport_012.WRlxwF5l.webp": {
    "type": "image/webp",
    "etag": "\"4c608-j1qx1+KLIkLq6F3JywyszNKCnjc\"",
    "mtime": "2026-09-28T12:17:37.579Z",
    "size": 312840,
    "path": "../public/_nuxt/heysport_012.WRlxwF5l.webp"
  },
  "/_nuxt/heysport_014.BebRmkKZ.webp": {
    "type": "image/webp",
    "etag": "\"53190-7knr5W88gE1OrtkiSbxYKsC10dY\"",
    "mtime": "2026-09-28T12:17:37.579Z",
    "size": 340368,
    "path": "../public/_nuxt/heysport_014.BebRmkKZ.webp"
  },
  "/_nuxt/heysport_013.KFt41wJC.webp": {
    "type": "image/webp",
    "etag": "\"6271c-0TwhPM6jljkKLn9rSUE2tFVNcKA\"",
    "mtime": "2026-09-28T12:17:37.579Z",
    "size": 403228,
    "path": "../public/_nuxt/heysport_013.KFt41wJC.webp"
  },
  "/_nuxt/heysport_016.j05En8Zn.webp": {
    "type": "image/webp",
    "etag": "\"67cf6-/kza/tk1yeznJiSCQ5VX5WHunrE\"",
    "mtime": "2026-09-28T12:17:37.579Z",
    "size": 425206,
    "path": "../public/_nuxt/heysport_016.j05En8Zn.webp"
  },
  "/_nuxt/h4IaXlWR.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7f-38j3PtFUKEPPNbFi6SpPcjyVUdk\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 127,
    "path": "../public/_nuxt/h4IaXlWR.js"
  },
  "/_nuxt/heysport_017.CYe37wMH.webp": {
    "type": "image/webp",
    "etag": "\"5b9f2-UxX26J0JpyiOPqCV+Vah7rstGdM\"",
    "mtime": "2026-09-28T12:17:37.579Z",
    "size": 375282,
    "path": "../public/_nuxt/heysport_017.CYe37wMH.webp"
  },
  "/_nuxt/heysport_02.BgcqqUvr.webp": {
    "type": "image/webp",
    "etag": "\"5cfb8-NDqpnDKzoUVtdACyLJ21gpQSBk8\"",
    "mtime": "2026-09-28T12:17:37.579Z",
    "size": 380856,
    "path": "../public/_nuxt/heysport_02.BgcqqUvr.webp"
  },
  "/_nuxt/guee7Zu_.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"79-kZBHbtuxVq8gHpMxFiB6wC/KDjE\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 121,
    "path": "../public/_nuxt/guee7Zu_.js"
  },
  "/_nuxt/heysport_03.X2eig4UB.webp": {
    "type": "image/webp",
    "etag": "\"67386-rBzBNlOpgx1LaPwGzXgAs3rEXkk\"",
    "mtime": "2026-09-28T12:17:37.579Z",
    "size": 422790,
    "path": "../public/_nuxt/heysport_03.X2eig4UB.webp"
  },
  "/_nuxt/heysport_04.bvyWxAzQ.webp": {
    "type": "image/webp",
    "etag": "\"55a22-X2wi6T49IKBPIyOntHQC9XD2hlI\"",
    "mtime": "2026-09-28T12:17:37.579Z",
    "size": 350754,
    "path": "../public/_nuxt/heysport_04.bvyWxAzQ.webp"
  },
  "/_nuxt/heysport_05.C_1gJlN6.webp": {
    "type": "image/webp",
    "etag": "\"53f0a-n8wvHxgKg69UWMTZt0vPu/WAjpg\"",
    "mtime": "2026-09-28T12:17:37.579Z",
    "size": 343818,
    "path": "../public/_nuxt/heysport_05.C_1gJlN6.webp"
  },
  "/_nuxt/heysport_06.m93Dvraq.webp": {
    "type": "image/webp",
    "etag": "\"59c0e-RPYxbWcwY5PEmt+MiOS9gXDuTcc\"",
    "mtime": "2026-09-28T12:17:37.579Z",
    "size": 367630,
    "path": "../public/_nuxt/heysport_06.m93Dvraq.webp"
  },
  "/_nuxt/heysport_08.tbT2IgCt.webp": {
    "type": "image/webp",
    "etag": "\"5231c-QuTw7frJNpBwrHFUlydTp/k2x6k\"",
    "mtime": "2026-09-28T12:17:37.579Z",
    "size": 336668,
    "path": "../public/_nuxt/heysport_08.tbT2IgCt.webp"
  },
  "/_nuxt/HNsgN3Gl.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-+Cj5QzPAigtGHImSWgHcrFoQo3g\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 119,
    "path": "../public/_nuxt/HNsgN3Gl.js"
  },
  "/_nuxt/Iyl0PKBm.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"80-D770+46uNhfEq+W3N7j+haNg5Lc\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 128,
    "path": "../public/_nuxt/Iyl0PKBm.js"
  },
  "/_nuxt/hMDso6Bn.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"75-aateBfxXABm+nLUPpoWe+Ng01hw\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 117,
    "path": "../public/_nuxt/hMDso6Bn.js"
  },
  "/_nuxt/j2ey5R9S.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-LYG2aiXEGDfBvSTdUQ5lcTJBcF8\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 119,
    "path": "../public/_nuxt/j2ey5R9S.js"
  },
  "/_nuxt/J4GeDJ93.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-3Zt/zJUQirTAQAiwrvXzYJ9rFjk\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/J4GeDJ93.js"
  },
  "/_nuxt/JAuBXJL4.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"79-zr4TPwUiD/0CoYkIWRpUv6M2tOc\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 121,
    "path": "../public/_nuxt/JAuBXJL4.js"
  },
  "/_nuxt/JwC4esDW.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-xi2UsHE94lGi83Gg1dSyL66vm7A\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 110,
    "path": "../public/_nuxt/JwC4esDW.js"
  },
  "/_nuxt/JGo8xbTp.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-aezhGEbz6tsymhxFcPc0jjCzep0\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 114,
    "path": "../public/_nuxt/JGo8xbTp.js"
  },
  "/_nuxt/JGZHRHgZ.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-RjhZCerQk+s1Br3KYHbx7XXiDCE\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 114,
    "path": "../public/_nuxt/JGZHRHgZ.js"
  },
  "/_nuxt/l6fDOm2w.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6c-nxz82du7k0AAAHLZ9behfv9V654\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 108,
    "path": "../public/_nuxt/l6fDOm2w.js"
  },
  "/_nuxt/kT0-J1Rf.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-GZaECd6CNis7j0Yz2zPbLK6jEfE\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 122,
    "path": "../public/_nuxt/kT0-J1Rf.js"
  },
  "/_nuxt/k_2Y9fpm.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-z5O6ZYLA01xEPX4vqNRYN4nicBQ\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/k_2Y9fpm.js"
  },
  "/_nuxt/Gara.DbmDujH0.mp4": {
    "type": "video/mp4",
    "etag": "\"2eec86-vu+Twn6LTEsQ5cron9K25+5pt0A\"",
    "mtime": "2026-09-28T12:17:37.920Z",
    "size": 3075206,
    "path": "../public/_nuxt/Gara.DbmDujH0.mp4"
  },
  "/_nuxt/L0Y-hZvZ.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-/PaHPTJYw0Nj6otsAbG93RV7+sI\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 107,
    "path": "../public/_nuxt/L0Y-hZvZ.js"
  },
  "/_nuxt/laurea_fabius_175.H1m8Hz2r.webp": {
    "type": "image/webp",
    "etag": "\"6a0ea-fqk2ugJMvL9xGJpsOsnZE2M8IKU\"",
    "mtime": "2026-09-28T12:17:37.579Z",
    "size": 434410,
    "path": "../public/_nuxt/laurea_fabius_175.H1m8Hz2r.webp"
  },
  "/_nuxt/l7nseTGK.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-gFqwZOoSdJUY7kfZzqZJ0yrBvj0\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/l7nseTGK.js"
  },
  "/_nuxt/laurea_fabius_240.DtH7xuyZ.webp": {
    "type": "image/webp",
    "etag": "\"67332-ABH/yRg3rhQQFW49F3PYokLhxBg\"",
    "mtime": "2026-09-28T12:17:37.579Z",
    "size": 422706,
    "path": "../public/_nuxt/laurea_fabius_240.DtH7xuyZ.webp"
  },
  "/_nuxt/laurea_fabius_171.DON82Etd.webp": {
    "type": "image/webp",
    "etag": "\"b8630-afZ2g+U1951Rrcw0MdZIJMgdvM4\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 755248,
    "path": "../public/_nuxt/laurea_fabius_171.DON82Etd.webp"
  },
  "/_nuxt/laurea_fabius_149.BJxIgAI8.webp": {
    "type": "image/webp",
    "etag": "\"d44ae-JjD70MaEPZtwj6hJI80O/CMR3F8\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 869550,
    "path": "../public/_nuxt/laurea_fabius_149.BJxIgAI8.webp"
  },
  "/_nuxt/laurea_fabius_242.XqqubF7E.webp": {
    "type": "image/webp",
    "etag": "\"800a4-AsS4FjWvN/kz8KDZfNP/7eXfcL4\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 524452,
    "path": "../public/_nuxt/laurea_fabius_242.XqqubF7E.webp"
  },
  "/_nuxt/laurea_fabius_40.CRR_cY9f.webp": {
    "type": "image/webp",
    "etag": "\"b004e-ERJJZldRfD1VI3yMKOjZQzJYF0Y\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 720974,
    "path": "../public/_nuxt/laurea_fabius_40.CRR_cY9f.webp"
  },
  "/_nuxt/laurea_fabius_56.hYGniWyq.webp": {
    "type": "image/webp",
    "etag": "\"d9c10-Klx6bKmk7DJfAZpXW/G7H741IIg\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 891920,
    "path": "../public/_nuxt/laurea_fabius_56.hYGniWyq.webp"
  },
  "/_nuxt/laurea_fabius_59.DRH1PDiu.webp": {
    "type": "image/webp",
    "etag": "\"9ebb8-ObIDxX3ic9SUxeJWDMvig3uivmc\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 650168,
    "path": "../public/_nuxt/laurea_fabius_59.DRH1PDiu.webp"
  },
  "/_nuxt/laurea_magistrale_ture_110.BjgwugKs.webp": {
    "type": "image/webp",
    "etag": "\"eddba-RiYOLcxuL7mb81I4cqp+lV4kRhk\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 974266,
    "path": "../public/_nuxt/laurea_magistrale_ture_110.BjgwugKs.webp"
  },
  "/_nuxt/laurea_magistrale_ture_126.CHL4hUP3.webp": {
    "type": "image/webp",
    "etag": "\"da92c-CJmVlgHwjveQK4QE+8ZIpbIN2Io\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 895276,
    "path": "../public/_nuxt/laurea_magistrale_ture_126.CHL4hUP3.webp"
  },
  "/_nuxt/laurea_magistrale_ture_128.CRcyGicX.webp": {
    "type": "image/webp",
    "etag": "\"c5f70-s/TCZIOBSxaRIXb9Nxc+S7T/6UA\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 810864,
    "path": "../public/_nuxt/laurea_magistrale_ture_128.CRcyGicX.webp"
  },
  "/_nuxt/laurea_magistrale_ture_120.BaFEyEk1.webp": {
    "type": "image/webp",
    "etag": "\"10a0a8-ffOrWx2n+A3NEl8ox1U95jAH580\"",
    "mtime": "2026-09-28T12:17:37.893Z",
    "size": 1089704,
    "path": "../public/_nuxt/laurea_magistrale_ture_120.BaFEyEk1.webp"
  },
  "/_nuxt/laurea_magistrale_ture_185.D8wszn3X.webp": {
    "type": "image/webp",
    "etag": "\"fe692-AajMkCict6oUJLabTZP00JBlTow\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 1042066,
    "path": "../public/_nuxt/laurea_magistrale_ture_185.D8wszn3X.webp"
  },
  "/_nuxt/laurea_magistrale_ture_198.D_PVmzvs.webp": {
    "type": "image/webp",
    "etag": "\"cfcea-e3E3qWbf3+9hpB1joayimRdFDcw\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 851178,
    "path": "../public/_nuxt/laurea_magistrale_ture_198.D_PVmzvs.webp"
  },
  "/_nuxt/laurea_magistrale_ture_315.C3t2vTYT.webp": {
    "type": "image/webp",
    "etag": "\"f16b2-WlTkCx3ywc0d0H1UVm+7tJze0SE\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 988850,
    "path": "../public/_nuxt/laurea_magistrale_ture_315.C3t2vTYT.webp"
  },
  "/_nuxt/laurea_magistrale_ture_355.Dcn9jeEf.webp": {
    "type": "image/webp",
    "etag": "\"feb44-/n3LN1ZwFnbhvvh4b8QV+Ubi5eE\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 1043268,
    "path": "../public/_nuxt/laurea_magistrale_ture_355.Dcn9jeEf.webp"
  },
  "/_nuxt/laurea_magistrale_ture_37.DVZlRDWq.webp": {
    "type": "image/webp",
    "etag": "\"c5f80-ryqbYdtC+CgWW823AQxuGaDpIdo\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 810880,
    "path": "../public/_nuxt/laurea_magistrale_ture_37.DVZlRDWq.webp"
  },
  "/_nuxt/laurea_magistrale_ture_378.C03svurm.webp": {
    "type": "image/webp",
    "etag": "\"99d56-Zkt+wCS8E5GMwng83PWYCBhLEqs\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 630102,
    "path": "../public/_nuxt/laurea_magistrale_ture_378.C03svurm.webp"
  },
  "/_nuxt/laurea_magistrale_ture_385.DangeNSf.webp": {
    "type": "image/webp",
    "etag": "\"e872a-/dRupqLrrDERmJ2EF5UAvkNz+t4\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 952106,
    "path": "../public/_nuxt/laurea_magistrale_ture_385.DangeNSf.webp"
  },
  "/_nuxt/laurea_magistrale_ture_19.BS8utQtA.webp": {
    "type": "image/webp",
    "etag": "\"11e1d0-NH3+uKvWkw9GyLT+ZfpK7lMY8gs\"",
    "mtime": "2026-09-28T12:17:37.893Z",
    "size": 1171920,
    "path": "../public/_nuxt/laurea_magistrale_ture_19.BS8utQtA.webp"
  },
  "/_nuxt/laurea_magistrale_ture_31.C77WAEdS.webp": {
    "type": "image/webp",
    "etag": "\"116bda-ZG1hcQaWHwSy5hOUn2pKq8HGoMs\"",
    "mtime": "2026-09-28T12:17:37.893Z",
    "size": 1141722,
    "path": "../public/_nuxt/laurea_magistrale_ture_31.C77WAEdS.webp"
  },
  "/_nuxt/laurea_magistrale_ture_388.DreMOKvb.webp": {
    "type": "image/webp",
    "etag": "\"ee376-vUmqknC7ekFNv1nZ+4yOwXcR7D0\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 975734,
    "path": "../public/_nuxt/laurea_magistrale_ture_388.DreMOKvb.webp"
  },
  "/_nuxt/laurea_magistrale_ture_348.B1S9bsdZ.webp": {
    "type": "image/webp",
    "etag": "\"12c95e-I+ZpBKBW+B4cZv5IQm/LyGerARM\"",
    "mtime": "2026-09-28T12:17:37.893Z",
    "size": 1231198,
    "path": "../public/_nuxt/laurea_magistrale_ture_348.B1S9bsdZ.webp"
  },
  "/_nuxt/laurea_magistrale_ture_51.CHBuKUzZ.webp": {
    "type": "image/webp",
    "etag": "\"ebaa0-+lBn9oCrE9YW8OGHCYVDowWTxU8\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 965280,
    "path": "../public/_nuxt/laurea_magistrale_ture_51.CHBuKUzZ.webp"
  },
  "/_nuxt/laurea_magistrale_ture_96.DznrazNz.webp": {
    "type": "image/webp",
    "etag": "\"d6578-Sy17toYG02mp2s2W1NoeKk1Hrq8\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 877944,
    "path": "../public/_nuxt/laurea_magistrale_ture_96.DznrazNz.webp"
  },
  "/_nuxt/laurea_maria_chiara_mattina_129.DlpQroC1.webp": {
    "type": "image/webp",
    "etag": "\"f061a-oTtvX7mgSxNphw7IeKIX9v21vGo\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 984602,
    "path": "../public/_nuxt/laurea_maria_chiara_mattina_129.DlpQroC1.webp"
  },
  "/_nuxt/laurea_maria_chiara_mattina_141.QEEuGcbG.webp": {
    "type": "image/webp",
    "etag": "\"f889c-xVzlDPFLokrRhEP4JJzn/7xargE\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 1018012,
    "path": "../public/_nuxt/laurea_maria_chiara_mattina_141.QEEuGcbG.webp"
  },
  "/_nuxt/laurea_maria_chiara_mattina_24.CXFHIj5x.webp": {
    "type": "image/webp",
    "etag": "\"df590-c4Qmc28c3qtjs769//lxbGn42+Q\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 914832,
    "path": "../public/_nuxt/laurea_maria_chiara_mattina_24.CXFHIj5x.webp"
  },
  "/_nuxt/laurea_maria_chiara_mattina_39.stHKIrMz.webp": {
    "type": "image/webp",
    "etag": "\"e40ec-LMAy7KaDE7MA8YpcYLwvZm3CTJI\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 934124,
    "path": "../public/_nuxt/laurea_maria_chiara_mattina_39.stHKIrMz.webp"
  },
  "/_nuxt/laurea_maria_chiara_mattina_63._Aat8c47.webp": {
    "type": "image/webp",
    "etag": "\"e0766-6cjz0aP09mODGHxELQnp24mA3mU\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 919398,
    "path": "../public/_nuxt/laurea_maria_chiara_mattina_63._Aat8c47.webp"
  },
  "/_nuxt/laurea_magistrale_ture_56.JD9uR8X7.webp": {
    "type": "image/webp",
    "etag": "\"121ec8-W8SBZRPtj/5mKdOgJt1LK+ow2Oc\"",
    "mtime": "2026-09-28T12:17:37.893Z",
    "size": 1187528,
    "path": "../public/_nuxt/laurea_magistrale_ture_56.JD9uR8X7.webp"
  },
  "/_nuxt/laurea_maria_chiara_mattina_78.ymH0m4FX.webp": {
    "type": "image/webp",
    "etag": "\"a1cc6-3nqXqYMSr6hIsC5hKoVtAEZVAyk\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 662726,
    "path": "../public/_nuxt/laurea_maria_chiara_mattina_78.ymH0m4FX.webp"
  },
  "/_nuxt/LTxIg7yS.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-rqgcPfaO3BjR/kA+cmPZGvZd3Lw\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 110,
    "path": "../public/_nuxt/LTxIg7yS.js"
  },
  "/_nuxt/m4YY1u5g.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6a-JY9b1/fR7rzOlcOb8ZQGYSrpThE\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 106,
    "path": "../public/_nuxt/m4YY1u5g.js"
  },
  "/_nuxt/merlo_01.DbyfGf1P.webp": {
    "type": "image/webp",
    "etag": "\"27528-3nCLuQaeMPwR4sn8uykBb5U6EG0\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 161064,
    "path": "../public/_nuxt/merlo_01.DbyfGf1P.webp"
  },
  "/_nuxt/merlo_02.B7aMcTXh.webp": {
    "type": "image/webp",
    "etag": "\"2d3e4-oLUf6Zf5jwrmZlwQjjtgoBRwR0Y\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 185316,
    "path": "../public/_nuxt/merlo_02.B7aMcTXh.webp"
  },
  "/_nuxt/merlo_03.Cwi0r-2O.webp": {
    "type": "image/webp",
    "etag": "\"2341e-EpK7TYMw7XMNYNxODsIDUPowRUw\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 144414,
    "path": "../public/_nuxt/merlo_03.Cwi0r-2O.webp"
  },
  "/_nuxt/laurea_maria_chiara_mattina_120.eMbROpjJ.webp": {
    "type": "image/webp",
    "etag": "\"1c5c92-XBAUYBuGzKm5w8tiVe7Uc5eZhF8\"",
    "mtime": "2026-09-28T12:17:37.915Z",
    "size": 1858706,
    "path": "../public/_nuxt/laurea_maria_chiara_mattina_120.eMbROpjJ.webp"
  },
  "/_nuxt/LipZT_LJ.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6f-UxMIupMkkoeEeE6Ahbw/CyV9kHI\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 111,
    "path": "../public/_nuxt/LipZT_LJ.js"
  },
  "/_nuxt/merlo_04.CXeUGaMF.webp": {
    "type": "image/webp",
    "etag": "\"3af4a-23mdjB2R16n6sd0yU7xqlhrEP5s\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 241482,
    "path": "../public/_nuxt/merlo_04.CXeUGaMF.webp"
  },
  "/_nuxt/merlo_05.CPzD1Z6q.webp": {
    "type": "image/webp",
    "etag": "\"2f26c-GM6KZrbWQsrFeSA5udcH4dwHJMg\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 193132,
    "path": "../public/_nuxt/merlo_05.CPzD1Z6q.webp"
  },
  "/_nuxt/merlo_06.rcBn_2ZC.webp": {
    "type": "image/webp",
    "etag": "\"3a916-26RIW1P7tpe34cv0suv3MZY/euI\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 239894,
    "path": "../public/_nuxt/merlo_06.rcBn_2ZC.webp"
  },
  "/_nuxt/merlo_07.G4uu6H_8.webp": {
    "type": "image/webp",
    "etag": "\"1c1c8-Gfz5ug0V+VhNzUITwNDvwUsXGIU\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 115144,
    "path": "../public/_nuxt/merlo_07.G4uu6H_8.webp"
  },
  "/_nuxt/LMi1-vCK.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"80-0uIC6rTWQtjvcBnsi4ThiEsK0xo\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 128,
    "path": "../public/_nuxt/LMi1-vCK.js"
  },
  "/_nuxt/merlo_08.BUESYY5A.webp": {
    "type": "image/webp",
    "etag": "\"2c78e-rGuau8AsgcO3gaimgW4unFEN06E\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 182158,
    "path": "../public/_nuxt/merlo_08.BUESYY5A.webp"
  },
  "/_nuxt/merlo_09.Dpw-H_1Z.webp": {
    "type": "image/webp",
    "etag": "\"16ccc-kLlF9U97/EjeeGfPNLaqIV3DuYs\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 93388,
    "path": "../public/_nuxt/merlo_09.Dpw-H_1Z.webp"
  },
  "/_nuxt/mpv-shot0001.BEa7af5q.webp": {
    "type": "image/webp",
    "etag": "\"48c7a-exITzGcRWVC7pnRmF4RdKoRWdqE\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 298106,
    "path": "../public/_nuxt/mpv-shot0001.BEa7af5q.webp"
  },
  "/_nuxt/mpv-shot0001.LSBeDOQE.webp": {
    "type": "image/webp",
    "etag": "\"7a034-yOenmyGgc7uGDx//3jxinE6KIQQ\"",
    "mtime": "2026-09-28T12:17:37.579Z",
    "size": 499764,
    "path": "../public/_nuxt/mpv-shot0001.LSBeDOQE.webp"
  },
  "/_nuxt/mpv-shot0002.CtwC1Wug.webp": {
    "type": "image/webp",
    "etag": "\"6120c-dtYpZI5pGVQ8/muDZvy6nwMWs1Q\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 397836,
    "path": "../public/_nuxt/mpv-shot0002.CtwC1Wug.webp"
  },
  "/_nuxt/mpv-shot0002.DfZ00paL.webp": {
    "type": "image/webp",
    "etag": "\"7670e-ETGfBhI7FELo6bAUCudELhUQKzM\"",
    "mtime": "2026-09-28T12:17:37.579Z",
    "size": 485134,
    "path": "../public/_nuxt/mpv-shot0002.DfZ00paL.webp"
  },
  "/_nuxt/MjJfyY6E.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-P5knmjsRBXC/GYql9ok2WnlRCL0\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 122,
    "path": "../public/_nuxt/MjJfyY6E.js"
  },
  "/_nuxt/MKeteAHU.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"75-Ommz4Qe2u/S0AB7MIetPXkvVSgU\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 117,
    "path": "../public/_nuxt/MKeteAHU.js"
  },
  "/_nuxt/mpv-shot0004.BmrDcc-C.webp": {
    "type": "image/webp",
    "etag": "\"70320-0HIh7SBqFxLEGAV+10BTPAj8TNM\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 459552,
    "path": "../public/_nuxt/mpv-shot0004.BmrDcc-C.webp"
  },
  "/_nuxt/mpv-shot0005.8AVDYAbC.webp": {
    "type": "image/webp",
    "etag": "\"32d60-FhqOUKdiRTk5YV82uml2kjZ3bfk\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 208224,
    "path": "../public/_nuxt/mpv-shot0005.8AVDYAbC.webp"
  },
  "/_nuxt/mpv-shot0005.BdcQSTBP.webp": {
    "type": "image/webp",
    "etag": "\"44892-cGqJANnD2Y2lN5B4dXQ1FPp2gNY\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 280722,
    "path": "../public/_nuxt/mpv-shot0005.BdcQSTBP.webp"
  },
  "/_nuxt/mpv-shot0003.BO0uRXRS.webp": {
    "type": "image/webp",
    "etag": "\"c05b6-0eHy15x1I7j09/XV6xDCCLhLHHw\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 787894,
    "path": "../public/_nuxt/mpv-shot0003.BO0uRXRS.webp"
  },
  "/_nuxt/mpv-shot0005.Bumeb61Y.webp": {
    "type": "image/webp",
    "etag": "\"71704-jAFe/5uVMaBV7KoJXi0tgHg5QAo\"",
    "mtime": "2026-09-28T12:17:37.579Z",
    "size": 464644,
    "path": "../public/_nuxt/mpv-shot0005.Bumeb61Y.webp"
  },
  "/_nuxt/mpv-shot0003.C3mfCb8Y.webp": {
    "type": "image/webp",
    "etag": "\"92baa-EUED0mKqhm91W4k/dCpCZoPpqyM\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 601002,
    "path": "../public/_nuxt/mpv-shot0003.C3mfCb8Y.webp"
  },
  "/_nuxt/mpv-shot0006.Bz97pD2G.webp": {
    "type": "image/webp",
    "etag": "\"4391c-GJonHjTR3GUM1nXUamFJSkbIiIY\"",
    "mtime": "2026-09-28T12:17:37.579Z",
    "size": 276764,
    "path": "../public/_nuxt/mpv-shot0006.Bz97pD2G.webp"
  },
  "/_nuxt/mpv-shot0006.CdRC6Tc5.webp": {
    "type": "image/webp",
    "etag": "\"7e48c-ee58tMPJZldLUk/Q12e9ISJyLkE\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 517260,
    "path": "../public/_nuxt/mpv-shot0006.CdRC6Tc5.webp"
  },
  "/_nuxt/mpv-shot0007.ChruRf8n.webp": {
    "type": "image/webp",
    "etag": "\"57130-HvXcKe587hYwgi3G2XREtNqoI9E\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 356656,
    "path": "../public/_nuxt/mpv-shot0007.ChruRf8n.webp"
  },
  "/_nuxt/mpv-shot0004.OEvuatkS.webp": {
    "type": "image/webp",
    "etag": "\"8d48a-w9jZK+GnPzwMPMRmhyC/pkdWHqQ\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 578698,
    "path": "../public/_nuxt/mpv-shot0004.OEvuatkS.webp"
  },
  "/_nuxt/mpv-shot0008.BhvnVghR.webp": {
    "type": "image/webp",
    "etag": "\"67556-7e496lSkqBNp7d/OiU832Bh9T6M\"",
    "mtime": "2026-09-28T12:17:37.579Z",
    "size": 423254,
    "path": "../public/_nuxt/mpv-shot0008.BhvnVghR.webp"
  },
  "/_nuxt/mpv-shot0009.BSqqOd7Q.webp": {
    "type": "image/webp",
    "etag": "\"6a072-8PBzJ775G4rHb35H5LW7sknZCvc\"",
    "mtime": "2026-09-28T12:17:37.579Z",
    "size": 434290,
    "path": "../public/_nuxt/mpv-shot0009.BSqqOd7Q.webp"
  },
  "/_nuxt/mpv-shot0010.BI9HU0Wt.webp": {
    "type": "image/webp",
    "etag": "\"3db84-9hg0UrJ0owfAkkdHWwlCoMzWgDw\"",
    "mtime": "2026-09-28T12:17:37.579Z",
    "size": 252804,
    "path": "../public/_nuxt/mpv-shot0010.BI9HU0Wt.webp"
  },
  "/_nuxt/mpv-shot0010.rRi4CTA-.webp": {
    "type": "image/webp",
    "etag": "\"274b6-j18uth4xncG+P+Akof5LcGNGdBY\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 160950,
    "path": "../public/_nuxt/mpv-shot0010.rRi4CTA-.webp"
  },
  "/_nuxt/mpv-shot0011.Cez22cEU.webp": {
    "type": "image/webp",
    "etag": "\"2712a-tanuXuo+6oEO2ahXvsQpmsl38zM\"",
    "mtime": "2026-09-28T12:17:37.582Z",
    "size": 160042,
    "path": "../public/_nuxt/mpv-shot0011.Cez22cEU.webp"
  },
  "/_nuxt/mpv-shot0007.BBwnlwSQ.webp": {
    "type": "image/webp",
    "etag": "\"8bc58-o8S787JA35bFYK0dyTPJXijE19c\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 572504,
    "path": "../public/_nuxt/mpv-shot0007.BBwnlwSQ.webp"
  },
  "/_nuxt/mpv-shot0012.A8ZhGDao.webp": {
    "type": "image/webp",
    "etag": "\"56e9a-ZQS8asNEJ/TGr2URXlDzge0RDPQ\"",
    "mtime": "2026-09-28T12:17:37.582Z",
    "size": 355994,
    "path": "../public/_nuxt/mpv-shot0012.A8ZhGDao.webp"
  },
  "/_nuxt/mpv-shot0011.D7lGGtjj.webp": {
    "type": "image/webp",
    "etag": "\"8e026-DwsZTDMnAFwo08c68OSsXJOXFy0\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 581670,
    "path": "../public/_nuxt/mpv-shot0011.D7lGGtjj.webp"
  },
  "/_nuxt/mpv-shot0012.DNtZLSiu.webp": {
    "type": "image/webp",
    "etag": "\"533e0-+M08ZTwXaFShzjM6GwtR0VLk+qs\"",
    "mtime": "2026-09-28T12:17:37.580Z",
    "size": 340960,
    "path": "../public/_nuxt/mpv-shot0012.DNtZLSiu.webp"
  },
  "/_nuxt/Mood.DOeN3S3Z.mp4": {
    "type": "video/mp4",
    "etag": "\"2053d6-VAXFeabJWrfYoKE5BBwaloqzMQY\"",
    "mtime": "2026-09-28T12:17:37.919Z",
    "size": 2118614,
    "path": "../public/_nuxt/Mood.DOeN3S3Z.mp4"
  },
  "/_nuxt/mpv-shot0013.C1juAq85.webp": {
    "type": "image/webp",
    "etag": "\"4fad6-dxaLCJStylhdHSlgHD7rzqVF4JQ\"",
    "mtime": "2026-09-28T12:17:37.582Z",
    "size": 326358,
    "path": "../public/_nuxt/mpv-shot0013.C1juAq85.webp"
  },
  "/_nuxt/mpv-shot0013.KoHrb48V.webp": {
    "type": "image/webp",
    "etag": "\"63e9a-9mNSQBSaITRY7C7SwE/hoBMic80\"",
    "mtime": "2026-09-28T12:17:37.580Z",
    "size": 409242,
    "path": "../public/_nuxt/mpv-shot0013.KoHrb48V.webp"
  },
  "/_nuxt/mpv-shot0014.B_mEUmtx.webp": {
    "type": "image/webp",
    "etag": "\"378e4-hwk/fpQRwu0M0yrz6AZE1ivMXrk\"",
    "mtime": "2026-09-28T12:17:37.580Z",
    "size": 227556,
    "path": "../public/_nuxt/mpv-shot0014.B_mEUmtx.webp"
  },
  "/_nuxt/mpv-shot0014.CoPZIZtH.webp": {
    "type": "image/webp",
    "etag": "\"4338c-elElHQRKCW9w9kuwARaURStnoSk\"",
    "mtime": "2026-09-28T12:17:37.582Z",
    "size": 275340,
    "path": "../public/_nuxt/mpv-shot0014.CoPZIZtH.webp"
  },
  "/_nuxt/mpv-shot0015.BPaHbOs8.webp": {
    "type": "image/webp",
    "etag": "\"52688-MkFD3Q7wR5DcDrZxBHsK6va7CsU\"",
    "mtime": "2026-09-28T12:17:37.580Z",
    "size": 337544,
    "path": "../public/_nuxt/mpv-shot0015.BPaHbOs8.webp"
  },
  "/_nuxt/mpv-shot0015.DJdV4wzQ.webp": {
    "type": "image/webp",
    "etag": "\"3489c-R6Ryzqv1zaQrpm8g1ifnegJ2qFk\"",
    "mtime": "2026-09-28T12:17:37.582Z",
    "size": 215196,
    "path": "../public/_nuxt/mpv-shot0015.DJdV4wzQ.webp"
  },
  "/_nuxt/mpv-shot0016.CryTVSdY.webp": {
    "type": "image/webp",
    "etag": "\"4b560-Jz4w2Rm8uxs9ENa0z2J111ocbfU\"",
    "mtime": "2026-09-28T12:17:37.582Z",
    "size": 308576,
    "path": "../public/_nuxt/mpv-shot0016.CryTVSdY.webp"
  },
  "/_nuxt/mpv-shot0016._0c9QXRK.webp": {
    "type": "image/webp",
    "etag": "\"55d32-d+e86JR1lIA0QVSBbbS46FK8tuM\"",
    "mtime": "2026-09-28T12:17:37.580Z",
    "size": 351538,
    "path": "../public/_nuxt/mpv-shot0016._0c9QXRK.webp"
  },
  "/_nuxt/mpv-shot0017.C4JkMyDK.webp": {
    "type": "image/webp",
    "etag": "\"5a574-A4nxZus2Gxi79mMpETMBX+dWrTc\"",
    "mtime": "2026-09-28T12:17:37.582Z",
    "size": 370036,
    "path": "../public/_nuxt/mpv-shot0017.C4JkMyDK.webp"
  },
  "/_nuxt/mpv-shot0017.Y5KYyP5m.webp": {
    "type": "image/webp",
    "etag": "\"30812-XjI0lCCjDk2Ulr9+QFdDOpGR29M\"",
    "mtime": "2026-09-28T12:17:37.580Z",
    "size": 198674,
    "path": "../public/_nuxt/mpv-shot0017.Y5KYyP5m.webp"
  },
  "/_nuxt/mpv-shot0018.DfnbMMIE.webp": {
    "type": "image/webp",
    "etag": "\"380d8-GyPz9updcdswpLYkWC7wA7YHO2s\"",
    "mtime": "2026-09-28T12:17:37.580Z",
    "size": 229592,
    "path": "../public/_nuxt/mpv-shot0018.DfnbMMIE.webp"
  },
  "/_nuxt/mpv-shot0018.yxVzSwAB.webp": {
    "type": "image/webp",
    "etag": "\"4e09c-uRtQ1/HZ6zxR1pzk72pkI7+ZyRo\"",
    "mtime": "2026-09-28T12:17:37.582Z",
    "size": 319644,
    "path": "../public/_nuxt/mpv-shot0018.yxVzSwAB.webp"
  },
  "/_nuxt/mpv-shot0019.BwWhopUi.webp": {
    "type": "image/webp",
    "etag": "\"77078-DsMAo+FcwOSduckXhkvg4KTE8+w\"",
    "mtime": "2026-09-28T12:17:37.582Z",
    "size": 487544,
    "path": "../public/_nuxt/mpv-shot0019.BwWhopUi.webp"
  },
  "/_nuxt/mpv-shot0019.C_y2IEuF.webp": {
    "type": "image/webp",
    "etag": "\"3caa8-t8DvJDk6P/gyPT4Z7mTpc59/S8w\"",
    "mtime": "2026-09-28T12:17:37.580Z",
    "size": 248488,
    "path": "../public/_nuxt/mpv-shot0019.C_y2IEuF.webp"
  },
  "/_nuxt/mpv-shot0020.CkWNt4Li.webp": {
    "type": "image/webp",
    "etag": "\"34f0c-G+o1FHHLbRRz3sRoMlnfi7LA7eI\"",
    "mtime": "2026-09-28T12:17:37.582Z",
    "size": 216844,
    "path": "../public/_nuxt/mpv-shot0020.CkWNt4Li.webp"
  },
  "/_nuxt/mpv-shot0020.DluVERIZ.webp": {
    "type": "image/webp",
    "etag": "\"5f6ce-OMRu6qmHoRJsBj1QllLnX/oP2o0\"",
    "mtime": "2026-09-28T12:17:37.580Z",
    "size": 390862,
    "path": "../public/_nuxt/mpv-shot0020.DluVERIZ.webp"
  },
  "/_nuxt/mpv-shot0021.-9m7A7dF.webp": {
    "type": "image/webp",
    "etag": "\"67440-uj8GzzovuN/bMqN6RHUF6eVpQzM\"",
    "mtime": "2026-09-28T12:17:37.582Z",
    "size": 422976,
    "path": "../public/_nuxt/mpv-shot0021.-9m7A7dF.webp"
  },
  "/_nuxt/mpv-shot0021.BjXWNTls.webp": {
    "type": "image/webp",
    "etag": "\"360f0-Nqny9Rkr5iIzcQgpbv2TtuyIwiI\"",
    "mtime": "2026-09-28T12:17:37.580Z",
    "size": 221424,
    "path": "../public/_nuxt/mpv-shot0021.BjXWNTls.webp"
  },
  "/_nuxt/mpv-shot0022.B5hLPO6R.webp": {
    "type": "image/webp",
    "etag": "\"46c46-/k6BhJc0irMCIT5Dk9yajhch4pM\"",
    "mtime": "2026-09-28T12:17:37.582Z",
    "size": 289862,
    "path": "../public/_nuxt/mpv-shot0022.B5hLPO6R.webp"
  },
  "/_nuxt/mpv-shot0022.DHmlO6rH.webp": {
    "type": "image/webp",
    "etag": "\"41ef8-5xoNuH0mhi7YTsb8MIULYXUGJtk\"",
    "mtime": "2026-09-28T12:17:37.580Z",
    "size": 270072,
    "path": "../public/_nuxt/mpv-shot0022.DHmlO6rH.webp"
  },
  "/_nuxt/mpv-shot0023.BxCs1w0v.webp": {
    "type": "image/webp",
    "etag": "\"43548-drKAfXzBrJRrjn1H5k2li1jySGc\"",
    "mtime": "2026-09-28T12:17:37.582Z",
    "size": 275784,
    "path": "../public/_nuxt/mpv-shot0023.BxCs1w0v.webp"
  },
  "/_nuxt/mpv-shot0023.CB2S_Xqd.webp": {
    "type": "image/webp",
    "etag": "\"51a2a-bhbqFJQy7TdaNt2Y8HTA3nuNXlE\"",
    "mtime": "2026-09-28T12:17:37.580Z",
    "size": 334378,
    "path": "../public/_nuxt/mpv-shot0023.CB2S_Xqd.webp"
  },
  "/_nuxt/mpv-shot0024.AXrSw4QI.webp": {
    "type": "image/webp",
    "etag": "\"4cf9e-W7//rRk3voefFOS2QRgxhApIlpU\"",
    "mtime": "2026-09-28T12:17:37.580Z",
    "size": 315294,
    "path": "../public/_nuxt/mpv-shot0024.AXrSw4QI.webp"
  },
  "/_nuxt/mpv-shot0024.DEPvHqyh.webp": {
    "type": "image/webp",
    "etag": "\"351ce-/skLkYC62GGGqKbuK3scwbX9JHs\"",
    "mtime": "2026-09-28T12:17:37.582Z",
    "size": 217550,
    "path": "../public/_nuxt/mpv-shot0024.DEPvHqyh.webp"
  },
  "/_nuxt/mpv-shot0025.CRGYpqNl.webp": {
    "type": "image/webp",
    "etag": "\"580ca-Lj+/oZcURH3U6oKrH1a0thzDrTM\"",
    "mtime": "2026-09-28T12:17:37.582Z",
    "size": 360650,
    "path": "../public/_nuxt/mpv-shot0025.CRGYpqNl.webp"
  },
  "/_nuxt/mpv-shot0025.CvzPW4aI.webp": {
    "type": "image/webp",
    "etag": "\"5e6c6-qcDS105yhRbV+zMasrjcoUnb2h4\"",
    "mtime": "2026-09-28T12:17:37.580Z",
    "size": 386758,
    "path": "../public/_nuxt/mpv-shot0025.CvzPW4aI.webp"
  },
  "/_nuxt/mpv-shot0026.B8uxsMaf.webp": {
    "type": "image/webp",
    "etag": "\"392a4-pLNmtHMO4ZE7xvxLQlbpi1UUpDY\"",
    "mtime": "2026-09-28T12:17:37.580Z",
    "size": 234148,
    "path": "../public/_nuxt/mpv-shot0026.B8uxsMaf.webp"
  },
  "/_nuxt/mpv-shot0026.Bcmrr4nr.webp": {
    "type": "image/webp",
    "etag": "\"26e9c-cKtlIwTh+jQyVW6uyOAwL512vSE\"",
    "mtime": "2026-09-28T12:17:37.582Z",
    "size": 159388,
    "path": "../public/_nuxt/mpv-shot0026.Bcmrr4nr.webp"
  },
  "/_nuxt/mpv-shot0027.CPzojBew.webp": {
    "type": "image/webp",
    "etag": "\"2f320-oN//oP03c01XszHRdm8XIgXR63k\"",
    "mtime": "2026-09-28T12:17:37.582Z",
    "size": 193312,
    "path": "../public/_nuxt/mpv-shot0027.CPzojBew.webp"
  },
  "/_nuxt/mpv-shot0027.DHRNC-FN.webp": {
    "type": "image/webp",
    "etag": "\"540ce-kudfl05o6dVkaNMD83sVItf0LxQ\"",
    "mtime": "2026-09-28T12:17:37.580Z",
    "size": 344270,
    "path": "../public/_nuxt/mpv-shot0027.DHRNC-FN.webp"
  },
  "/_nuxt/mpv-shot0028.7tFLtrUZ.webp": {
    "type": "image/webp",
    "etag": "\"32742-xCZsJspW2nUticNsFilB+Zs+lkc\"",
    "mtime": "2026-09-28T12:17:37.582Z",
    "size": 206658,
    "path": "../public/_nuxt/mpv-shot0028.7tFLtrUZ.webp"
  },
  "/_nuxt/mpv-shot0028.BdeFGjzu.webp": {
    "type": "image/webp",
    "etag": "\"4874a-WTvamD3JnHY7x02M7KQtTBjlpJ8\"",
    "mtime": "2026-09-28T12:17:37.580Z",
    "size": 296778,
    "path": "../public/_nuxt/mpv-shot0028.BdeFGjzu.webp"
  },
  "/_nuxt/mpv-shot0029.B4_DXI6b.webp": {
    "type": "image/webp",
    "etag": "\"4f50a-LVJNAyxIPOKK5IpObM2qMifoJK0\"",
    "mtime": "2026-09-28T12:17:37.580Z",
    "size": 324874,
    "path": "../public/_nuxt/mpv-shot0029.B4_DXI6b.webp"
  },
  "/_nuxt/mpv-shot0029.CalJpXCs.webp": {
    "type": "image/webp",
    "etag": "\"3d234-BhOaAqD+OnEp/QdTpOruAXTGBVo\"",
    "mtime": "2026-09-28T12:17:37.582Z",
    "size": 250420,
    "path": "../public/_nuxt/mpv-shot0029.CalJpXCs.webp"
  },
  "/_nuxt/mpv-shot0030.B6rekqTj.webp": {
    "type": "image/webp",
    "etag": "\"56fe0-zZijiDLnxBz3yf734y3SHkRqeJ8\"",
    "mtime": "2026-09-28T12:17:37.583Z",
    "size": 356320,
    "path": "../public/_nuxt/mpv-shot0030.B6rekqTj.webp"
  },
  "/_nuxt/mpv-shot0030.Db_YlQaH.webp": {
    "type": "image/webp",
    "etag": "\"7386c-9rSLYOW26X1oVIvat605wn1awdI\"",
    "mtime": "2026-09-28T12:17:37.580Z",
    "size": 473196,
    "path": "../public/_nuxt/mpv-shot0030.Db_YlQaH.webp"
  },
  "/_nuxt/mpv-shot0031.C3BkGLVv.webp": {
    "type": "image/webp",
    "etag": "\"440f4-/wNiQXykdmwQPNBecJKFbBOHHb8\"",
    "mtime": "2026-09-28T12:17:37.583Z",
    "size": 278772,
    "path": "../public/_nuxt/mpv-shot0031.C3BkGLVv.webp"
  },
  "/_nuxt/mpv-shot0032.Cu4JM3Ht.webp": {
    "type": "image/webp",
    "etag": "\"4edd0-UIcpQT9aB54/uOFYtvrRRRHWkNI\"",
    "mtime": "2026-09-28T12:17:37.582Z",
    "size": 323024,
    "path": "../public/_nuxt/mpv-shot0032.Cu4JM3Ht.webp"
  },
  "/_nuxt/mpv-shot0034.DJdYMuh2.webp": {
    "type": "image/webp",
    "etag": "\"27458-iA5haUwAc0Px2BQ3irjRmTC4oRM\"",
    "mtime": "2026-09-28T12:17:37.583Z",
    "size": 160856,
    "path": "../public/_nuxt/mpv-shot0034.DJdYMuh2.webp"
  },
  "/_nuxt/mpv-shot0035.Dt03FRIQ.webp": {
    "type": "image/webp",
    "etag": "\"264a4-YyTm9IhTvJ2FuJY5pJV5oVFcCss\"",
    "mtime": "2026-09-28T12:17:37.583Z",
    "size": 156836,
    "path": "../public/_nuxt/mpv-shot0035.Dt03FRIQ.webp"
  },
  "/_nuxt/mpv-shot0033.DedEREbB.webp": {
    "type": "image/webp",
    "etag": "\"4af84-5ybT22pFSs3hScC8EjeomzfPeJ4\"",
    "mtime": "2026-09-28T12:17:37.583Z",
    "size": 307076,
    "path": "../public/_nuxt/mpv-shot0033.DedEREbB.webp"
  },
  "/_nuxt/mpv-shot0036.3Gaa4fgv.webp": {
    "type": "image/webp",
    "etag": "\"37bb2-v5ZUm6BD+MCOF6373ikb617puMI\"",
    "mtime": "2026-09-28T12:17:37.583Z",
    "size": 228274,
    "path": "../public/_nuxt/mpv-shot0036.3Gaa4fgv.webp"
  },
  "/_nuxt/Mw03s_rb.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-3+YEYTHsI755sarHcylfBggMsAo\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 110,
    "path": "../public/_nuxt/Mw03s_rb.js"
  },
  "/_nuxt/MwgaiYOd.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-hAk3DjgviszQuwL0fqktLhhrQCw\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 110,
    "path": "../public/_nuxt/MwgaiYOd.js"
  },
  "/_nuxt/MyLamination-1.DEdhDx0K.webp": {
    "type": "image/webp",
    "etag": "\"58b2e-WTFK5JUre8yCt3dSu8S56eMf2yU\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 363310,
    "path": "../public/_nuxt/MyLamination-1.DEdhDx0K.webp"
  },
  "/_nuxt/MyLamination-11.H-UCQOU2.webp": {
    "type": "image/webp",
    "etag": "\"70338-652I6I6ZnUdcmWcfY1IVaFqLDl0\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 459576,
    "path": "../public/_nuxt/MyLamination-11.H-UCQOU2.webp"
  },
  "/_nuxt/MyLamination-13.j8h24tZT.webp": {
    "type": "image/webp",
    "etag": "\"4bd18-4GdOmbYhtEPpgVUuGUP/IS8eXFw\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 310552,
    "path": "../public/_nuxt/MyLamination-13.j8h24tZT.webp"
  },
  "/_nuxt/MyLamination-14.DllIOz8w.webp": {
    "type": "image/webp",
    "etag": "\"77cc6-HxccVLA5RL7zJNE6tSqrbfCdPQU\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 490694,
    "path": "../public/_nuxt/MyLamination-14.DllIOz8w.webp"
  },
  "/_nuxt/MyLamination-15.ZAPrPgHL.webp": {
    "type": "image/webp",
    "etag": "\"68926-Or7sTcnb+Tjg+46STOZE/xnF+9U\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 428326,
    "path": "../public/_nuxt/MyLamination-15.ZAPrPgHL.webp"
  },
  "/_nuxt/MyLamination-16.BVAwx8av.webp": {
    "type": "image/webp",
    "etag": "\"692e2-n89H2EevVHSm7t9JVTdSZl85jdY\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 430818,
    "path": "../public/_nuxt/MyLamination-16.BVAwx8av.webp"
  },
  "/_nuxt/MyLamination-3.CME1PvBS.webp": {
    "type": "image/webp",
    "etag": "\"541a2-XSYi6v1KvxHA8QCQHuu5KxuWXk8\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 344482,
    "path": "../public/_nuxt/MyLamination-3.CME1PvBS.webp"
  },
  "/_nuxt/MyLamination-5.SlyAbUEr.webp": {
    "type": "image/webp",
    "etag": "\"6c030-2uK9v32sZ5Vnlijt+gZw3PvRZ6k\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 442416,
    "path": "../public/_nuxt/MyLamination-5.SlyAbUEr.webp"
  },
  "/_nuxt/MyLamination-6.CQHkb8vj.webp": {
    "type": "image/webp",
    "etag": "\"53f9e-IIziVdMrfGIJrdLM2q2UWhOgLX0\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 343966,
    "path": "../public/_nuxt/MyLamination-6.CQHkb8vj.webp"
  },
  "/_nuxt/mUQozsi_.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"79-oIunTppQmqLYAGfZ1t7Jk8mYVh4\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 121,
    "path": "../public/_nuxt/mUQozsi_.js"
  },
  "/_nuxt/MyLamination-7.CAZEQMJt.webp": {
    "type": "image/webp",
    "etag": "\"55c7c-TNgMbXxNYlQEgxate91wTTkX6ic\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 351356,
    "path": "../public/_nuxt/MyLamination-7.CAZEQMJt.webp"
  },
  "/_nuxt/MyLamination-9.c29xTlFQ.webp": {
    "type": "image/webp",
    "etag": "\"75ad8-mGDrU5/21Ke2V3eNg1FeOZUiG1E\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 482008,
    "path": "../public/_nuxt/MyLamination-9.c29xTlFQ.webp"
  },
  "/_nuxt/MyLamination-17.BVJBbPWl.webp": {
    "type": "image/webp",
    "etag": "\"810f0-zzUCVidI8S/1Mv6whWrJ5Opej1g\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 528624,
    "path": "../public/_nuxt/MyLamination-17.BVJBbPWl.webp"
  },
  "/_nuxt/MyLamination-19.BsGVGjEy.webp": {
    "type": "image/webp",
    "etag": "\"896bc-IRPADobx7Pyhs8Flfjwh8p0jI7M\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 562876,
    "path": "../public/_nuxt/MyLamination-19.BsGVGjEy.webp"
  },
  "/_nuxt/NS-Jrxc4.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-iSl3E0nAlmw6QPOmqgIy1X6I1Ik\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/NS-Jrxc4.js"
  },
  "/_nuxt/nJ2wZ7k6.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-XWAeocIMW8wOAx06wL3b6/ewokQ\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 114,
    "path": "../public/_nuxt/nJ2wZ7k6.js"
  },
  "/_nuxt/na7V9tia.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"75-MV5bjgoVOdkFoiguZzb4AJNAwM4\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 117,
    "path": "../public/_nuxt/na7V9tia.js"
  },
  "/_nuxt/NF2NRPD6.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"d57-9Sv2XaAkHyrdm0cmHkwIJWWg38w\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 3415,
    "path": "../public/_nuxt/NF2NRPD6.js"
  },
  "/_nuxt/nYmQlMhE.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-1ZHN6pZH511pVJNjQfCej8O40DA\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 119,
    "path": "../public/_nuxt/nYmQlMhE.js"
  },
  "/_nuxt/NvKhiGA2.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-nGXimritaVmHSvcJt61VfTmE6OE\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 122,
    "path": "../public/_nuxt/NvKhiGA2.js"
  },
  "/_nuxt/MyLamination-8._EcY2sqf.webp": {
    "type": "image/webp",
    "etag": "\"84b26-TRkZHm5RY+0n0iDIBN+SEiRnFko\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 543526,
    "path": "../public/_nuxt/MyLamination-8._EcY2sqf.webp"
  },
  "/_nuxt/nZOfMSdk.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7f-oGP9Iab1NcXZ1ry6MPkDXUDQu20\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 127,
    "path": "../public/_nuxt/nZOfMSdk.js"
  },
  "/_nuxt/oX0Y8SNp.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-gOw4DlErcq22Cp6wVLjXsCtM3Ak\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 107,
    "path": "../public/_nuxt/oX0Y8SNp.js"
  },
  "/_nuxt/oaGtAVft.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-qP8Fr3nJ8ntWdEP4C3rPoKkesBA\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 107,
    "path": "../public/_nuxt/oaGtAVft.js"
  },
  "/_nuxt/opJjL8Zg.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-kPLHZ+2WeExwrmitztLpJBrEUS4\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 120,
    "path": "../public/_nuxt/opJjL8Zg.js"
  },
  "/_nuxt/P1012607.DHBoQSeF.webp": {
    "type": "image/webp",
    "etag": "\"68720-WRyh4HJ1rfZR3mRakyh3nsRsQTY\"",
    "mtime": "2026-09-28T12:17:37.583Z",
    "size": 427808,
    "path": "../public/_nuxt/P1012607.DHBoQSeF.webp"
  },
  "/_nuxt/P1012610.OtEs1SL3.webp": {
    "type": "image/webp",
    "etag": "\"6b410-aK2UZeYJgbLLPyEalsStvSg7yz8\"",
    "mtime": "2026-09-28T12:17:37.583Z",
    "size": 439312,
    "path": "../public/_nuxt/P1012610.OtEs1SL3.webp"
  },
  "/_nuxt/oIrm3p64.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-LjzN5nd/uDPUa2cYYyioHOtwnec\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 122,
    "path": "../public/_nuxt/oIrm3p64.js"
  },
  "/_nuxt/P1012611.ehDCeD4o.webp": {
    "type": "image/webp",
    "etag": "\"7325c-0joaMON7INQaur3iXXaJGByLXqM\"",
    "mtime": "2026-09-28T12:17:37.583Z",
    "size": 471644,
    "path": "../public/_nuxt/P1012611.ehDCeD4o.webp"
  },
  "/_nuxt/P1012624.TGXTNYIZ.webp": {
    "type": "image/webp",
    "etag": "\"71646-NOFQz0vebl2XvbOqT52sGln/vyg\"",
    "mtime": "2026-09-28T12:17:37.583Z",
    "size": 464454,
    "path": "../public/_nuxt/P1012624.TGXTNYIZ.webp"
  },
  "/_nuxt/P0YgC2sb.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-5vlSPH+dBXFWibZMroLpXvohT0U\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/P0YgC2sb.js"
  },
  "/_nuxt/P1012636.DqP6OjA0.webp": {
    "type": "image/webp",
    "etag": "\"6c75c-5nq5mLQO926LY3/AYCXgf8M0RXw\"",
    "mtime": "2026-09-28T12:17:37.583Z",
    "size": 444252,
    "path": "../public/_nuxt/P1012636.DqP6OjA0.webp"
  },
  "/_nuxt/P1012684.BklHBkzB.webp": {
    "type": "image/webp",
    "etag": "\"738b6-Zz1hItiuve6a1gpV2+gErXn2Tkk\"",
    "mtime": "2026-09-28T12:17:37.583Z",
    "size": 473270,
    "path": "../public/_nuxt/P1012684.BklHBkzB.webp"
  },
  "/_nuxt/P1012694.Jll9f4kB.webp": {
    "type": "image/webp",
    "etag": "\"78eae-I5mUQdXytYf1w7JojWEXv8IFnxU\"",
    "mtime": "2026-09-28T12:17:37.583Z",
    "size": 495278,
    "path": "../public/_nuxt/P1012694.Jll9f4kB.webp"
  },
  "/_nuxt/P1012630.AMQjT0eN.webp": {
    "type": "image/webp",
    "etag": "\"920c8-TVI0Qw78O+Ti4EtIJj7NSzjS5kQ\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 598216,
    "path": "../public/_nuxt/P1012630.AMQjT0eN.webp"
  },
  "/_nuxt/P1012705.DeIqemxL.webp": {
    "type": "image/webp",
    "etag": "\"5c21c-L0vbRtpQd+RQbP65EpFzqHcKzjU\"",
    "mtime": "2026-09-28T12:17:37.583Z",
    "size": 377372,
    "path": "../public/_nuxt/P1012705.DeIqemxL.webp"
  },
  "/_nuxt/P1012646.Dcp3DggT.webp": {
    "type": "image/webp",
    "etag": "\"ab886-BQfUtLqJUuGLoTMN5przAgNe96o\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 702598,
    "path": "../public/_nuxt/P1012646.Dcp3DggT.webp"
  },
  "/_nuxt/P1012669.DnUTwB8X.webp": {
    "type": "image/webp",
    "etag": "\"9d43c-xr1a1yxh8CjS5lQ2nDMSH6Rdm4E\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 644156,
    "path": "../public/_nuxt/P1012669.DnUTwB8X.webp"
  },
  "/_nuxt/P1012747.BDrIW0Tn.webp": {
    "type": "image/webp",
    "etag": "\"7739e-9frjh28QVIIs5rHxQZgIE6bYEpI\"",
    "mtime": "2026-09-28T12:17:37.583Z",
    "size": 488350,
    "path": "../public/_nuxt/P1012747.BDrIW0Tn.webp"
  },
  "/_nuxt/P1012676.BTcyZW1f.webp": {
    "type": "image/webp",
    "etag": "\"b7990-ysln08CBucYoHbosjGdB7U1lXEw\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 752016,
    "path": "../public/_nuxt/P1012676.BTcyZW1f.webp"
  },
  "/_nuxt/P1012677.CI02Z9_i.webp": {
    "type": "image/webp",
    "etag": "\"931ba-hzKzqN/btteyLDbpsh3fWzmjwwE\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 602554,
    "path": "../public/_nuxt/P1012677.CI02Z9_i.webp"
  },
  "/_nuxt/P1012696.DJmgihe4.webp": {
    "type": "image/webp",
    "etag": "\"a025e-VOeNNEKsYHOR4RQMC7yt5q5634k\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 655966,
    "path": "../public/_nuxt/P1012696.DJmgihe4.webp"
  },
  "/_nuxt/P1012726.CrY1NAea.webp": {
    "type": "image/webp",
    "etag": "\"8e9ee-TRfo/fEMqgdaQcNYlFkWYr9r67c\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 584174,
    "path": "../public/_nuxt/P1012726.CrY1NAea.webp"
  },
  "/_nuxt/P1012734.DOe6MUFZ.webp": {
    "type": "image/webp",
    "etag": "\"946a8-wHWrpip/ChO0j5yeljUBBe/4N0o\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 607912,
    "path": "../public/_nuxt/P1012734.DOe6MUFZ.webp"
  },
  "/_nuxt/P1012752.hhR9Oe4m.webp": {
    "type": "image/webp",
    "etag": "\"9b134-DHPHtWon86XAWcVaH5RYiJDJ3a8\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 635188,
    "path": "../public/_nuxt/P1012752.hhR9Oe4m.webp"
  },
  "/_nuxt/PANA9339.DZ14lbIl.webp": {
    "type": "image/webp",
    "etag": "\"36858-PFx93h4yEZD3FY4ucbXyMqwR+YA\"",
    "mtime": "2026-09-28T12:17:37.578Z",
    "size": 223320,
    "path": "../public/_nuxt/PANA9339.DZ14lbIl.webp"
  },
  "/_nuxt/PANA9342.DPsXQ1Ck.webp": {
    "type": "image/webp",
    "etag": "\"24f5c-GhOTYIjWru0QU7BJ8iBS+T13Ti0\"",
    "mtime": "2026-09-28T12:17:37.578Z",
    "size": 151388,
    "path": "../public/_nuxt/PANA9342.DPsXQ1Ck.webp"
  },
  "/_nuxt/PANA9347.C6FNWSRe.webp": {
    "type": "image/webp",
    "etag": "\"32b22-abPIR6H/JmVwtyEP6NWMRb3hHTo\"",
    "mtime": "2026-09-28T12:17:37.578Z",
    "size": 207650,
    "path": "../public/_nuxt/PANA9347.C6FNWSRe.webp"
  },
  "/_nuxt/PANA9348.CwHsorxG.webp": {
    "type": "image/webp",
    "etag": "\"6f35e-mmXRkiWKu2/sandPhhsIO+MthEk\"",
    "mtime": "2026-09-28T12:17:37.578Z",
    "size": 455518,
    "path": "../public/_nuxt/PANA9348.CwHsorxG.webp"
  },
  "/_nuxt/PANA9392.CI_4YH72.webp": {
    "type": "image/webp",
    "etag": "\"54bda-eCBCSEH9Eyu8QO9ewMuHu1Hghhc\"",
    "mtime": "2026-09-28T12:17:37.578Z",
    "size": 347098,
    "path": "../public/_nuxt/PANA9392.CI_4YH72.webp"
  },
  "/_nuxt/PANA9395.CRsHSK3X.webp": {
    "type": "image/webp",
    "etag": "\"2fc90-Ypzjx7PrOK7QXfG60HEjyN83MYI\"",
    "mtime": "2026-09-28T12:17:37.578Z",
    "size": 195728,
    "path": "../public/_nuxt/PANA9395.CRsHSK3X.webp"
  },
  "/_nuxt/PANA9397.BFIGaeXp.webp": {
    "type": "image/webp",
    "etag": "\"44022-bGK5rATGWws4+dKSjabIpgBRrIE\"",
    "mtime": "2026-09-28T12:17:37.578Z",
    "size": 278562,
    "path": "../public/_nuxt/PANA9397.BFIGaeXp.webp"
  },
  "/_nuxt/PANA9401.-5XSY0zU.webp": {
    "type": "image/webp",
    "etag": "\"4fb84-NGaAO3V9OrwMY56xjoLB1MKYNJY\"",
    "mtime": "2026-09-28T12:17:37.578Z",
    "size": 326532,
    "path": "../public/_nuxt/PANA9401.-5XSY0zU.webp"
  },
  "/_nuxt/PANA9403.C8awFeF2.webp": {
    "type": "image/webp",
    "etag": "\"6610c-OtHDksgp37lmIVi2TlgADrjZOQ8\"",
    "mtime": "2026-09-28T12:17:37.578Z",
    "size": 418060,
    "path": "../public/_nuxt/PANA9403.C8awFeF2.webp"
  },
  "/_nuxt/PANA9412.IQen3UPO.webp": {
    "type": "image/webp",
    "etag": "\"37d42-QFUk9zSoDDzcqX/9lgduJeLSZR0\"",
    "mtime": "2026-09-28T12:17:37.578Z",
    "size": 228674,
    "path": "../public/_nuxt/PANA9412.IQen3UPO.webp"
  },
  "/_nuxt/PowerGrotesk-Regular.DNJ9ML-1.woff2": {
    "type": "font/woff2",
    "etag": "\"53b4-3y3eUrmFI11SKzg4U8TvS0hSFf0\"",
    "mtime": "2026-09-28T12:17:37.433Z",
    "size": 21428,
    "path": "../public/_nuxt/PowerGrotesk-Regular.DNJ9ML-1.woff2"
  },
  "/_nuxt/PykcmSbo.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-/PaHPTJYw0Nj6otsAbG93RV7+sI\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 107,
    "path": "../public/_nuxt/PykcmSbo.js"
  },
  "/_nuxt/PA8DC59D.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"76-/j7nIXTp3XfXeOnf8QIFdLTYHz0\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 118,
    "path": "../public/_nuxt/PA8DC59D.js"
  },
  "/_nuxt/pcUHmIyP.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"70-TA33oy8rxpHA3pAXVguJDV7fSdQ\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 112,
    "path": "../public/_nuxt/pcUHmIyP.js"
  },
  "/_nuxt/PANA9405.DycVmkCK.webp": {
    "type": "image/webp",
    "etag": "\"b78ca-BCAnQDc578V7xKfQyO93YCdkiXU\"",
    "mtime": "2026-09-28T12:17:37.610Z",
    "size": 751818,
    "path": "../public/_nuxt/PANA9405.DycVmkCK.webp"
  },
  "/_nuxt/PANA9407.BcPLIf9C.webp": {
    "type": "image/webp",
    "etag": "\"c7a4c-KDzh/czGFYGC2IU2FwCJ+IIksZU\"",
    "mtime": "2026-09-28T12:17:37.610Z",
    "size": 817740,
    "path": "../public/_nuxt/PANA9407.BcPLIf9C.webp"
  },
  "/_nuxt/PANA9409.DaHVepRC.webp": {
    "type": "image/webp",
    "etag": "\"90d5e-ZxuPoT/GAPFrjfPHQLapmuaj0pk\"",
    "mtime": "2026-09-28T12:17:37.610Z",
    "size": 593246,
    "path": "../public/_nuxt/PANA9409.DaHVepRC.webp"
  },
  "/_nuxt/pZhJMGFr.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6f-w9XDiBAF6fWHelySLGkFcXoPp4I\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 111,
    "path": "../public/_nuxt/pZhJMGFr.js"
  },
  "/_nuxt/Pf9m3M4j.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-ZEGWQBwKlH2SOOvE+jXXRO08kTg\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 119,
    "path": "../public/_nuxt/Pf9m3M4j.js"
  },
  "/_nuxt/P_wD5yLO.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-SVoxgWQg6EnkNvBFb/SX5Mw3+/g\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 114,
    "path": "../public/_nuxt/P_wD5yLO.js"
  },
  "/_nuxt/QkPkNSZ_.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-YUYW9JkobsVIDSZVG2DLhxiN2rA\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 113,
    "path": "../public/_nuxt/QkPkNSZ_.js"
  },
  "/_nuxt/q9aq-7oj.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-KWVxZyEGbvg0kK4UwmW+xirmC0M\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 113,
    "path": "../public/_nuxt/q9aq-7oj.js"
  },
  "/_nuxt/Qb-g8z1n.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-2w2mmuDMA8TriorqX6kLlRVIcIw\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 114,
    "path": "../public/_nuxt/Qb-g8z1n.js"
  },
  "/_nuxt/rigolizia_1.H552A0St.webp": {
    "type": "image/webp",
    "etag": "\"59a08-zN+Pnj/4y3XrJZdkTupf2aJThwM\"",
    "mtime": "2026-09-28T12:17:37.583Z",
    "size": 367112,
    "path": "../public/_nuxt/rigolizia_1.H552A0St.webp"
  },
  "/_nuxt/rigolizia_10.DWCP-yRx.webp": {
    "type": "image/webp",
    "etag": "\"790fa-dlmcVAwT6FdGdAfxDgeNsLfkbJQ\"",
    "mtime": "2026-09-28T12:17:37.583Z",
    "size": 495866,
    "path": "../public/_nuxt/rigolizia_10.DWCP-yRx.webp"
  },
  "/_nuxt/RANDOM4.C23X0MsK.webp": {
    "type": "image/webp",
    "etag": "\"e9b7e-vQSdFeKiy/RXJ3ko04jhEE/r15M\"",
    "mtime": "2026-09-28T12:17:37.610Z",
    "size": 957310,
    "path": "../public/_nuxt/RANDOM4.C23X0MsK.webp"
  },
  "/_nuxt/rigolizia_13.BTCnC0t2.webp": {
    "type": "image/webp",
    "etag": "\"65c98-llWO0lyGevMk/gvVd4X8xSHwYD0\"",
    "mtime": "2026-09-28T12:17:37.583Z",
    "size": 416920,
    "path": "../public/_nuxt/rigolizia_13.BTCnC0t2.webp"
  },
  "/_nuxt/rigolizia_11.DYXd5iPW.webp": {
    "type": "image/webp",
    "etag": "\"bee6c-sgGLeW8qKSvFIvcU8a8nJ2hiGb4\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 781932,
    "path": "../public/_nuxt/rigolizia_11.DYXd5iPW.webp"
  },
  "/_nuxt/RANDOM19.55xTwRTV.webp": {
    "type": "image/webp",
    "etag": "\"17e62a-0/N7T2hLK6wv9/UMrFjdfoIsLkc\"",
    "mtime": "2026-09-28T12:17:37.893Z",
    "size": 1566250,
    "path": "../public/_nuxt/RANDOM19.55xTwRTV.webp"
  },
  "/_nuxt/R9DIN9rd.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-jWnzpESYLazerTQmX39E37pn6nw\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 122,
    "path": "../public/_nuxt/R9DIN9rd.js"
  },
  "/_nuxt/r6FUSuTw.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-G8ykK+MhoU78yKrsxUkDvNcr+9w\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/r6FUSuTw.js"
  },
  "/_nuxt/rigolizia_12.DqkzmLrs.webp": {
    "type": "image/webp",
    "etag": "\"9f072-85pO+SShlLqHMnqytZ6KUfIWrxo\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 651378,
    "path": "../public/_nuxt/rigolizia_12.DqkzmLrs.webp"
  },
  "/_nuxt/rigolizia_22.Cd28j9ND.webp": {
    "type": "image/webp",
    "etag": "\"723a4-zHcAG45I9Pgor3Sw/VFdeS5/aII\"",
    "mtime": "2026-09-28T12:17:37.583Z",
    "size": 467876,
    "path": "../public/_nuxt/rigolizia_22.Cd28j9ND.webp"
  },
  "/_nuxt/rigolizia_14.DXN9OKAR.webp": {
    "type": "image/webp",
    "etag": "\"c5ad0-mAYHhbfFuzYG7sLQiwDrdkJnrPA\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 809680,
    "path": "../public/_nuxt/rigolizia_14.DXN9OKAR.webp"
  },
  "/_nuxt/rigolizia_15.Dq5rQ8kX.webp": {
    "type": "image/webp",
    "etag": "\"966ac-oC2/SvUTq2boR4l0VRyt0eSwGyY\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 616108,
    "path": "../public/_nuxt/rigolizia_15.Dq5rQ8kX.webp"
  },
  "/_nuxt/rigolizia_17.sc9Ntezp.webp": {
    "type": "image/webp",
    "etag": "\"cf8f6-wKYdlvMMvZDz1+VyTry3P/3GDaY\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 850166,
    "path": "../public/_nuxt/rigolizia_17.sc9Ntezp.webp"
  },
  "/_nuxt/rigolizia_18.BGpsXjTo.webp": {
    "type": "image/webp",
    "etag": "\"bf8a6-ZIxDWaHLVmosB7F2y2zfY1BPBYc\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 784550,
    "path": "../public/_nuxt/rigolizia_18.BGpsXjTo.webp"
  },
  "/_nuxt/rigolizia_2.DwB3YPvP.webp": {
    "type": "image/webp",
    "etag": "\"9c8da-3NmvoBBeHGMPLSO0AwgzcRMk1+s\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 641242,
    "path": "../public/_nuxt/rigolizia_2.DwB3YPvP.webp"
  },
  "/_nuxt/rigolizia_19.Ct2yh91A.webp": {
    "type": "image/webp",
    "etag": "\"8e8ec-KZ8xgPSBLplhUwG/3xF2xmj41Vc\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 583916,
    "path": "../public/_nuxt/rigolizia_19.Ct2yh91A.webp"
  },
  "/_nuxt/rigolizia_20.BVewlEKg.webp": {
    "type": "image/webp",
    "etag": "\"87c28-zW9DNQCgN5+AnKS6BbAkNU0SArs\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 556072,
    "path": "../public/_nuxt/rigolizia_20.BVewlEKg.webp"
  },
  "/_nuxt/rigolizia_21.BqkTF_uc.webp": {
    "type": "image/webp",
    "etag": "\"947a6-A8pljk0RhmjDGITC096XzmpD/N0\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 608166,
    "path": "../public/_nuxt/rigolizia_21.BqkTF_uc.webp"
  },
  "/_nuxt/Paganella-Prep.D-lEEBse.mp4": {
    "type": "video/mp4",
    "etag": "\"483428-0XGEEoKjQAOsYcAtxcJ0MKK8g7I\"",
    "mtime": "2026-09-28T12:17:37.921Z",
    "size": 4731944,
    "path": "../public/_nuxt/Paganella-Prep.D-lEEBse.mp4"
  },
  "/_nuxt/rigolizia_23.Ch5TH77J.webp": {
    "type": "image/webp",
    "etag": "\"aeeee-H4AOHo/7dOgLDKfMaxJV2nL+1n0\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 716526,
    "path": "../public/_nuxt/rigolizia_23.Ch5TH77J.webp"
  },
  "/_nuxt/rigolizia_3.BE2wZv0G.webp": {
    "type": "image/webp",
    "etag": "\"9d0e0-oe67DWCbmJUyXYpCqEFTAIE3GEk\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 643296,
    "path": "../public/_nuxt/rigolizia_3.BE2wZv0G.webp"
  },
  "/_nuxt/rigolizia_4.C6m7ewT5.webp": {
    "type": "image/webp",
    "etag": "\"9e5fc-yWiQBYT3amJPDgOqQcJ+lgiiYrs\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 648700,
    "path": "../public/_nuxt/rigolizia_4.C6m7ewT5.webp"
  },
  "/_nuxt/rigolizia_5.DO5cyP62.webp": {
    "type": "image/webp",
    "etag": "\"91e2a-6AeUDa87HD+wQZ6ha/UjWiiElBU\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 597546,
    "path": "../public/_nuxt/rigolizia_5.DO5cyP62.webp"
  },
  "/_nuxt/rigolizia_6.BLQdPqo9.webp": {
    "type": "image/webp",
    "etag": "\"a33a6-wteMFqSoMNHPkCloLfX7qYSMh9s\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 668582,
    "path": "../public/_nuxt/rigolizia_6.BLQdPqo9.webp"
  },
  "/_nuxt/rigolizia_8.la8zDCTp.webp": {
    "type": "image/webp",
    "etag": "\"a3f92-8XNUQkEC/RhmsBn6az5cE9ILMEM\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 671634,
    "path": "../public/_nuxt/rigolizia_8.la8zDCTp.webp"
  },
  "/_nuxt/rigolizia_7.DaWq9N-y.webp": {
    "type": "image/webp",
    "etag": "\"9c282-YI5h8x9aBnqwt0CSSpxcDt58WwU\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 639618,
    "path": "../public/_nuxt/rigolizia_7.DaWq9N-y.webp"
  },
  "/_nuxt/rigolizia_9.D-0LNBMg.webp": {
    "type": "image/webp",
    "etag": "\"bfd72-P3us9UUJbSMq8OfgQyoD+dhfxxg\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 785778,
    "path": "../public/_nuxt/rigolizia_9.D-0LNBMg.webp"
  },
  "/_nuxt/roma_2026_104.TX3LaVAi.webp": {
    "type": "image/webp",
    "etag": "\"e4c54-z53Z4x9uGqy66UbT3e6vMwaEXew\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 937044,
    "path": "../public/_nuxt/roma_2026_104.TX3LaVAi.webp"
  },
  "/_nuxt/roma_2026_121.Do1wCuia.webp": {
    "type": "image/webp",
    "etag": "\"f8148-WYG8Cnh3lMWt49jFVFYQqCbNTkM\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 1016136,
    "path": "../public/_nuxt/roma_2026_121.Do1wCuia.webp"
  },
  "/_nuxt/roma_2026_132.CeTqVtpz.webp": {
    "type": "image/webp",
    "etag": "\"b4932-s23NGZFE4Lbs8gaGmSNsp5nMlcg\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 739634,
    "path": "../public/_nuxt/roma_2026_132.CeTqVtpz.webp"
  },
  "/_nuxt/qoAE13G5.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"14234-AkFDd4b6Mc9k+fHKhPaxivpWBwM\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 82484,
    "path": "../public/_nuxt/qoAE13G5.js"
  },
  "/_nuxt/roma_2026_15.DWf4L3zu.webp": {
    "type": "image/webp",
    "etag": "\"e741c-GEmyqNpPD+3LFt6sw0J7BztZ6nY\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 947228,
    "path": "../public/_nuxt/roma_2026_15.DWf4L3zu.webp"
  },
  "/_nuxt/roma_2026_114.H-aKDmFY.webp": {
    "type": "image/webp",
    "etag": "\"135752-UIHtUwsnhIxvZPZfz8Pc0sv6XcM\"",
    "mtime": "2026-09-28T12:17:37.894Z",
    "size": 1267538,
    "path": "../public/_nuxt/roma_2026_114.H-aKDmFY.webp"
  },
  "/_nuxt/roma_2026_140.BL7YY3UN.webp": {
    "type": "image/webp",
    "etag": "\"11630a-upL4yHROcEI658k+b8OLy9RTYL4\"",
    "mtime": "2026-09-28T12:17:37.894Z",
    "size": 1139466,
    "path": "../public/_nuxt/roma_2026_140.BL7YY3UN.webp"
  },
  "/_nuxt/roma_2026_151.Bj0PQCWN.webp": {
    "type": "image/webp",
    "etag": "\"e6f70-GBUSN8jI8ZP2AMjK+b8a++P5+8o\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 946032,
    "path": "../public/_nuxt/roma_2026_151.Bj0PQCWN.webp"
  },
  "/_nuxt/roma_2026_16.DQ4lnpMb.webp": {
    "type": "image/webp",
    "etag": "\"ebf08-GjJN/yGrV7A5gMMxh8xjuFFwv6w\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 966408,
    "path": "../public/_nuxt/roma_2026_16.DQ4lnpMb.webp"
  },
  "/_nuxt/roma_2026_167.uy7pMQ1S.webp": {
    "type": "image/webp",
    "etag": "\"c55b6-atuoWOSVFDjekLsXNAdnccnkoTg\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 808374,
    "path": "../public/_nuxt/roma_2026_167.uy7pMQ1S.webp"
  },
  "/_nuxt/roma_2026_173.B_1v2i5E.webp": {
    "type": "image/webp",
    "etag": "\"bfe9a-39THK/GgLQFzcVP7+JaFIjEMoOU\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 786074,
    "path": "../public/_nuxt/roma_2026_173.B_1v2i5E.webp"
  },
  "/_nuxt/roma_2026_168.CgKBD66M.webp": {
    "type": "image/webp",
    "etag": "\"c7b80-GnXaXQY943IJNE7rF5ZLlFPkbKg\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 818048,
    "path": "../public/_nuxt/roma_2026_168.CgKBD66M.webp"
  },
  "/_nuxt/roma_2026_153.D9U4xmGH.webp": {
    "type": "image/webp",
    "etag": "\"102a04-qPQKkglY205DQg15P5DMqH6b8mE\"",
    "mtime": "2026-09-28T12:17:37.894Z",
    "size": 1059332,
    "path": "../public/_nuxt/roma_2026_153.D9U4xmGH.webp"
  },
  "/_nuxt/roma_2026_203.6h6jbqFp.webp": {
    "type": "image/webp",
    "etag": "\"bde6a-0zy+W6HV+zqruYapoyFeHr6HVDs\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 777834,
    "path": "../public/_nuxt/roma_2026_203.6h6jbqFp.webp"
  },
  "/_nuxt/roma_2026_198.BneHqWUc.webp": {
    "type": "image/webp",
    "etag": "\"c9838-p7+Td8dTQwjZYP9QY/zdGhs0SfY\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 825400,
    "path": "../public/_nuxt/roma_2026_198.BneHqWUc.webp"
  },
  "/_nuxt/roma_2026_204.DBY5_thM.webp": {
    "type": "image/webp",
    "etag": "\"cdd70-XkC1BdNgZT5aZXM5aZ9v13fwImc\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 843120,
    "path": "../public/_nuxt/roma_2026_204.DBY5_thM.webp"
  },
  "/_nuxt/roma_2026_218.CiYacnta.webp": {
    "type": "image/webp",
    "etag": "\"f87b0-3Ph1/duhl9jPyM8NUCk8EKFaNiQ\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 1017776,
    "path": "../public/_nuxt/roma_2026_218.CiYacnta.webp"
  },
  "/_nuxt/roma_2026_18.Df7ri95l.webp": {
    "type": "image/webp",
    "etag": "\"10fb7a-W3TjXwtW+HDNEb0MWPG8Tzh3zxQ\"",
    "mtime": "2026-09-28T12:17:37.894Z",
    "size": 1112954,
    "path": "../public/_nuxt/roma_2026_18.Df7ri95l.webp"
  },
  "/_nuxt/roma_2026_187.DG7fb2SX.webp": {
    "type": "image/webp",
    "etag": "\"17c9b4-vynKO4OS6rzG6rlDr6TOHcr3XMw\"",
    "mtime": "2026-09-28T12:17:37.894Z",
    "size": 1558964,
    "path": "../public/_nuxt/roma_2026_187.DG7fb2SX.webp"
  },
  "/_nuxt/roma_2026_22.DiuCUPlo.webp": {
    "type": "image/webp",
    "etag": "\"f01f2-YdIHuVewkiVDYmcE6AjY6vdjbek\"",
    "mtime": "2026-09-28T12:17:37.614Z",
    "size": 983538,
    "path": "../public/_nuxt/roma_2026_22.DiuCUPlo.webp"
  },
  "/_nuxt/roma_2026_189.BNZqO7r3.webp": {
    "type": "image/webp",
    "etag": "\"106bbe-3DLZpGuY8m9TYOiPSfZRzd10f/M\"",
    "mtime": "2026-09-28T12:17:37.894Z",
    "size": 1076158,
    "path": "../public/_nuxt/roma_2026_189.BNZqO7r3.webp"
  },
  "/_nuxt/roma_2026_188.CoLt3KVy.webp": {
    "type": "image/webp",
    "etag": "\"1608a2-8H69bUZ0PXs40wf9N1n6C5FzwmA\"",
    "mtime": "2026-09-28T12:17:37.894Z",
    "size": 1444002,
    "path": "../public/_nuxt/roma_2026_188.CoLt3KVy.webp"
  },
  "/_nuxt/roma_2026_220.C9kZ9-S0.webp": {
    "type": "image/webp",
    "etag": "\"a7c20-3PTq6otuKTORiaOYVhGsOQZ7AuE\"",
    "mtime": "2026-09-28T12:17:37.613Z",
    "size": 687136,
    "path": "../public/_nuxt/roma_2026_220.C9kZ9-S0.webp"
  },
  "/_nuxt/roma_2026_23.BQ_A61VZ.webp": {
    "type": "image/webp",
    "etag": "\"e9d76-OTHiP3Tm3/UUCzX6ouGIogTHNe0\"",
    "mtime": "2026-09-28T12:17:37.614Z",
    "size": 957814,
    "path": "../public/_nuxt/roma_2026_23.BQ_A61VZ.webp"
  },
  "/_nuxt/roma_2026_235.CMfqqm1Y.webp": {
    "type": "image/webp",
    "etag": "\"ec1fc-fb6729AabNE1rFc76lMBX8vlx1U\"",
    "mtime": "2026-09-28T12:17:37.614Z",
    "size": 967164,
    "path": "../public/_nuxt/roma_2026_235.CMfqqm1Y.webp"
  },
  "/_nuxt/roma_2026_266.DjdEli03.webp": {
    "type": "image/webp",
    "etag": "\"d7b62-oaNNjg5XYlW1x62Lgwb9SEb7ieM\"",
    "mtime": "2026-09-28T12:17:37.614Z",
    "size": 883554,
    "path": "../public/_nuxt/roma_2026_266.DjdEli03.webp"
  },
  "/_nuxt/roma_2026_272.DCK_2NOt.webp": {
    "type": "image/webp",
    "etag": "\"ff14c-ebQ/WW51FPWIfHOtotdfLhergQQ\"",
    "mtime": "2026-09-28T12:17:37.614Z",
    "size": 1044812,
    "path": "../public/_nuxt/roma_2026_272.DCK_2NOt.webp"
  },
  "/_nuxt/roma_2026_279.DeTN01NJ.webp": {
    "type": "image/webp",
    "etag": "\"d61c6-Vk56pgHngNGOvqeY189CQQph6yg\"",
    "mtime": "2026-09-28T12:17:37.614Z",
    "size": 876998,
    "path": "../public/_nuxt/roma_2026_279.DeTN01NJ.webp"
  },
  "/_nuxt/roma_2026_288.BJwV5P4E.webp": {
    "type": "image/webp",
    "etag": "\"c2fc4-9vHfsDp0twK8nQ/n/2Bmki1mj5w\"",
    "mtime": "2026-09-28T12:17:37.614Z",
    "size": 798660,
    "path": "../public/_nuxt/roma_2026_288.BJwV5P4E.webp"
  },
  "/_nuxt/roma_2026_291.Ch4juJAw.webp": {
    "type": "image/webp",
    "etag": "\"ea260-k6L9VZfC8+9T4W1b7SotfPjA6tA\"",
    "mtime": "2026-09-28T12:17:37.614Z",
    "size": 959072,
    "path": "../public/_nuxt/roma_2026_291.Ch4juJAw.webp"
  },
  "/_nuxt/roma_2026_297.C6LN4qFX.webp": {
    "type": "image/webp",
    "etag": "\"df80c-qdCEkiUHPTXmL7xudnloel+4uwg\"",
    "mtime": "2026-09-28T12:17:37.614Z",
    "size": 915468,
    "path": "../public/_nuxt/roma_2026_297.C6LN4qFX.webp"
  },
  "/_nuxt/roma_2026_298.DprIcLC4.webp": {
    "type": "image/webp",
    "etag": "\"e49a8-25GOS9NjOwPziJ7sV6GnQxrSG1Y\"",
    "mtime": "2026-09-28T12:17:37.614Z",
    "size": 936360,
    "path": "../public/_nuxt/roma_2026_298.DprIcLC4.webp"
  },
  "/_nuxt/roma_2026_290.BS1kCZPo.webp": {
    "type": "image/webp",
    "etag": "\"12c326-FyR0aa7v1rQ6S/5ILDetqR+lwCs\"",
    "mtime": "2026-09-28T12:17:37.894Z",
    "size": 1229606,
    "path": "../public/_nuxt/roma_2026_290.BS1kCZPo.webp"
  },
  "/_nuxt/roma_2026_313.CRNEluWa.webp": {
    "type": "image/webp",
    "etag": "\"ea360-CVW5fbH6+8SpeyxfhmnSYoMLhmY\"",
    "mtime": "2026-09-28T12:17:37.614Z",
    "size": 959328,
    "path": "../public/_nuxt/roma_2026_313.CRNEluWa.webp"
  },
  "/_nuxt/roma_2026_315.DaOUjldo.webp": {
    "type": "image/webp",
    "etag": "\"aedf2-og3ctDZFwySJB3aoMPJRk4RkMGE\"",
    "mtime": "2026-09-28T12:17:37.614Z",
    "size": 716274,
    "path": "../public/_nuxt/roma_2026_315.DaOUjldo.webp"
  },
  "/_nuxt/roma_2026_320.CbDLFc3w.webp": {
    "type": "image/webp",
    "etag": "\"c6720-KcI0yUFpLroA1sRLwJ43aH8KySc\"",
    "mtime": "2026-09-28T12:17:37.614Z",
    "size": 812832,
    "path": "../public/_nuxt/roma_2026_320.CbDLFc3w.webp"
  },
  "/_nuxt/roma_2026_321.B6p4qE2O.webp": {
    "type": "image/webp",
    "etag": "\"ce06e-9lSfxaO5XnI6Xv3d2nK6Hcjea+w\"",
    "mtime": "2026-09-28T12:17:37.614Z",
    "size": 843886,
    "path": "../public/_nuxt/roma_2026_321.B6p4qE2O.webp"
  },
  "/_nuxt/roma_2026_30.BD_CuaaH.webp": {
    "type": "image/webp",
    "etag": "\"10e08e-WMmYhkEApYmmu5/pKwFQhZuLEC8\"",
    "mtime": "2026-09-28T12:17:37.894Z",
    "size": 1106062,
    "path": "../public/_nuxt/roma_2026_30.BD_CuaaH.webp"
  },
  "/_nuxt/roma_2026_303.Fq_WbT2g.webp": {
    "type": "image/webp",
    "etag": "\"108174-uAjMxdH4EuKexsof0/6CmxqLRrw\"",
    "mtime": "2026-09-28T12:17:37.894Z",
    "size": 1081716,
    "path": "../public/_nuxt/roma_2026_303.Fq_WbT2g.webp"
  },
  "/_nuxt/roma_2026_31.Bsk4Lpyi.webp": {
    "type": "image/webp",
    "etag": "\"160378-oBOb/DTqQ0SzGqboRvOoTO3f7Lw\"",
    "mtime": "2026-09-28T12:17:37.894Z",
    "size": 1442680,
    "path": "../public/_nuxt/roma_2026_31.Bsk4Lpyi.webp"
  },
  "/_nuxt/roma_2026_322.1E49Pmje.webp": {
    "type": "image/webp",
    "etag": "\"9de60-k9q9nVjUwvityNnqE1tboJcRW8o\"",
    "mtime": "2026-09-28T12:17:37.614Z",
    "size": 646752,
    "path": "../public/_nuxt/roma_2026_322.1E49Pmje.webp"
  },
  "/_nuxt/roma_2026_329.DYt7lfyO.webp": {
    "type": "image/webp",
    "etag": "\"c4044-34fRXxC/OYpsETMGEJCK5HrrhJ4\"",
    "mtime": "2026-09-28T12:17:37.614Z",
    "size": 802884,
    "path": "../public/_nuxt/roma_2026_329.DYt7lfyO.webp"
  },
  "/_nuxt/roma_2026_64._nTdqetq.webp": {
    "type": "image/webp",
    "etag": "\"f6086-qbZx9qF3nTfb6IF27XCwAFiCLU0\"",
    "mtime": "2026-09-28T12:17:37.614Z",
    "size": 1007750,
    "path": "../public/_nuxt/roma_2026_64._nTdqetq.webp"
  },
  "/_nuxt/roma_2026_72.BRGmYTPv.webp": {
    "type": "image/webp",
    "etag": "\"ef19a-zDC2af4cT9rHfGka3bsuOo6qs4k\"",
    "mtime": "2026-09-28T12:17:37.614Z",
    "size": 979354,
    "path": "../public/_nuxt/roma_2026_72.BRGmYTPv.webp"
  },
  "/_nuxt/roma_2026_80.BH9gKYAB.webp": {
    "type": "image/webp",
    "etag": "\"c9682-Mqx25uNre2fEjlolScgqTREsW1M\"",
    "mtime": "2026-09-28T12:17:37.614Z",
    "size": 824962,
    "path": "../public/_nuxt/roma_2026_80.BH9gKYAB.webp"
  },
  "/_nuxt/roma_2026_33.GFVzvQnb.webp": {
    "type": "image/webp",
    "etag": "\"106696-60+8Vn4+yOKhtqNGeJ4ycLgvaEo\"",
    "mtime": "2026-09-28T12:17:37.894Z",
    "size": 1074838,
    "path": "../public/_nuxt/roma_2026_33.GFVzvQnb.webp"
  },
  "/_nuxt/roma_2026_82.CpwpqEY3.webp": {
    "type": "image/webp",
    "etag": "\"da4ac-/lMaD0RJQJ9fHCi13JIw2iYNoT0\"",
    "mtime": "2026-09-28T12:17:37.614Z",
    "size": 894124,
    "path": "../public/_nuxt/roma_2026_82.CpwpqEY3.webp"
  },
  "/_nuxt/roma_2026_36.BHbVEvUP.webp": {
    "type": "image/webp",
    "etag": "\"124d44-9lQGBQPERaPY+gntuFCfgCMs668\"",
    "mtime": "2026-09-28T12:17:37.894Z",
    "size": 1199428,
    "path": "../public/_nuxt/roma_2026_36.BHbVEvUP.webp"
  },
  "/_nuxt/roma_2026_70.uTEtTAxq.webp": {
    "type": "image/webp",
    "etag": "\"115bfc-BIdb+VoxwjGl6q0I9IdnNXBgIFA\"",
    "mtime": "2026-09-28T12:17:37.894Z",
    "size": 1137660,
    "path": "../public/_nuxt/roma_2026_70.uTEtTAxq.webp"
  },
  "/_nuxt/sfilata_nicolaci_160.vFT6QUtG.webp": {
    "type": "image/webp",
    "etag": "\"7665a-gyOGNOK2sAezZ3bEXL4Z7AFbDG8\"",
    "mtime": "2026-09-28T12:17:37.578Z",
    "size": 484954,
    "path": "../public/_nuxt/sfilata_nicolaci_160.vFT6QUtG.webp"
  },
  "/_nuxt/roma_2026_leica_13.Db8MPmQI.webp": {
    "type": "image/webp",
    "etag": "\"23da60-9spcCLAvzxf2j0otqMeev1rYkO0\"",
    "mtime": "2026-09-28T12:17:37.919Z",
    "size": 2349664,
    "path": "../public/_nuxt/roma_2026_leica_13.Db8MPmQI.webp"
  },
  "/_nuxt/roma_2026_leica_46.4o00CC1v.webp": {
    "type": "image/webp",
    "etag": "\"1dd1b2-Z4QqAuU42WiOx8xHuLro7hoTJ2g\"",
    "mtime": "2026-09-28T12:17:37.915Z",
    "size": 1954226,
    "path": "../public/_nuxt/roma_2026_leica_46.4o00CC1v.webp"
  },
  "/_nuxt/sfilata_nicolaci_120.Dlhf64ik.webp": {
    "type": "image/webp",
    "etag": "\"efed2-yxo6yWU6X4TZelyvvo3n3XCwPEA\"",
    "mtime": "2026-09-28T12:17:37.610Z",
    "size": 982738,
    "path": "../public/_nuxt/sfilata_nicolaci_120.Dlhf64ik.webp"
  },
  "/_nuxt/sfilata_nicolaci_190.x2wEMYQl.webp": {
    "type": "image/webp",
    "etag": "\"7f7a2-sihIYI48UEtXubN0AYASyFlfMyY\"",
    "mtime": "2026-09-28T12:17:37.579Z",
    "size": 522146,
    "path": "../public/_nuxt/sfilata_nicolaci_190.x2wEMYQl.webp"
  },
  "/_nuxt/sfilata_nicolaci_122.B2deuTkR.webp": {
    "type": "image/webp",
    "etag": "\"fb5de-HsIoyiZkEpvfo90DaPaW5AhtOQg\"",
    "mtime": "2026-09-28T12:17:37.610Z",
    "size": 1029598,
    "path": "../public/_nuxt/sfilata_nicolaci_122.B2deuTkR.webp"
  },
  "/_nuxt/sfilata_nicolaci_127.V5i4dRCg.webp": {
    "type": "image/webp",
    "etag": "\"9963c-kZbObSmnxdWfP17Zvz4hubW4q6M\"",
    "mtime": "2026-09-28T12:17:37.610Z",
    "size": 628284,
    "path": "../public/_nuxt/sfilata_nicolaci_127.V5i4dRCg.webp"
  },
  "/_nuxt/roma_2026_leica_17.2M_smFku.webp": {
    "type": "image/webp",
    "etag": "\"229382-Aqy6Mp9uT96FB9nakEvKIgbi09k\"",
    "mtime": "2026-09-28T12:17:37.919Z",
    "size": 2265986,
    "path": "../public/_nuxt/roma_2026_leica_17.2M_smFku.webp"
  },
  "/_nuxt/sfilata_nicolaci_128.BB52RsRg.webp": {
    "type": "image/webp",
    "etag": "\"a3f04-FagQrAN8uQnCYEpi0qjeEVbL/cY\"",
    "mtime": "2026-09-28T12:17:37.610Z",
    "size": 671492,
    "path": "../public/_nuxt/sfilata_nicolaci_128.BB52RsRg.webp"
  },
  "/_nuxt/sfilata_nicolaci_147.ClaPw8e1.webp": {
    "type": "image/webp",
    "etag": "\"ea9a6-ERSBMEGqlazJbgc2ZhaowJMu0yA\"",
    "mtime": "2026-09-28T12:17:37.610Z",
    "size": 960934,
    "path": "../public/_nuxt/sfilata_nicolaci_147.ClaPw8e1.webp"
  },
  "/_nuxt/roma_2026_leica_56.G-PvJM2T.webp": {
    "type": "image/webp",
    "etag": "\"1f6068-wP4OAip6tF72eB0j/H1XVHSMNW4\"",
    "mtime": "2026-09-28T12:17:37.915Z",
    "size": 2056296,
    "path": "../public/_nuxt/roma_2026_leica_56.G-PvJM2T.webp"
  },
  "/_nuxt/roma_2026_leica_45.DxM-iI1N.webp": {
    "type": "image/webp",
    "etag": "\"201458-71mhhHpmNFDTQHonKKLGXMWLsb8\"",
    "mtime": "2026-09-28T12:17:37.919Z",
    "size": 2102360,
    "path": "../public/_nuxt/roma_2026_leica_45.DxM-iI1N.webp"
  },
  "/_nuxt/roma_2026_leica_7.B85hvzs4.webp": {
    "type": "image/webp",
    "etag": "\"1fc5ca-E117FHxuXmPBADRjZc1DT4Au9xY\"",
    "mtime": "2026-09-28T12:17:37.916Z",
    "size": 2082250,
    "path": "../public/_nuxt/roma_2026_leica_7.B85hvzs4.webp"
  },
  "/_nuxt/roma_2026_leica_47.QaReoAWo.webp": {
    "type": "image/webp",
    "etag": "\"215aa2-09bZAIKhd6JrTSo3UQ9sACFRTr8\"",
    "mtime": "2026-09-28T12:17:37.919Z",
    "size": 2185890,
    "path": "../public/_nuxt/roma_2026_leica_47.QaReoAWo.webp"
  },
  "/_nuxt/sfilata_nicolaci_114.DOeqrRuu.webp": {
    "type": "image/webp",
    "etag": "\"144d54-xnrJhYeD0vuFfp4AkVriJo9Hp30\"",
    "mtime": "2026-09-28T12:17:37.897Z",
    "size": 1330516,
    "path": "../public/_nuxt/sfilata_nicolaci_114.DOeqrRuu.webp"
  },
  "/_nuxt/sfilata_nicolaci_186.BRwOJNGQ.webp": {
    "type": "image/webp",
    "etag": "\"da15a-qQlMtty6tXi6MN/Iyvsni3BrPHI\"",
    "mtime": "2026-09-28T12:17:37.610Z",
    "size": 893274,
    "path": "../public/_nuxt/sfilata_nicolaci_186.BRwOJNGQ.webp"
  },
  "/_nuxt/sfilata_nicolaci_189.B0wDFMlg.webp": {
    "type": "image/webp",
    "etag": "\"8b786-bCaQWrGX5ZJXVfxldTRGBOu/WNQ\"",
    "mtime": "2026-09-28T12:17:37.610Z",
    "size": 571270,
    "path": "../public/_nuxt/sfilata_nicolaci_189.B0wDFMlg.webp"
  },
  "/_nuxt/roma_2026_leica_81.bD9sasTt.webp": {
    "type": "image/webp",
    "etag": "\"1f63c8-bF2lX88o/15vAYE5HbZ6rh7m5gE\"",
    "mtime": "2026-09-28T12:17:37.916Z",
    "size": 2057160,
    "path": "../public/_nuxt/roma_2026_leica_81.bD9sasTt.webp"
  },
  "/_nuxt/sfilata_nicolaci_191.B_RVDZdq.webp": {
    "type": "image/webp",
    "etag": "\"93602-F/X3p8Fj+0QhF3ed+ocVXDnepY0\"",
    "mtime": "2026-09-28T12:17:37.610Z",
    "size": 603650,
    "path": "../public/_nuxt/sfilata_nicolaci_191.B_RVDZdq.webp"
  },
  "/_nuxt/RqwlF5h2.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"eb2-/hCbBr7m+aX3Zz5XCatmhUhxlDo\"",
    "mtime": "2026-09-28T12:17:37.596Z",
    "size": 3762,
    "path": "../public/_nuxt/RqwlF5h2.js"
  },
  "/_nuxt/sfilata_nicolaci_192._xxNZYFm.webp": {
    "type": "image/webp",
    "etag": "\"9418c-6V4GwE9wVI1Xa6JRukU/D+FBt5s\"",
    "mtime": "2026-09-28T12:17:37.610Z",
    "size": 606604,
    "path": "../public/_nuxt/sfilata_nicolaci_192._xxNZYFm.webp"
  },
  "/_nuxt/sfilata_nicolaci_194.DzQHdBeH.webp": {
    "type": "image/webp",
    "etag": "\"90012-oTrk9j/ecABn/ghgEI1RAI4FzsA\"",
    "mtime": "2026-09-28T12:17:37.610Z",
    "size": 589842,
    "path": "../public/_nuxt/sfilata_nicolaci_194.DzQHdBeH.webp"
  },
  "/_nuxt/roma_2026_leica_89.a4o9rv8S.webp": {
    "type": "image/webp",
    "etag": "\"1b5010-FNGrFJK8z+SeXAJboSs9Oe4n9as\"",
    "mtime": "2026-09-28T12:17:37.915Z",
    "size": 1789968,
    "path": "../public/_nuxt/roma_2026_leica_89.a4o9rv8S.webp"
  },
  "/_nuxt/roma_2026_leica_78.a1i2pvtn.webp": {
    "type": "image/webp",
    "etag": "\"21a28c-eSH79C3PjGOaqhuieokTrsIePb0\"",
    "mtime": "2026-09-28T12:17:37.919Z",
    "size": 2204300,
    "path": "../public/_nuxt/roma_2026_leica_78.a1i2pvtn.webp"
  },
  "/_nuxt/sfilata_nicolaci_213.CSW4Nj8f.webp": {
    "type": "image/webp",
    "etag": "\"cbd64-TdXcSuwhd/5aqJYvZmeHKsPIv6w\"",
    "mtime": "2026-09-28T12:17:37.610Z",
    "size": 834916,
    "path": "../public/_nuxt/sfilata_nicolaci_213.CSW4Nj8f.webp"
  },
  "/_nuxt/sfilata_nicolaci_232.BhHiRJqY.webp": {
    "type": "image/webp",
    "etag": "\"5ce84-aWsRpsocJ1/y05nNHhnKLyk2gtg\"",
    "mtime": "2026-09-28T12:17:37.579Z",
    "size": 380548,
    "path": "../public/_nuxt/sfilata_nicolaci_232.BhHiRJqY.webp"
  },
  "/_nuxt/SGmshPL_.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-4EKc3owXsEOazYmpRuMtLAeQ/sY\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 110,
    "path": "../public/_nuxt/SGmshPL_.js"
  },
  "/_nuxt/skHAF9YR.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-ynOe1nXZRNRFR/tTyOJt28Z8+K4\"",
    "mtime": "2026-09-28T12:17:37.603Z",
    "size": 110,
    "path": "../public/_nuxt/skHAF9YR.js"
  },
  "/_nuxt/sfilata_nicolaci_234.DtpYCZyY.webp": {
    "type": "image/webp",
    "etag": "\"a2230-Qkh48RaJZcIEP9mYbLm9Vu3C3HQ\"",
    "mtime": "2026-09-28T12:17:37.610Z",
    "size": 664112,
    "path": "../public/_nuxt/sfilata_nicolaci_234.DtpYCZyY.webp"
  },
  "/_nuxt/SRQZfVVm.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-8EET7QRpdZrSFMfKAyqzLjkKRNs\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 110,
    "path": "../public/_nuxt/SRQZfVVm.js"
  },
  "/_nuxt/sfilata_nicolaci_239.7GtJHO7M.webp": {
    "type": "image/webp",
    "etag": "\"ad39c-uZWk+ETv8ScWYfQOtat+RfeFPVU\"",
    "mtime": "2026-09-28T12:17:37.610Z",
    "size": 709532,
    "path": "../public/_nuxt/sfilata_nicolaci_239.7GtJHO7M.webp"
  },
  "/_nuxt/t1EJGAPI.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-GCMEzM2u4pBwQfZT7t0oiNVI0JA\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 114,
    "path": "../public/_nuxt/t1EJGAPI.js"
  },
  "/_nuxt/sfilata_nicolaci_246.Drm42JsH.webp": {
    "type": "image/webp",
    "etag": "\"b5944-OR/kI++/4safAAS7QJm18vPKiUo\"",
    "mtime": "2026-09-28T12:17:37.610Z",
    "size": 743748,
    "path": "../public/_nuxt/sfilata_nicolaci_246.Drm42JsH.webp"
  },
  "/_nuxt/sfilata_nicolaci_260.C_z1rVQt.webp": {
    "type": "image/webp",
    "etag": "\"a0608-X7XOBdc91u3YzUgcWDvd2Vh1QaE\"",
    "mtime": "2026-09-28T12:17:37.610Z",
    "size": 656904,
    "path": "../public/_nuxt/sfilata_nicolaci_260.C_z1rVQt.webp"
  },
  "/_nuxt/sfilata_nicolaci_276.DqCvLTLm.webp": {
    "type": "image/webp",
    "etag": "\"9eaea-BVAhou5TxbdTeWBBt8zACPoLGVU\"",
    "mtime": "2026-09-28T12:17:37.610Z",
    "size": 649962,
    "path": "../public/_nuxt/sfilata_nicolaci_276.DqCvLTLm.webp"
  },
  "/_nuxt/sfilata_nicolaci_274.BrbyPuq1.webp": {
    "type": "image/webp",
    "etag": "\"cc2d6-oIdmt8Cwisj6/wrBEiBOYmkuVdU\"",
    "mtime": "2026-09-28T12:17:37.610Z",
    "size": 836310,
    "path": "../public/_nuxt/sfilata_nicolaci_274.BrbyPuq1.webp"
  },
  "/_nuxt/sfilata_nicolaci_31.D4VkjCIl.webp": {
    "type": "image/webp",
    "etag": "\"a8f7a-09OkBMoqJW5KNOND/re2j0p91WY\"",
    "mtime": "2026-09-28T12:17:37.610Z",
    "size": 692090,
    "path": "../public/_nuxt/sfilata_nicolaci_31.D4VkjCIl.webp"
  },
  "/_nuxt/sfilata_nicolaci_40.BwHKhBTh.webp": {
    "type": "image/webp",
    "etag": "\"ab382-1qSftIY/Pdx84N/BfmfDosWtdZY\"",
    "mtime": "2026-09-28T12:17:37.611Z",
    "size": 701314,
    "path": "../public/_nuxt/sfilata_nicolaci_40.BwHKhBTh.webp"
  },
  "/_nuxt/sfilata_nicolaci_32.vL3Utiyu.webp": {
    "type": "image/webp",
    "etag": "\"b7900-esbaFOWRauPTn1hR9SkQfJMX/5I\"",
    "mtime": "2026-09-28T12:17:37.610Z",
    "size": 751872,
    "path": "../public/_nuxt/sfilata_nicolaci_32.vL3Utiyu.webp"
  },
  "/_nuxt/test_canon_c50_120.B5s9q6Fg.webp": {
    "type": "image/webp",
    "etag": "\"6cce2-OVkF14mhKH6UldnNw5sS4c7NU5g\"",
    "mtime": "2026-09-28T12:17:37.580Z",
    "size": 445666,
    "path": "../public/_nuxt/test_canon_c50_120.B5s9q6Fg.webp"
  },
  "/_nuxt/test_canon_c50_121.C6fNpklx.webp": {
    "type": "image/webp",
    "etag": "\"63ae0-ZCQjU14Xy26K7Rwuc+M7fyRRqXE\"",
    "mtime": "2026-09-28T12:17:37.580Z",
    "size": 408288,
    "path": "../public/_nuxt/test_canon_c50_121.C6fNpklx.webp"
  },
  "/_nuxt/test_canon_c50_130.COgFJ4mE.webp": {
    "type": "image/webp",
    "etag": "\"7b3e4-GKNE4bUP17MZIWrlhskxFrrzKJI\"",
    "mtime": "2026-09-28T12:17:37.580Z",
    "size": 504804,
    "path": "../public/_nuxt/test_canon_c50_130.COgFJ4mE.webp"
  },
  "/_nuxt/test_canon_c50_134.ow4TJxmN.webp": {
    "type": "image/webp",
    "etag": "\"7b316-TIHbDYiO7t97rXYYzh/qQPULpsE\"",
    "mtime": "2026-09-28T12:17:37.580Z",
    "size": 504598,
    "path": "../public/_nuxt/test_canon_c50_134.ow4TJxmN.webp"
  },
  "/_nuxt/test_canon_c50_01.C0ZsDuOk.webp": {
    "type": "image/webp",
    "etag": "\"d9a2e-E9NN9hWHpAqk7XLa4m7pBOLtpJw\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 891438,
    "path": "../public/_nuxt/test_canon_c50_01.C0ZsDuOk.webp"
  },
  "/_nuxt/test_canon_c50_113.DNshoH5y.webp": {
    "type": "image/webp",
    "etag": "\"c182e-mXC62CAO59SURnZvz/O4ZUew3/g\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 792622,
    "path": "../public/_nuxt/test_canon_c50_113.DNshoH5y.webp"
  },
  "/_nuxt/test_canon_c50_115.D9niYql2.webp": {
    "type": "image/webp",
    "etag": "\"ad01a-ihEfOCO1WAFzUzdvcLJo+xSOcmw\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 708634,
    "path": "../public/_nuxt/test_canon_c50_115.D9niYql2.webp"
  },
  "/_nuxt/test_canon_c50_118.DIwqilZY.webp": {
    "type": "image/webp",
    "etag": "\"85c60-R4+aCXR/UY9aKrV/ShJbrqDFEAU\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 547936,
    "path": "../public/_nuxt/test_canon_c50_118.DIwqilZY.webp"
  },
  "/_nuxt/test_canon_c50_126.qHKNGLZ7.webp": {
    "type": "image/webp",
    "etag": "\"80dc6-WNfopw7YlarzdPtenHgiv2P4fto\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 527814,
    "path": "../public/_nuxt/test_canon_c50_126.qHKNGLZ7.webp"
  },
  "/_nuxt/test_canon_c50_135.kRQo5jjZ.webp": {
    "type": "image/webp",
    "etag": "\"91400-TQ9bfCyrsDT/pQS06Vb+1BOKkK0\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 594944,
    "path": "../public/_nuxt/test_canon_c50_135.kRQo5jjZ.webp"
  },
  "/_nuxt/sfilata_nicolaci_242.x8sXiH8k.webp": {
    "type": "image/webp",
    "etag": "\"1cd212-6huVKx1xq0Qg3S1I4bamKayHXrg\"",
    "mtime": "2026-09-28T12:17:37.915Z",
    "size": 1888786,
    "path": "../public/_nuxt/sfilata_nicolaci_242.x8sXiH8k.webp"
  },
  "/_nuxt/test_canon_c50_22.YwAGJCHf.webp": {
    "type": "image/webp",
    "etag": "\"66bca-mett2a23x9ggLFkI8E3WUy0mDQU\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 420810,
    "path": "../public/_nuxt/test_canon_c50_22.YwAGJCHf.webp"
  },
  "/_nuxt/test_canon_c50_89.CCDxfWSk.webp": {
    "type": "image/webp",
    "etag": "\"59906-px8XU4FY7f3VJIl6owsFX1PPgiU\"",
    "mtime": "2026-09-28T12:17:37.580Z",
    "size": 366854,
    "path": "../public/_nuxt/test_canon_c50_89.CCDxfWSk.webp"
  },
  "/_nuxt/test_canon_c50_93.C5YUiFaW.webp": {
    "type": "image/webp",
    "etag": "\"7530a-JW/yNQVqPOj+6S7lNYyrgRixVoQ\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 480010,
    "path": "../public/_nuxt/test_canon_c50_93.C5YUiFaW.webp"
  },
  "/_nuxt/tnCY6ats.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-UrO46EZVwrAePHF851EnMFpT7hk\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 110,
    "path": "../public/_nuxt/tnCY6ats.js"
  },
  "/_nuxt/test_canon_c50_95.DjMXSu4C.webp": {
    "type": "image/webp",
    "etag": "\"7bfba-bPhHB+xNZ7dleFTdyLWwG4wBeN0\"",
    "mtime": "2026-09-28T12:17:37.581Z",
    "size": 507834,
    "path": "../public/_nuxt/test_canon_c50_95.DjMXSu4C.webp"
  },
  "/_nuxt/test_canon_c50_26.BXF7leY7.webp": {
    "type": "image/webp",
    "etag": "\"8f874-pcj/tIfDNN4Gz6zttKv0qznymG0\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 587892,
    "path": "../public/_nuxt/test_canon_c50_26.BXF7leY7.webp"
  },
  "/_nuxt/test_canon_c50_36.BNWm0OVV.webp": {
    "type": "image/webp",
    "etag": "\"809d2-Di5NsnMibQEGORdih/vhkmcZwtA\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 526802,
    "path": "../public/_nuxt/test_canon_c50_36.BNWm0OVV.webp"
  },
  "/_nuxt/test_canon_c50_37.71d8QbOy.webp": {
    "type": "image/webp",
    "etag": "\"91764-HLuoXLGMUhxvQVjhpVS5aKTDKPM\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 595812,
    "path": "../public/_nuxt/test_canon_c50_37.71d8QbOy.webp"
  },
  "/_nuxt/test_canon_c50_43.DOXFdBpp.webp": {
    "type": "image/webp",
    "etag": "\"85880-XHykGS5aMJEtIKzoJIFKKN6d1U0\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 546944,
    "path": "../public/_nuxt/test_canon_c50_43.DOXFdBpp.webp"
  },
  "/_nuxt/trxQv4_M.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-EaOP+2hJk5RJE26miPCQwkIsuGU\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 122,
    "path": "../public/_nuxt/trxQv4_M.js"
  },
  "/_nuxt/uLdwANPY.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-JVg4FeeLW8wth2tiYKkAKs6m0zs\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 119,
    "path": "../public/_nuxt/uLdwANPY.js"
  },
  "/_nuxt/unZs3mBk.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-HEDoxkYOZMGL4GvDrda6VEUfSHE\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/unZs3mBk.js"
  },
  "/_nuxt/test_canon_c50_76.DfXCWcyr.webp": {
    "type": "image/webp",
    "etag": "\"9229c-P7H5M6Zx0Ha6460TWd9xE9rMZYU\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 598684,
    "path": "../public/_nuxt/test_canon_c50_76.DfXCWcyr.webp"
  },
  "/_nuxt/test_canon_c50_60.CxHb1jwa.webp": {
    "type": "image/webp",
    "etag": "\"d4d24-SWWn/w6bqijE3tcicxDZ92KJSs8\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 871716,
    "path": "../public/_nuxt/test_canon_c50_60.CxHb1jwa.webp"
  },
  "/_nuxt/test_canon_c50_79.qgonCJSv.webp": {
    "type": "image/webp",
    "etag": "\"a23f6-JyhuHVBx81YlD2/eZQ+tJk4/V68\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 664566,
    "path": "../public/_nuxt/test_canon_c50_79.qgonCJSv.webp"
  },
  "/_nuxt/uS4mbH8B.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-NdVRRAMftIyjoonS/YSExad56Os\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 114,
    "path": "../public/_nuxt/uS4mbH8B.js"
  },
  "/_nuxt/test_canon_c50_46.BXb7U_V3.webp": {
    "type": "image/webp",
    "etag": "\"10e000-Z2nprXbdQX17ETUtM/yLgG18SAg\"",
    "mtime": "2026-09-28T12:17:37.894Z",
    "size": 1105920,
    "path": "../public/_nuxt/test_canon_c50_46.BXb7U_V3.webp"
  },
  "/_nuxt/VFXShootingDay-15.CovekTET.webp": {
    "type": "image/webp",
    "etag": "\"7970c-g+nA9U0HNXzb8hGi8q9BcFZM1zU\"",
    "mtime": "2026-09-28T12:17:37.583Z",
    "size": 497420,
    "path": "../public/_nuxt/VFXShootingDay-15.CovekTET.webp"
  },
  "/_nuxt/VFXShootingDay-11.BRjBu4Vp.webp": {
    "type": "image/webp",
    "etag": "\"d20cc-HzbKtuvIeuoG3yZVfUNtoUnzmR4\"",
    "mtime": "2026-09-28T12:17:37.614Z",
    "size": 860364,
    "path": "../public/_nuxt/VFXShootingDay-11.BRjBu4Vp.webp"
  },
  "/_nuxt/VFXShootingDay-12.DSxQv7oW.webp": {
    "type": "image/webp",
    "etag": "\"f20d0-+PclaFDjDG+aJ4PlyAvNxAPivoc\"",
    "mtime": "2026-09-28T12:17:37.614Z",
    "size": 991440,
    "path": "../public/_nuxt/VFXShootingDay-12.DSxQv7oW.webp"
  },
  "/_nuxt/VFXShootingDay-1.PjESjBGJ.webp": {
    "type": "image/webp",
    "etag": "\"15e5e8-QjU6Sow78cCCVkpKvT1KPjGO36w\"",
    "mtime": "2026-09-28T12:17:37.894Z",
    "size": 1435112,
    "path": "../public/_nuxt/VFXShootingDay-1.PjESjBGJ.webp"
  },
  "/_nuxt/VFXShootingDay-10.CvsNyrxI.webp": {
    "type": "image/webp",
    "etag": "\"110d24-3oOwZysr64EGDTX5XPDWH5hKfQY\"",
    "mtime": "2026-09-28T12:17:37.894Z",
    "size": 1117476,
    "path": "../public/_nuxt/VFXShootingDay-10.CvsNyrxI.webp"
  },
  "/_nuxt/VFXShootingDay-16.D_K85eNd.webp": {
    "type": "image/webp",
    "etag": "\"cc71c-JI0TTe5uSkLr95VgpLzKHQL4Dtk\"",
    "mtime": "2026-09-28T12:17:37.614Z",
    "size": 837404,
    "path": "../public/_nuxt/VFXShootingDay-16.D_K85eNd.webp"
  },
  "/_nuxt/VFXShootingDay-13.DOz3JTW2.webp": {
    "type": "image/webp",
    "etag": "\"11fd7e-9cqeIi+nNx0tOTGDGjibLpFkrBs\"",
    "mtime": "2026-09-28T12:17:37.894Z",
    "size": 1179006,
    "path": "../public/_nuxt/VFXShootingDay-13.DOz3JTW2.webp"
  },
  "/_nuxt/TutaRossa-Prep.DCFxjJrc.mp4": {
    "type": "video/mp4",
    "etag": "\"206ea8-xqesk2XMID5wxPnDchVrojQH+Uw\"",
    "mtime": "2026-09-28T12:17:37.919Z",
    "size": 2125480,
    "path": "../public/_nuxt/TutaRossa-Prep.DCFxjJrc.mp4"
  },
  "/_nuxt/VFXShootingDay-17.D07c8kaZ.webp": {
    "type": "image/webp",
    "etag": "\"12ac68-K52d3V9b4QjvalQNnc5TrY+y+tw\"",
    "mtime": "2026-09-28T12:17:37.894Z",
    "size": 1223784,
    "path": "../public/_nuxt/VFXShootingDay-17.D07c8kaZ.webp"
  },
  "/_nuxt/VFXShootingDay-18.k4sEr8Ys.webp": {
    "type": "image/webp",
    "etag": "\"c2a6e-CO3PFNMzo7RJZx4EOWpfEJfZABE\"",
    "mtime": "2026-09-28T12:17:37.614Z",
    "size": 797294,
    "path": "../public/_nuxt/VFXShootingDay-18.k4sEr8Ys.webp"
  },
  "/_nuxt/VFXShootingDay-19.RbbdSI5C.webp": {
    "type": "image/webp",
    "etag": "\"d1004-UUix6a7zzmHVsKxl9coXvw+bags\"",
    "mtime": "2026-09-28T12:17:37.614Z",
    "size": 856068,
    "path": "../public/_nuxt/VFXShootingDay-19.RbbdSI5C.webp"
  },
  "/_nuxt/VFXShootingDay-2.fyY2imTK.webp": {
    "type": "image/webp",
    "etag": "\"e4f0c-ZRRQfrqosFJY/xH13NDYWl8BvE0\"",
    "mtime": "2026-09-28T12:17:37.614Z",
    "size": 937740,
    "path": "../public/_nuxt/VFXShootingDay-2.fyY2imTK.webp"
  },
  "/_nuxt/VFXShootingDay-20.C6oD6UT8.webp": {
    "type": "image/webp",
    "etag": "\"d3caa-esuSEq/XbiWz11VLbSdHGzCYzic\"",
    "mtime": "2026-09-28T12:17:37.615Z",
    "size": 867498,
    "path": "../public/_nuxt/VFXShootingDay-20.C6oD6UT8.webp"
  },
  "/_nuxt/VFXShootingDay-21.BLfRmdUi.webp": {
    "type": "image/webp",
    "etag": "\"d5194-tJVWtYNf+wXrscZMFvfhxRwcDZs\"",
    "mtime": "2026-09-28T12:17:37.614Z",
    "size": 872852,
    "path": "../public/_nuxt/VFXShootingDay-21.BLfRmdUi.webp"
  },
  "/_nuxt/VFXShootingDay-22.CcRT2tYQ.webp": {
    "type": "image/webp",
    "etag": "\"c3b18-nK7+CRpcEl02eeRPj1ZGvJ6LrCw\"",
    "mtime": "2026-09-28T12:17:37.614Z",
    "size": 801560,
    "path": "../public/_nuxt/VFXShootingDay-22.CcRT2tYQ.webp"
  },
  "/_nuxt/VFXShootingDay-26.B0FgBgij.webp": {
    "type": "image/webp",
    "etag": "\"f4fa6-dWK4Jzubr24Tih7DP40zeHYicTc\"",
    "mtime": "2026-09-28T12:17:37.614Z",
    "size": 1003430,
    "path": "../public/_nuxt/VFXShootingDay-26.B0FgBgij.webp"
  },
  "/_nuxt/VFXShootingDay-25.CmZIBoy1.webp": {
    "type": "image/webp",
    "etag": "\"ed506-IP0bEFZvi8yZD/vvFeau10IliJI\"",
    "mtime": "2026-09-28T12:17:37.614Z",
    "size": 972038,
    "path": "../public/_nuxt/VFXShootingDay-25.CmZIBoy1.webp"
  },
  "/_nuxt/VFXShootingDay-27.Cv5eHU04.webp": {
    "type": "image/webp",
    "etag": "\"bd06c-pho62zOiZt1Rkyo0wHsMHXkF0Pg\"",
    "mtime": "2026-09-28T12:17:37.615Z",
    "size": 774252,
    "path": "../public/_nuxt/VFXShootingDay-27.Cv5eHU04.webp"
  },
  "/_nuxt/VFXShootingDay-23.Eh_3CiNc.webp": {
    "type": "image/webp",
    "etag": "\"11a106-7WdL7xOlbpWddhS8LwE2OrydaeA\"",
    "mtime": "2026-09-28T12:17:37.894Z",
    "size": 1155334,
    "path": "../public/_nuxt/VFXShootingDay-23.Eh_3CiNc.webp"
  },
  "/_nuxt/VFXShootingDay-30.C5TrwONA.webp": {
    "type": "image/webp",
    "etag": "\"d239a-Yl4iKi3oO7C6SOYB65HFCgy9Z9Y\"",
    "mtime": "2026-09-28T12:17:37.615Z",
    "size": 861082,
    "path": "../public/_nuxt/VFXShootingDay-30.C5TrwONA.webp"
  },
  "/_nuxt/VFXShootingDay-24.DzjMkhTS.webp": {
    "type": "image/webp",
    "etag": "\"12be24-ebhHas4odEkLXDnTjlGXEfu0cn0\"",
    "mtime": "2026-09-28T12:17:37.894Z",
    "size": 1228324,
    "path": "../public/_nuxt/VFXShootingDay-24.DzjMkhTS.webp"
  },
  "/_nuxt/VFXShootingDay-29.DTgDc45H.webp": {
    "type": "image/webp",
    "etag": "\"100898-OEJsx6xzASBMCltQT0JriJw3dNI\"",
    "mtime": "2026-09-28T12:17:37.894Z",
    "size": 1050776,
    "path": "../public/_nuxt/VFXShootingDay-29.DTgDc45H.webp"
  },
  "/_nuxt/VFXShootingDay-28.CEkfSUqf.webp": {
    "type": "image/webp",
    "etag": "\"144630-ly6EjeBziYFtVsVEQr3nsPqWHvo\"",
    "mtime": "2026-09-28T12:17:37.894Z",
    "size": 1328688,
    "path": "../public/_nuxt/VFXShootingDay-28.CEkfSUqf.webp"
  },
  "/_nuxt/VFXShootingDay-3.9YcJ1MkE.webp": {
    "type": "image/webp",
    "etag": "\"116080-+v9tnVvmZnQulwPrjTY7EtiBtw8\"",
    "mtime": "2026-09-28T12:17:37.894Z",
    "size": 1138816,
    "path": "../public/_nuxt/VFXShootingDay-3.9YcJ1MkE.webp"
  },
  "/_nuxt/VFXShootingDay-8.1kg-EQa_.webp": {
    "type": "image/webp",
    "etag": "\"b5096-5yX+0Yk29uSeILyAyEB1p3h1sek\"",
    "mtime": "2026-09-28T12:17:37.615Z",
    "size": 741526,
    "path": "../public/_nuxt/VFXShootingDay-8.1kg-EQa_.webp"
  },
  "/_nuxt/VFXShootingDay-4.9HEi4_Q2.webp": {
    "type": "image/webp",
    "etag": "\"17dd44-TzbMmLIl0vNfeauFTppE33ubQzI\"",
    "mtime": "2026-09-28T12:17:37.894Z",
    "size": 1563972,
    "path": "../public/_nuxt/VFXShootingDay-4.9HEi4_Q2.webp"
  },
  "/_nuxt/VFXShootingDay-9.COQvSK8L.webp": {
    "type": "image/webp",
    "etag": "\"c8814-6Lce9BRGhIZ2d/J7K8JQdAmJOVc\"",
    "mtime": "2026-09-28T12:17:37.615Z",
    "size": 821268,
    "path": "../public/_nuxt/VFXShootingDay-9.COQvSK8L.webp"
  },
  "/_nuxt/VFXShootingDay-5.WhFM-Q94.webp": {
    "type": "image/webp",
    "etag": "\"10041e-P3YMtC4qRCT+W7s1a11dmx/uJtY\"",
    "mtime": "2026-09-28T12:17:37.894Z",
    "size": 1049630,
    "path": "../public/_nuxt/VFXShootingDay-5.WhFM-Q94.webp"
  },
  "/_nuxt/VFXShootingDay-6.wLQ4xTAU.webp": {
    "type": "image/webp",
    "etag": "\"12c554-BQAkyiH3/cE9dW95f/mFY/2D3oM\"",
    "mtime": "2026-09-28T12:17:37.894Z",
    "size": 1230164,
    "path": "../public/_nuxt/VFXShootingDay-6.wLQ4xTAU.webp"
  },
  "/_nuxt/VFXShootingDay-7.C4CdfrwP.webp": {
    "type": "image/webp",
    "etag": "\"14d076-TOClymiNaQY6QipgRM7znU5tqmo\"",
    "mtime": "2026-09-28T12:17:37.895Z",
    "size": 1364086,
    "path": "../public/_nuxt/VFXShootingDay-7.C4CdfrwP.webp"
  },
  "/_nuxt/VYL1qCAl.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-JFX06rEdDN6aRviWBzn8rdQCL8w\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/VYL1qCAl.js"
  },
  "/_nuxt/W3vBmqWL.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-PyoCafQgYM8P+g/kRC47r27eMu8\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 107,
    "path": "../public/_nuxt/W3vBmqWL.js"
  },
  "/_nuxt/wpzhEJNW.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-xHiAY6oluEqeWl0SuaEtV9khddY\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 107,
    "path": "../public/_nuxt/wpzhEJNW.js"
  },
  "/_nuxt/wkXSq5ja.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-FdnoHCDXY6OsEfgD7Xjt6dA8blo\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/wkXSq5ja.js"
  },
  "/_nuxt/W5cUfp1x.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"73-xkyJ6wbxW/SO8utCsiZPkUtT6Pw\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 115,
    "path": "../public/_nuxt/W5cUfp1x.js"
  },
  "/_nuxt/xAp7PkRt.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6e-W+iqQ/IL6lFpAmGrrdoRFC6Hxd0\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 110,
    "path": "../public/_nuxt/xAp7PkRt.js"
  },
  "/_nuxt/VFX_03.DrPXr-KH.webp": {
    "type": "image/webp",
    "etag": "\"e42ec-TKrvjSAviaomKdH3yJhh5nxD0K8\"",
    "mtime": "2026-09-28T12:17:37.612Z",
    "size": 934636,
    "path": "../public/_nuxt/VFX_03.DrPXr-KH.webp"
  },
  "/_nuxt/VFX_02.Blh7y_ny.webp": {
    "type": "image/webp",
    "etag": "\"17799e-ldP5mF2Mu31n/lyJQ/p6mY8OAP4\"",
    "mtime": "2026-09-28T12:17:37.893Z",
    "size": 1538462,
    "path": "../public/_nuxt/VFX_02.Blh7y_ny.webp"
  },
  "/_nuxt/xlqri7Gr.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"78-fEKZttxPh6x2bmNGLce+ZdlFI54\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 120,
    "path": "../public/_nuxt/xlqri7Gr.js"
  },
  "/_nuxt/Xhyo1CEP.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-qEqoVGSdxP1yIGdOVO2lGPWGSD0\"",
    "mtime": "2026-09-28T12:17:37.599Z",
    "size": 114,
    "path": "../public/_nuxt/Xhyo1CEP.js"
  },
  "/_nuxt/WRcQZsIB.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-9fShm7/oplxtzVV7/a4KoTCuP/w\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 114,
    "path": "../public/_nuxt/WRcQZsIB.js"
  },
  "/_nuxt/VFX_01.Dfz1bpQ8.webp": {
    "type": "image/webp",
    "etag": "\"18713a-2mCdtqFDX3ni7LDjFJ4qGD/J1s0\"",
    "mtime": "2026-09-28T12:17:37.915Z",
    "size": 1601850,
    "path": "../public/_nuxt/VFX_01.Dfz1bpQ8.webp"
  },
  "/_nuxt/xpHY4uVU.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-CJ93YV/TAmhGUtSX1fWo+U7FK0w\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 114,
    "path": "../public/_nuxt/xpHY4uVU.js"
  },
  "/_nuxt/xQPhJAuQ.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"72-d75PH2lJ11bhqfDhOhvMusHQLcg\"",
    "mtime": "2026-09-28T12:17:37.601Z",
    "size": 114,
    "path": "../public/_nuxt/xQPhJAuQ.js"
  },
  "/_nuxt/XxC8ue6N.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"77-hs8lWV7JEIMz7rrSZRjrZnpiguA\"",
    "mtime": "2026-09-28T12:17:37.602Z",
    "size": 119,
    "path": "../public/_nuxt/XxC8ue6N.js"
  },
  "/_nuxt/xU6ZFJHL.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"74-7IKvqb2HM7Y9pez6QXf191PCNZU\"",
    "mtime": "2026-09-28T12:17:37.600Z",
    "size": 116,
    "path": "../public/_nuxt/xU6ZFJHL.js"
  },
  "/other_projects/Freudenberg-Renders/cover.webp": {
    "type": "image/webp",
    "etag": "\"6cb84-2Tjl9hRdZ1AbD51LSZGeMAhL3+4\"",
    "mtime": "2026-08-16T12:55:42.220Z",
    "size": 445316,
    "path": "../public/other_projects/Freudenberg-Renders/cover.webp"
  },
  "/_nuxt/y2GB0cWc.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"7a-5qlp7UpWvsxdOcZR+PGoFWMUro4\"",
    "mtime": "2026-09-28T12:17:37.597Z",
    "size": 122,
    "path": "../public/_nuxt/y2GB0cWc.js"
  },
  "/other_projects/Freudenberg-Renders/project.json": {
    "type": "application/json",
    "etag": "\"222-2FcSnieEyoL5/JeCQm6xH08Ll08\"",
    "mtime": "2026-08-16T12:55:42.251Z",
    "size": 546,
    "path": "../public/other_projects/Freudenberg-Renders/project.json"
  },
  "/projects/Fragile/project.json": {
    "type": "application/json",
    "etag": "\"399-6huJIzbBsG8sr1Ch1CBdzZmplxk\"",
    "mtime": "2026-05-04T18:43:23.275Z",
    "size": 921,
    "path": "../public/projects/Fragile/project.json"
  },
  "/projects/Cars/project.json": {
    "type": "application/json",
    "etag": "\"9c-BhHG4XAVGDrfGiAZ5Av+YHIIOoM\"",
    "mtime": "2026-08-16T15:12:31.477Z",
    "size": 156,
    "path": "../public/projects/Cars/project.json"
  },
  "/projects/Fragile/cover.jpg": {
    "type": "image/jpeg",
    "etag": "\"8df29-7BOY6jpgQSHNavDfldMtB7HttJA\"",
    "mtime": "2026-05-04T13:11:33.709Z",
    "size": 581417,
    "path": "../public/projects/Fragile/cover.jpg"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/project.json": {
    "type": "application/json",
    "etag": "\"5b-30Jg0ZiuWuHzqZVp+dveQrzhPRA\"",
    "mtime": "2026-05-26T18:11:28.391Z",
    "size": 91,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/project.json"
  },
  "/projects/Henosis/project.json": {
    "type": "application/json",
    "etag": "\"242-t265NxKT4TyaLg+kj4pie3+e98Y\"",
    "mtime": "2026-08-16T12:55:42.277Z",
    "size": 578,
    "path": "../public/projects/Henosis/project.json"
  },
  "/projects/Henosis/cover.webp": {
    "type": "image/webp",
    "etag": "\"62fbe-qKEx0FHCdGHUYW744vJTl6+mubM\"",
    "mtime": "2026-08-16T12:55:42.253Z",
    "size": 405438,
    "path": "../public/projects/Henosis/cover.webp"
  },
  "/_nuxt/Z1TQSQi8.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"6b-iGG/ZZy+xp6F7GKklIqbEZu9kW0\"",
    "mtime": "2026-09-28T12:17:37.608Z",
    "size": 107,
    "path": "../public/_nuxt/Z1TQSQi8.js"
  },
  "/projects/Cars/cover.webp": {
    "type": "image/webp",
    "etag": "\"e3808-JPtxyAgE2a6tu4179iFyp/ze2O8\"",
    "mtime": "2026-05-29T07:41:52.222Z",
    "size": 931848,
    "path": "../public/projects/Cars/cover.webp"
  },
  "/_nuxt/zQQvPMuM.js": {
    "type": "text/javascript; charset=utf-8",
    "etag": "\"71-jalXnvW/gD5QfqmN5NDKvzE5CGE\"",
    "mtime": "2026-09-28T12:17:37.598Z",
    "size": 113,
    "path": "../public/_nuxt/zQQvPMuM.js"
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
  "/projects/Fragile/cover.mp4": {
    "type": "video/mp4",
    "etag": "\"1664b4-XUvsbLH+9TKo2Iil5Oz96EDmHeM\"",
    "mtime": "2026-05-04T21:30:20.513Z",
    "size": 1467572,
    "path": "../public/projects/Fragile/cover.mp4"
  },
  "/projects/L'Autin-Logo-Animation/project.json": {
    "type": "application/json",
    "etag": "\"1ba-vrbqLYd++IutOM3Ifi2VP+rwwcU\"",
    "mtime": "2026-05-03T22:36:41.692Z",
    "size": 442,
    "path": "../public/projects/L'Autin-Logo-Animation/project.json"
  },
  "/projects/Lauree/convert_webp.bat": {
    "type": "application/x-msdownload",
    "etag": "\"5b-gQhysR4s9RpFh0Np/onnCQFCuY8\"",
    "mtime": "2026-09-28T11:47:00.272Z",
    "size": 91,
    "path": "../public/projects/Lauree/convert_webp.bat"
  },
  "/projects/Lauree/project.json": {
    "type": "application/json",
    "etag": "\"71-YopEIokNK42olfKuS4etx3/MaUM\"",
    "mtime": "2026-09-28T11:50:01.101Z",
    "size": 113,
    "path": "../public/projects/Lauree/project.json"
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
    "etag": "\"31a-SSr/cAzSMWIVt+JwI/S1Zbo3+/w\"",
    "mtime": "2026-09-03T11:47:54.159Z",
    "size": 794,
    "path": "../public/projects/Macello-Castle-VFX/project.json"
  },
  "/projects/macello-horse-bts/project.json": {
    "type": "application/json",
    "etag": "\"1de-5NnPE6B/AhdC9Q1T3dx+fbf7SxQ\"",
    "mtime": "2026-05-03T22:36:41.700Z",
    "size": 478,
    "path": "../public/projects/macello-horse-bts/project.json"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/cover.webp": {
    "type": "image/webp",
    "etag": "\"1dc830-I9bRpmxeCB3Ce5rbS5h3yqfMirI\"",
    "mtime": "2026-05-26T18:10:43.017Z",
    "size": 1951792,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/cover.webp"
  },
  "/projects/Making_of_pasta/project.json": {
    "type": "application/json",
    "etag": "\"201-JPyYY9J/SU+vNAOObBBJQFvL48A\"",
    "mtime": "2026-08-16T12:55:42.310Z",
    "size": 513,
    "path": "../public/projects/Making_of_pasta/project.json"
  },
  "/projects/Making_of_pasta/cover.webp": {
    "type": "image/webp",
    "etag": "\"57f86-VyzxBN6E4VCfCdn3njraEiY4CDw\"",
    "mtime": "2026-08-16T12:55:42.279Z",
    "size": 360326,
    "path": "../public/projects/Making_of_pasta/cover.webp"
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
  "/projects/macello-horse-bts/cover.webp": {
    "type": "image/webp",
    "etag": "\"12fdc8-8jt/aFAMc7tOULQGr0RE1+AC/KE\"",
    "mtime": "2026-05-03T22:36:41.697Z",
    "size": 1244616,
    "path": "../public/projects/macello-horse-bts/cover.webp"
  },
  "/projects/Martina_Pace/cover.jpg": {
    "type": "image/jpeg",
    "etag": "\"4b437-jloMA3Q2//01aAywFK0Z6BKgElA\"",
    "mtime": "2026-05-04T13:01:34.419Z",
    "size": 308279,
    "path": "../public/projects/Martina_Pace/cover.jpg"
  },
  "/projects/My-Lamination/project.json": {
    "type": "application/json",
    "etag": "\"350-wwhQM3DrqV05NZ9KCSHl6MYrDiQ\"",
    "mtime": "2026-05-29T07:03:59.601Z",
    "size": 848,
    "path": "../public/projects/My-Lamination/project.json"
  },
  "/projects/OlioRoi_Rocks_Edit&SoundDesign/convert_webp.bat": {
    "type": "application/x-msdownload",
    "etag": "\"5b-UEclbuN74Tzo+wAuI95XevLFepI\"",
    "mtime": "2026-08-30T14:25:44.585Z",
    "size": 91,
    "path": "../public/projects/OlioRoi_Rocks_Edit&SoundDesign/convert_webp.bat"
  },
  "/projects/OlioRoi_Rocks_Edit&SoundDesign/cover.webp": {
    "type": "image/webp",
    "etag": "\"586d4-P2wgxrY5cFebB/9iSS53TobAmks\"",
    "mtime": "2026-08-30T14:25:48.776Z",
    "size": 362196,
    "path": "../public/projects/OlioRoi_Rocks_Edit&SoundDesign/cover.webp"
  },
  "/projects/OlioRoi_Rocks_Edit&SoundDesign/project.json": {
    "type": "application/json",
    "etag": "\"1e2-F5ZKHeWM2UUmk8Ab+/7wJCdf6ms\"",
    "mtime": "2026-08-30T14:31:34.842Z",
    "size": 482,
    "path": "../public/projects/OlioRoi_Rocks_Edit&SoundDesign/project.json"
  },
  "/projects/OrtoDiSantaChiara/cover.webp": {
    "type": "image/webp",
    "etag": "\"3ee22-/OlANjjdc6lRPd9an7KyiBV+QVY\"",
    "mtime": "2026-08-16T15:25:02.454Z",
    "size": 257570,
    "path": "../public/projects/OrtoDiSantaChiara/cover.webp"
  },
  "/projects/OrtoDiSantaChiara/project.json": {
    "type": "application/json",
    "etag": "\"227-TphFJJWQvzTd0f/F/EbjFdPU3F4\"",
    "mtime": "2026-08-16T15:37:33.043Z",
    "size": 551,
    "path": "../public/projects/OrtoDiSantaChiara/project.json"
  },
  "/projects/My-Lamination/cover.webp": {
    "type": "image/webp",
    "etag": "\"b06ec-nJSYLHRG2ghi0hwKJElW8ODj3GI\"",
    "mtime": "2026-05-29T07:27:42.288Z",
    "size": 722668,
    "path": "../public/projects/My-Lamination/cover.webp"
  },
  "/_nuxt/Vialattea-PrepAction.BBrdMAYS.mp4": {
    "type": "video/mp4",
    "etag": "\"502bb2-3GpwEu0/7zSu2Y1unZm///GKVig\"",
    "mtime": "2026-09-28T12:17:37.922Z",
    "size": 5254066,
    "path": "../public/_nuxt/Vialattea-PrepAction.BBrdMAYS.mp4"
  },
  "/projects/Rigolizia-Mon-Amour/project.json": {
    "type": "application/json",
    "etag": "\"2a1-OodT/vxysqznrW6rwO6V7Vde7H8\"",
    "mtime": "2026-05-04T20:28:27.243Z",
    "size": 673,
    "path": "../public/projects/Rigolizia-Mon-Amour/project.json"
  },
  "/projects/OrtoDiSantaChiaraPhotos/cover.webp": {
    "type": "image/webp",
    "etag": "\"5ecf6-0nioeVVGmT/AjmO2CoN5IoESi1I\"",
    "mtime": "2026-08-30T13:49:27.749Z",
    "size": 388342,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/cover.webp"
  },
  "/projects/Rigolizia-Mon-Amour/cover.webp": {
    "type": "image/webp",
    "etag": "\"bff88-kyi2i7/3CLJQ5qTZCmZMVPRANdg\"",
    "mtime": "2026-05-05T21:45:44.073Z",
    "size": 786312,
    "path": "../public/projects/Rigolizia-Mon-Amour/cover.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/project.json": {
    "type": "application/json",
    "etag": "\"175-04sUmI9l//dYU5xCBF6A8GCLTlg\"",
    "mtime": "2026-08-30T13:51:01.439Z",
    "size": 373,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/project.json"
  },
  "/projects/Roma/project.json": {
    "type": "application/json",
    "etag": "\"46-A8jmtRlUAbjcrBhhKvzymy9cXQ4\"",
    "mtime": "2026-05-25T17:39:23.599Z",
    "size": 70,
    "path": "../public/projects/Roma/project.json"
  },
  "/projects/Unbow-Logo-Animation/project.json": {
    "type": "application/json",
    "etag": "\"1cb-2BmKz3veJEG7yStHHvTfFv9FjrM\"",
    "mtime": "2026-05-03T22:36:41.697Z",
    "size": 459,
    "path": "../public/projects/Unbow-Logo-Animation/project.json"
  },
  "/projects/Roma/cover.webp": {
    "type": "image/webp",
    "etag": "\"e28ba-QqcMl/zKVUrUIUFjXw0CffZC+NE\"",
    "mtime": "2026-05-29T07:37:16.227Z",
    "size": 927930,
    "path": "../public/projects/Roma/cover.webp"
  },
  "/projects/My-Lamination/cover.jpg": {
    "type": "image/jpeg",
    "etag": "\"256c0a-iAfYBSRnU88cJDVzp6WsuWh7ngQ\"",
    "mtime": "2026-05-29T07:27:12.890Z",
    "size": 2452490,
    "path": "../public/projects/My-Lamination/cover.jpg"
  },
  "/other_projects/Freudenberg-Renders/images/493908234_section.webp": {
    "type": "image/webp",
    "etag": "\"1d8c6-uyo64yVMIUO60W/eNNLNrjr7LkE\"",
    "mtime": "2026-08-16T12:55:42.231Z",
    "size": 121030,
    "path": "../public/other_projects/Freudenberg-Renders/images/493908234_section.webp"
  },
  "/projects/Rigolizia-Mon-Amour/cover.mp4": {
    "type": "video/mp4",
    "etag": "\"194af1-Yb6hWIGQxrJUy5+kuQqeMykJftw\"",
    "mtime": "2026-05-03T22:42:29.388Z",
    "size": 1657585,
    "path": "../public/projects/Rigolizia-Mon-Amour/cover.mp4"
  },
  "/other_projects/Freudenberg-Renders/images/496368201.webp": {
    "type": "image/webp",
    "etag": "\"2aeda-eI7oOUg01Te0EDZhSjNxkvMkdBw\"",
    "mtime": "2026-08-16T12:55:42.235Z",
    "size": 175834,
    "path": "../public/other_projects/Freudenberg-Renders/images/496368201.webp"
  },
  "/other_projects/Freudenberg-Renders/images/49347758_section.webp": {
    "type": "image/webp",
    "etag": "\"cd968-yE8lLgixleS3m8Sk0A16a3Ii9pg\"",
    "mtime": "2026-08-16T12:55:42.229Z",
    "size": 842088,
    "path": "../public/other_projects/Freudenberg-Renders/images/49347758_section.webp"
  },
  "/other_projects/Freudenberg-Renders/images/a3_section.webp": {
    "type": "image/webp",
    "etag": "\"5a54c-9YvynffO5zzRlV4Lr9xqE6YrLak\"",
    "mtime": "2026-08-16T12:55:42.244Z",
    "size": 369996,
    "path": "../public/other_projects/Freudenberg-Renders/images/a3_section.webp"
  },
  "/other_projects/Freudenberg-Renders/images/Aover.webp": {
    "type": "image/webp",
    "etag": "\"6cb84-2Tjl9hRdZ1AbD51LSZGeMAhL3+4\"",
    "mtime": "2026-08-16T12:55:42.237Z",
    "size": 445316,
    "path": "../public/other_projects/Freudenberg-Renders/images/Aover.webp"
  },
  "/other_projects/Freudenberg-Renders/images/49390834_section.webp": {
    "type": "image/webp",
    "etag": "\"b7cfc-Zt6F8ieI+I1fLBVV2y/qUp5dIfc\"",
    "mtime": "2026-08-16T12:55:42.234Z",
    "size": 752892,
    "path": "../public/other_projects/Freudenberg-Renders/images/49390834_section.webp"
  },
  "/other_projects/Freudenberg-Renders/images/49347758.webp": {
    "type": "image/webp",
    "etag": "\"12f182-TAIqHqqiVNA/56XxkLmL7ni+lks\"",
    "mtime": "2026-08-16T12:55:42.226Z",
    "size": 1241474,
    "path": "../public/other_projects/Freudenberg-Renders/images/49347758.webp"
  },
  "/other_projects/Freudenberg-Renders/images/guarn1.webp": {
    "type": "image/webp",
    "etag": "\"de318-q7gZN0afhCTKlj29DPQl1B/GtEA\"",
    "mtime": "2026-08-16T12:55:42.248Z",
    "size": 910104,
    "path": "../public/other_projects/Freudenberg-Renders/images/guarn1.webp"
  },
  "/other_projects/Freudenberg-Renders/images/guarn1_section.webp": {
    "type": "image/webp",
    "etag": "\"93d74-K1ziaPHSpJlsL9tXuCUOmHA25lE\"",
    "mtime": "2026-08-16T12:55:42.251Z",
    "size": 605556,
    "path": "../public/other_projects/Freudenberg-Renders/images/guarn1_section.webp"
  },
  "/other_projects/Freudenberg-Renders/images/a2.webp": {
    "type": "image/webp",
    "etag": "\"10a220-KA4RnqrN6Lub8YPaz3YVr+Q2E64\"",
    "mtime": "2026-08-16T12:55:42.242Z",
    "size": 1090080,
    "path": "../public/other_projects/Freudenberg-Renders/images/a2.webp"
  },
  "/projects/Fragile/images/fragile_1.webp": {
    "type": "image/webp",
    "etag": "\"b5e40-UkPw0Y2MazfiX8sdVjz6Al0PuFs\"",
    "mtime": "2026-05-05T18:06:40.291Z",
    "size": 745024,
    "path": "../public/projects/Fragile/images/fragile_1.webp"
  },
  "/projects/Fragile/images/fragile_11.webp": {
    "type": "image/webp",
    "etag": "\"c1456-Jlw5sIpP4trYKHnznF3x2WsdB6k\"",
    "mtime": "2026-05-05T18:06:43.477Z",
    "size": 791638,
    "path": "../public/projects/Fragile/images/fragile_11.webp"
  },
  "/projects/Fragile/images/fragile_10.webp": {
    "type": "image/webp",
    "etag": "\"eda18-ug57Bvemf6U2pIW5rb2wIT3JVuM\"",
    "mtime": "2026-05-05T18:06:43.161Z",
    "size": 973336,
    "path": "../public/projects/Fragile/images/fragile_10.webp"
  },
  "/projects/Fragile/images/fragile_12.webp": {
    "type": "image/webp",
    "etag": "\"c9968-lPEfzNmS1Yy8bLiB2tMuYDikv0g\"",
    "mtime": "2026-05-05T18:06:43.789Z",
    "size": 825704,
    "path": "../public/projects/Fragile/images/fragile_12.webp"
  },
  "/projects/Merlo-e-Worker-ADVs/cover.mp4": {
    "type": "video/mp4",
    "etag": "\"469029-yQNV8SO8FMYCaYrzeAt+0VSexcA\"",
    "mtime": "2026-05-03T22:42:29.388Z",
    "size": 4624425,
    "path": "../public/projects/Merlo-e-Worker-ADVs/cover.mp4"
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
  "/projects/Fragile/images/fragile_16.webp": {
    "type": "image/webp",
    "etag": "\"bcdee-10wp+qJSWIfztBQSKyxwCdn4yic\"",
    "mtime": "2026-05-05T18:06:45.026Z",
    "size": 773614,
    "path": "../public/projects/Fragile/images/fragile_16.webp"
  },
  "/projects/Fragile/images/fragile_17.webp": {
    "type": "image/webp",
    "etag": "\"bee9c-7qRS1spflnNlz0dU165+hd/xf1A\"",
    "mtime": "2026-05-05T18:06:45.334Z",
    "size": 781980,
    "path": "../public/projects/Fragile/images/fragile_17.webp"
  },
  "/projects/Unbow-Logo-Animation/cover.gif": {
    "type": "image/gif",
    "etag": "\"2c2109-ut9h0RcqfIxm6v7cKjFTP8MzLiY\"",
    "mtime": "2026-05-03T22:36:41.697Z",
    "size": 2892041,
    "path": "../public/projects/Unbow-Logo-Animation/cover.gif"
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
  "/projects/Fragile/images/fragile_20.webp": {
    "type": "image/webp",
    "etag": "\"90b98-ENf6Yvjj8DJ/S8LG/nqrqLe106k\"",
    "mtime": "2026-05-05T18:06:46.223Z",
    "size": 592792,
    "path": "../public/projects/Fragile/images/fragile_20.webp"
  },
  "/projects/Fragile/images/fragile_2.webp": {
    "type": "image/webp",
    "etag": "\"dca14-YewP70GA8J2D6Php69LuwGbQUd0\"",
    "mtime": "2026-05-05T18:06:40.645Z",
    "size": 903700,
    "path": "../public/projects/Fragile/images/fragile_2.webp"
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
  "/projects/Fragile/images/fragile_5.webp": {
    "type": "image/webp",
    "etag": "\"ce2ba-eLyPezuxyevuUubr+UEKlPuiOfU\"",
    "mtime": "2026-05-05T18:06:41.597Z",
    "size": 844474,
    "path": "../public/projects/Fragile/images/fragile_5.webp"
  },
  "/projects/HeySport-Reels/cover.mp4": {
    "type": "video/mp4",
    "etag": "\"7cccb3-18JAFkajcM17yY0lKAibwYGg3KA\"",
    "mtime": "2026-05-03T22:42:29.387Z",
    "size": 8178867,
    "path": "../public/projects/HeySport-Reels/cover.mp4"
  },
  "/projects/L'Autin-Logo-Animation/cover.mp4": {
    "type": "video/mp4",
    "etag": "\"7e5935-2oH85kWP9kUijzTwxOO499ZvtLM\"",
    "mtime": "2026-05-03T22:42:29.388Z",
    "size": 8280373,
    "path": "../public/projects/L'Autin-Logo-Animation/cover.mp4"
  },
  "/projects/Fragile/images/fragile_6.webp": {
    "type": "image/webp",
    "etag": "\"c2db6-9uR4B6RqqANaXzRSWI5VeYme3iI\"",
    "mtime": "2026-05-05T18:06:41.919Z",
    "size": 798134,
    "path": "../public/projects/Fragile/images/fragile_6.webp"
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
  "/projects/Cars/images/02_03.webp": {
    "type": "image/webp",
    "etag": "\"762c6-SnXNZX0xmFIddCUQ8+OJWCa75Yo\"",
    "mtime": "2026-05-05T19:34:15.402Z",
    "size": 484038,
    "path": "../public/projects/Cars/images/02_03.webp"
  },
  "/projects/Cars/images/02_020.webp": {
    "type": "image/webp",
    "etag": "\"b2d88-hjOCm4h7XCQZTljyJPsRjDxd8y0\"",
    "mtime": "2026-05-05T19:34:15.383Z",
    "size": 732552,
    "path": "../public/projects/Cars/images/02_020.webp"
  },
  "/projects/Cars/images/CAR7.webp": {
    "type": "image/webp",
    "etag": "\"69338-ND42OkRkYFIirLw4Y5ayu5zFWWI\"",
    "mtime": "2026-05-05T19:34:15.460Z",
    "size": 430904,
    "path": "../public/projects/Cars/images/CAR7.webp"
  },
  "/projects/Cars/images/PANA9339.webp": {
    "type": "image/webp",
    "etag": "\"36858-PFx93h4yEZD3FY4ucbXyMqwR+YA\"",
    "mtime": "2026-05-05T19:34:15.464Z",
    "size": 223320,
    "path": "../public/projects/Cars/images/PANA9339.webp"
  },
  "/projects/Cars/images/02_021.webp": {
    "type": "image/webp",
    "etag": "\"f76ba-pudWbTKN117ATKvqIsPG35otg8s\"",
    "mtime": "2026-05-05T19:34:15.396Z",
    "size": 1013434,
    "path": "../public/projects/Cars/images/02_021.webp"
  },
  "/projects/Cars/images/PANA9342.webp": {
    "type": "image/webp",
    "etag": "\"24f5c-GhOTYIjWru0QU7BJ8iBS+T13Ti0\"",
    "mtime": "2026-05-05T19:34:15.471Z",
    "size": 151388,
    "path": "../public/projects/Cars/images/PANA9342.webp"
  },
  "/projects/Cars/images/02_01.webp": {
    "type": "image/webp",
    "etag": "\"16c9fa-q+HrLy/Q2RIaDV1BQebItuFcuqM\"",
    "mtime": "2026-05-05T19:34:15.360Z",
    "size": 1493498,
    "path": "../public/projects/Cars/images/02_01.webp"
  },
  "/projects/Cars/images/CAR1.webp": {
    "type": "image/webp",
    "etag": "\"98c4a-xjLnLoJSThu5Fh2U4ODy+vCryZY\"",
    "mtime": "2026-05-05T19:34:15.443Z",
    "size": 625738,
    "path": "../public/projects/Cars/images/CAR1.webp"
  },
  "/projects/Cars/images/02_06.webp": {
    "type": "image/webp",
    "etag": "\"deabc-zbeXmwtpwWbRVHtAPfRl+WBZ7XI\"",
    "mtime": "2026-05-05T19:34:15.433Z",
    "size": 912060,
    "path": "../public/projects/Cars/images/02_06.webp"
  },
  "/projects/Cars/images/CAR11.webp": {
    "type": "image/webp",
    "etag": "\"fd6ac-LF9e40X8/r1XU6MTVnktGF2pDt4\"",
    "mtime": "2026-05-05T19:34:15.454Z",
    "size": 1037996,
    "path": "../public/projects/Cars/images/CAR11.webp"
  },
  "/projects/Cars/images/PANA9347.webp": {
    "type": "image/webp",
    "etag": "\"32b22-abPIR6H/JmVwtyEP6NWMRb3hHTo\"",
    "mtime": "2026-05-05T19:34:15.477Z",
    "size": 207650,
    "path": "../public/projects/Cars/images/PANA9347.webp"
  },
  "/projects/Cars/images/PANA9348.webp": {
    "type": "image/webp",
    "etag": "\"6f35e-mmXRkiWKu2/sandPhhsIO+MthEk\"",
    "mtime": "2026-05-05T19:34:15.484Z",
    "size": 455518,
    "path": "../public/projects/Cars/images/PANA9348.webp"
  },
  "/projects/Cars/images/PANA9392.webp": {
    "type": "image/webp",
    "etag": "\"54bda-eCBCSEH9Eyu8QO9ewMuHu1Hghhc\"",
    "mtime": "2026-05-05T19:34:15.669Z",
    "size": 347098,
    "path": "../public/projects/Cars/images/PANA9392.webp"
  },
  "/projects/Cars/images/02_04.webp": {
    "type": "image/webp",
    "etag": "\"1036a4-kfI6p0NDgWLNgtV2QKDdXQNUziE\"",
    "mtime": "2026-05-05T19:34:15.414Z",
    "size": 1062564,
    "path": "../public/projects/Cars/images/02_04.webp"
  },
  "/projects/Cars/images/02_05.webp": {
    "type": "image/webp",
    "etag": "\"100362-VH5l5OJBQFDoiVIPKtklirNgFc8\"",
    "mtime": "2026-05-05T19:34:15.425Z",
    "size": 1049442,
    "path": "../public/projects/Cars/images/02_05.webp"
  },
  "/projects/Cars/images/02_02.webp": {
    "type": "image/webp",
    "etag": "\"184bcc-H87O+loBNIoJJiWnBZUxMGR+xGA\"",
    "mtime": "2026-05-05T19:34:15.375Z",
    "size": 1592268,
    "path": "../public/projects/Cars/images/02_02.webp"
  },
  "/projects/Cars/images/PANA9395.webp": {
    "type": "image/webp",
    "etag": "\"2fc90-Ypzjx7PrOK7QXfG60HEjyN83MYI\"",
    "mtime": "2026-05-05T19:34:15.676Z",
    "size": 195728,
    "path": "../public/projects/Cars/images/PANA9395.webp"
  },
  "/projects/Cars/images/PANA9397.webp": {
    "type": "image/webp",
    "etag": "\"44022-bGK5rATGWws4+dKSjabIpgBRrIE\"",
    "mtime": "2026-05-05T19:34:15.681Z",
    "size": 278562,
    "path": "../public/projects/Cars/images/PANA9397.webp"
  },
  "/projects/Cars/images/PANA9401.webp": {
    "type": "image/webp",
    "etag": "\"4fb84-NGaAO3V9OrwMY56xjoLB1MKYNJY\"",
    "mtime": "2026-05-05T19:34:15.687Z",
    "size": 326532,
    "path": "../public/projects/Cars/images/PANA9401.webp"
  },
  "/projects/Cars/images/PANA9403.webp": {
    "type": "image/webp",
    "etag": "\"6610c-OtHDksgp37lmIVi2TlgADrjZOQ8\"",
    "mtime": "2026-05-05T19:34:15.694Z",
    "size": 418060,
    "path": "../public/projects/Cars/images/PANA9403.webp"
  },
  "/projects/Cars/images/PANA9405.webp": {
    "type": "image/webp",
    "etag": "\"b78ca-BCAnQDc578V7xKfQyO93YCdkiXU\"",
    "mtime": "2026-05-05T19:34:15.704Z",
    "size": 751818,
    "path": "../public/projects/Cars/images/PANA9405.webp"
  },
  "/projects/Cars/images/PANA9412.webp": {
    "type": "image/webp",
    "etag": "\"37d42-QFUk9zSoDDzcqX/9lgduJeLSZR0\"",
    "mtime": "2026-05-05T19:34:15.727Z",
    "size": 228674,
    "path": "../public/projects/Cars/images/PANA9412.webp"
  },
  "/projects/Cars/images/PANA9407.webp": {
    "type": "image/webp",
    "etag": "\"c7a4c-KDzh/czGFYGC2IU2FwCJ+IIksZU\"",
    "mtime": "2026-05-05T19:34:15.713Z",
    "size": 817740,
    "path": "../public/projects/Cars/images/PANA9407.webp"
  },
  "/projects/Cars/images/PANA9409.webp": {
    "type": "image/webp",
    "etag": "\"90d5e-ZxuPoT/GAPFrjfPHQLapmuaj0pk\"",
    "mtime": "2026-05-05T19:34:15.721Z",
    "size": 593246,
    "path": "../public/projects/Cars/images/PANA9409.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/02_03.webp": {
    "type": "image/webp",
    "etag": "\"762c6-SnXNZX0xmFIddCUQ8+OJWCa75Yo\"",
    "mtime": "2026-05-05T19:34:15.402Z",
    "size": 484038,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/02_03.webp"
  },
  "/projects/Cars/images/RANDOM4.webp": {
    "type": "image/webp",
    "etag": "\"e9b7e-vQSdFeKiy/RXJ3ko04jhEE/r15M\"",
    "mtime": "2026-05-05T19:34:15.509Z",
    "size": 957310,
    "path": "../public/projects/Cars/images/RANDOM4.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/02_020.webp": {
    "type": "image/webp",
    "etag": "\"b2d88-hjOCm4h7XCQZTljyJPsRjDxd8y0\"",
    "mtime": "2026-05-05T19:34:15.383Z",
    "size": 732552,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/02_020.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/PANA9339.webp": {
    "type": "image/webp",
    "etag": "\"36858-PFx93h4yEZD3FY4ucbXyMqwR+YA\"",
    "mtime": "2026-05-05T19:34:15.464Z",
    "size": 223320,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/PANA9339.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/CAR7.webp": {
    "type": "image/webp",
    "etag": "\"69338-ND42OkRkYFIirLw4Y5ayu5zFWWI\"",
    "mtime": "2026-05-05T19:34:15.460Z",
    "size": 430904,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/CAR7.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/PANA9342.webp": {
    "type": "image/webp",
    "etag": "\"24f5c-GhOTYIjWru0QU7BJ8iBS+T13Ti0\"",
    "mtime": "2026-05-05T19:34:15.471Z",
    "size": 151388,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/PANA9342.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/PANA9347.webp": {
    "type": "image/webp",
    "etag": "\"32b22-abPIR6H/JmVwtyEP6NWMRb3hHTo\"",
    "mtime": "2026-05-05T19:34:15.477Z",
    "size": 207650,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/PANA9347.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/02_021.webp": {
    "type": "image/webp",
    "etag": "\"f76ba-pudWbTKN117ATKvqIsPG35otg8s\"",
    "mtime": "2026-05-05T19:34:15.396Z",
    "size": 1013434,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/02_021.webp"
  },
  "/projects/Cars/images/RANDOM19.webp": {
    "type": "image/webp",
    "etag": "\"17e62a-0/N7T2hLK6wv9/UMrFjdfoIsLkc\"",
    "mtime": "2026-05-05T19:34:15.499Z",
    "size": 1566250,
    "path": "../public/projects/Cars/images/RANDOM19.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/PANA9348.webp": {
    "type": "image/webp",
    "etag": "\"6f35e-mmXRkiWKu2/sandPhhsIO+MthEk\"",
    "mtime": "2026-05-05T19:34:15.484Z",
    "size": 455518,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/PANA9348.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/PANA9392.webp": {
    "type": "image/webp",
    "etag": "\"54bda-eCBCSEH9Eyu8QO9ewMuHu1Hghhc\"",
    "mtime": "2026-05-05T19:34:15.669Z",
    "size": 347098,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/PANA9392.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/02_01.webp": {
    "type": "image/webp",
    "etag": "\"16c9fa-q+HrLy/Q2RIaDV1BQebItuFcuqM\"",
    "mtime": "2026-05-05T19:34:15.360Z",
    "size": 1493498,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/02_01.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/02_06.webp": {
    "type": "image/webp",
    "etag": "\"deabc-zbeXmwtpwWbRVHtAPfRl+WBZ7XI\"",
    "mtime": "2026-05-05T19:34:15.433Z",
    "size": 912060,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/02_06.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/CAR1.webp": {
    "type": "image/webp",
    "etag": "\"98c4a-xjLnLoJSThu5Fh2U4ODy+vCryZY\"",
    "mtime": "2026-05-05T19:34:15.443Z",
    "size": 625738,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/CAR1.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/PANA9395.webp": {
    "type": "image/webp",
    "etag": "\"2fc90-Ypzjx7PrOK7QXfG60HEjyN83MYI\"",
    "mtime": "2026-05-05T19:34:15.676Z",
    "size": 195728,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/PANA9395.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/CAR11.webp": {
    "type": "image/webp",
    "etag": "\"fd6ac-LF9e40X8/r1XU6MTVnktGF2pDt4\"",
    "mtime": "2026-05-05T19:34:15.454Z",
    "size": 1037996,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/CAR11.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/02_04.webp": {
    "type": "image/webp",
    "etag": "\"1036a4-kfI6p0NDgWLNgtV2QKDdXQNUziE\"",
    "mtime": "2026-05-05T19:34:15.414Z",
    "size": 1062564,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/02_04.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/02_02.webp": {
    "type": "image/webp",
    "etag": "\"184bcc-H87O+loBNIoJJiWnBZUxMGR+xGA\"",
    "mtime": "2026-05-05T19:34:15.375Z",
    "size": 1592268,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/02_02.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/PANA9397.webp": {
    "type": "image/webp",
    "etag": "\"44022-bGK5rATGWws4+dKSjabIpgBRrIE\"",
    "mtime": "2026-05-05T19:34:15.681Z",
    "size": 278562,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/PANA9397.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/PANA9401.webp": {
    "type": "image/webp",
    "etag": "\"4fb84-NGaAO3V9OrwMY56xjoLB1MKYNJY\"",
    "mtime": "2026-05-05T19:34:15.687Z",
    "size": 326532,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/PANA9401.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/02_05.webp": {
    "type": "image/webp",
    "etag": "\"100362-VH5l5OJBQFDoiVIPKtklirNgFc8\"",
    "mtime": "2026-05-05T19:34:15.425Z",
    "size": 1049442,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/02_05.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/PANA9403.webp": {
    "type": "image/webp",
    "etag": "\"6610c-OtHDksgp37lmIVi2TlgADrjZOQ8\"",
    "mtime": "2026-05-05T19:34:15.694Z",
    "size": 418060,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/PANA9403.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/PANA9405.webp": {
    "type": "image/webp",
    "etag": "\"b78ca-BCAnQDc578V7xKfQyO93YCdkiXU\"",
    "mtime": "2026-05-05T19:34:15.704Z",
    "size": 751818,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/PANA9405.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/PANA9412.webp": {
    "type": "image/webp",
    "etag": "\"37d42-QFUk9zSoDDzcqX/9lgduJeLSZR0\"",
    "mtime": "2026-05-05T19:34:15.727Z",
    "size": 228674,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/PANA9412.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/PANA9407.webp": {
    "type": "image/webp",
    "etag": "\"c7a4c-KDzh/czGFYGC2IU2FwCJ+IIksZU\"",
    "mtime": "2026-05-05T19:34:15.713Z",
    "size": 817740,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/PANA9407.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/PANA9409.webp": {
    "type": "image/webp",
    "etag": "\"90d5e-ZxuPoT/GAPFrjfPHQLapmuaj0pk\"",
    "mtime": "2026-05-05T19:34:15.721Z",
    "size": 593246,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/PANA9409.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_160.webp": {
    "type": "image/webp",
    "etag": "\"7665a-gyOGNOK2sAezZ3bEXL4Z7AFbDG8\"",
    "mtime": "2026-05-25T12:20:50.826Z",
    "size": 484954,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_160.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_190.webp": {
    "type": "image/webp",
    "etag": "\"7f7a2-sihIYI48UEtXubN0AYASyFlfMyY\"",
    "mtime": "2026-05-25T12:20:52.538Z",
    "size": 522146,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_190.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/RANDOM4.webp": {
    "type": "image/webp",
    "etag": "\"e9b7e-vQSdFeKiy/RXJ3ko04jhEE/r15M\"",
    "mtime": "2026-05-05T19:34:15.509Z",
    "size": 957310,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/RANDOM4.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_120.webp": {
    "type": "image/webp",
    "etag": "\"efed2-yxo6yWU6X4TZelyvvo3n3XCwPEA\"",
    "mtime": "2026-05-25T12:20:47.945Z",
    "size": 982738,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_120.webp"
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
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_147.webp": {
    "type": "image/webp",
    "etag": "\"ea9a6-ERSBMEGqlazJbgc2ZhaowJMu0yA\"",
    "mtime": "2026-05-25T12:20:50.297Z",
    "size": 960934,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_147.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_232.webp": {
    "type": "image/webp",
    "etag": "\"5ce84-aWsRpsocJ1/y05nNHhnKLyk2gtg\"",
    "mtime": "2026-05-25T12:20:55.345Z",
    "size": 380548,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_232.webp"
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
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/RANDOM19.webp": {
    "type": "image/webp",
    "etag": "\"17e62a-0/N7T2hLK6wv9/UMrFjdfoIsLkc\"",
    "mtime": "2026-05-05T19:34:15.499Z",
    "size": 1566250,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/RANDOM19.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_114.webp": {
    "type": "image/webp",
    "etag": "\"144d54-xnrJhYeD0vuFfp4AkVriJo9Hp30\"",
    "mtime": "2026-05-25T12:20:47.327Z",
    "size": 1330516,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_114.webp"
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
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_213.webp": {
    "type": "image/webp",
    "etag": "\"cbd64-TdXcSuwhd/5aqJYvZmeHKsPIv6w\"",
    "mtime": "2026-05-25T12:20:54.823Z",
    "size": 834916,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_213.webp"
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
  "/projects/Henosis/images/convert.sh": {
    "type": "application/x-sh",
    "etag": "\"106-46a1n+a+SvO62eAu1vOmV2YUgMM\"",
    "mtime": "2026-08-16T12:55:42.254Z",
    "size": 262,
    "path": "../public/projects/Henosis/images/convert.sh"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_260.webp": {
    "type": "image/webp",
    "etag": "\"a0608-X7XOBdc91u3YzUgcWDvd2Vh1QaE\"",
    "mtime": "2026-05-25T12:20:58.345Z",
    "size": 656904,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_260.webp"
  },
  "/projects/Henosis/images/mpv-shot0001.webp": {
    "type": "image/webp",
    "etag": "\"7a034-yOenmyGgc7uGDx//3jxinE6KIQQ\"",
    "mtime": "2026-08-16T12:55:42.256Z",
    "size": 499764,
    "path": "../public/projects/Henosis/images/mpv-shot0001.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_274.webp": {
    "type": "image/webp",
    "etag": "\"cc2d6-oIdmt8Cwisj6/wrBEiBOYmkuVdU\"",
    "mtime": "2026-05-25T12:20:58.954Z",
    "size": 836310,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_274.webp"
  },
  "/projects/Henosis/images/mpv-shot0002.webp": {
    "type": "image/webp",
    "etag": "\"7670e-ETGfBhI7FELo6bAUCudELhUQKzM\"",
    "mtime": "2026-08-16T12:55:42.258Z",
    "size": 485134,
    "path": "../public/projects/Henosis/images/mpv-shot0002.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_276.webp": {
    "type": "image/webp",
    "etag": "\"9eaea-BVAhou5TxbdTeWBBt8zACPoLGVU\"",
    "mtime": "2026-05-25T12:20:59.533Z",
    "size": 649962,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_276.webp"
  },
  "/projects/Henosis/images/mpv-shot0005.webp": {
    "type": "image/webp",
    "etag": "\"71704-jAFe/5uVMaBV7KoJXi0tgHg5QAo\"",
    "mtime": "2026-08-16T12:55:42.266Z",
    "size": 464644,
    "path": "../public/projects/Henosis/images/mpv-shot0005.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_31.webp": {
    "type": "image/webp",
    "etag": "\"a8f7a-09OkBMoqJW5KNOND/re2j0p91WY\"",
    "mtime": "2026-05-25T12:21:00.126Z",
    "size": 692090,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_31.webp"
  },
  "/projects/Henosis/images/mpv-shot0006.webp": {
    "type": "image/webp",
    "etag": "\"4391c-GJonHjTR3GUM1nXUamFJSkbIiIY\"",
    "mtime": "2026-08-16T12:55:42.267Z",
    "size": 276764,
    "path": "../public/projects/Henosis/images/mpv-shot0006.webp"
  },
  "/projects/Henosis/images/mpv-shot0008.webp": {
    "type": "image/webp",
    "etag": "\"67556-7e496lSkqBNp7d/OiU832Bh9T6M\"",
    "mtime": "2026-08-16T12:55:42.271Z",
    "size": 423254,
    "path": "../public/projects/Henosis/images/mpv-shot0008.webp"
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
  "/projects/Henosis/images/mpv-shot0009.webp": {
    "type": "image/webp",
    "etag": "\"6a072-8PBzJ775G4rHb35H5LW7sknZCvc\"",
    "mtime": "2026-08-16T12:55:42.273Z",
    "size": 434290,
    "path": "../public/projects/Henosis/images/mpv-shot0009.webp"
  },
  "/projects/Henosis/images/mpv-shot0010.webp": {
    "type": "image/webp",
    "etag": "\"3db84-9hg0UrJ0owfAkkdHWwlCoMzWgDw\"",
    "mtime": "2026-08-16T12:55:42.274Z",
    "size": 252804,
    "path": "../public/projects/Henosis/images/mpv-shot0010.webp"
  },
  "/projects/Henosis/images/mpv-shot0004.webp": {
    "type": "image/webp",
    "etag": "\"8d48a-w9jZK+GnPzwMPMRmhyC/pkdWHqQ\"",
    "mtime": "2026-08-16T12:55:42.264Z",
    "size": 578698,
    "path": "../public/projects/Henosis/images/mpv-shot0004.webp"
  },
  "/projects/Henosis/images/mpv-shot0003.webp": {
    "type": "image/webp",
    "etag": "\"92baa-EUED0mKqhm91W4k/dCpCZoPpqyM\"",
    "mtime": "2026-08-16T12:55:42.260Z",
    "size": 601002,
    "path": "../public/projects/Henosis/images/mpv-shot0003.webp"
  },
  "/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_242.webp": {
    "type": "image/webp",
    "etag": "\"1cd212-6huVKx1xq0Qg3S1I4bamKayHXrg\"",
    "mtime": "2026-05-25T12:20:57.231Z",
    "size": 1888786,
    "path": "../public/projects/Fashion Shooting - Palazzo Nicolaci, Noto/images/sfilata_nicolaci_242.webp"
  },
  "/projects/Henosis/images/mpv-shot0007.webp": {
    "type": "image/webp",
    "etag": "\"8bc58-o8S787JA35bFYK0dyTPJXijE19c\"",
    "mtime": "2026-08-16T12:55:42.269Z",
    "size": 572504,
    "path": "../public/projects/Henosis/images/mpv-shot0007.webp"
  },
  "/projects/Henosis/images/mpv-shot0011.webp": {
    "type": "image/webp",
    "etag": "\"8e026-DwsZTDMnAFwo08c68OSsXJOXFy0\"",
    "mtime": "2026-08-16T12:55:42.276Z",
    "size": 581670,
    "path": "../public/projects/Henosis/images/mpv-shot0011.webp"
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
  "/projects/HeySport-Reels/images/ASMR-Gara.mp4": {
    "type": "video/mp4",
    "etag": "\"18052d-rXgJ0YWp1nUsatulWp9j4eltSU8\"",
    "mtime": "2026-05-03T22:42:29.388Z",
    "size": 1574189,
    "path": "../public/projects/HeySport-Reels/images/ASMR-Gara.mp4"
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
  "/projects/HeySport-Reels/images/Dettagli-B2B-3.mp4": {
    "type": "video/mp4",
    "etag": "\"1bfeae-FK2hrvkrc0KKIeeL0LaP103HP/k\"",
    "mtime": "2026-05-03T22:42:29.388Z",
    "size": 1834670,
    "path": "../public/projects/HeySport-Reels/images/Dettagli-B2B-3.mp4"
  },
  "/projects/HeySport-Reels/images/heysport_016.webp": {
    "type": "image/webp",
    "etag": "\"67cf6-/kza/tk1yeznJiSCQ5VX5WHunrE\"",
    "mtime": "2026-05-03T22:36:41.691Z",
    "size": 425206,
    "path": "../public/projects/HeySport-Reels/images/heysport_016.webp"
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
  "/projects/HeySport-Reels/images/heysport_08.webp": {
    "type": "image/webp",
    "etag": "\"5231c-QuTw7frJNpBwrHFUlydTp/k2x6k\"",
    "mtime": "2026-05-03T22:36:41.691Z",
    "size": 336668,
    "path": "../public/projects/HeySport-Reels/images/heysport_08.webp"
  },
  "/projects/HeySport-Reels/images/Dettagli-B2B.mp4": {
    "type": "video/mp4",
    "etag": "\"1c9d2a-o8imehKVv8KNbb1hSI3/sVTe1MM\"",
    "mtime": "2026-05-03T22:42:29.388Z",
    "size": 1875242,
    "path": "../public/projects/HeySport-Reels/images/Dettagli-B2B.mp4"
  },
  "/projects/OlioRoi_Rocks_Edit&SoundDesign/cover.png": {
    "type": "image/png",
    "etag": "\"105808c-nFeWoUO47RZPtzrnBbVLLmdcixc\"",
    "mtime": "2026-08-30T14:25:11.070Z",
    "size": 17137804,
    "path": "../public/projects/OlioRoi_Rocks_Edit&SoundDesign/cover.png"
  },
  "/projects/Macello-Castle-VFX/images/VFX_00.webp": {
    "type": "image/webp",
    "etag": "\"79ffe-NLz/R73zQfnluvl45pHreeQcQVE\"",
    "mtime": "2026-05-03T22:36:41.692Z",
    "size": 499710,
    "path": "../public/projects/Macello-Castle-VFX/images/VFX_00.webp"
  },
  "/projects/Lauree/images/laurea_fabius_175.webp": {
    "type": "image/webp",
    "etag": "\"6a0ea-fqk2ugJMvL9xGJpsOsnZE2M8IKU\"",
    "mtime": "2026-09-28T11:47:10.620Z",
    "size": 434410,
    "path": "../public/projects/Lauree/images/laurea_fabius_175.webp"
  },
  "/projects/Lauree/images/laurea_fabius_240.webp": {
    "type": "image/webp",
    "etag": "\"67332-ABH/yRg3rhQQFW49F3PYokLhxBg\"",
    "mtime": "2026-09-28T11:47:11.180Z",
    "size": 422706,
    "path": "../public/projects/Lauree/images/laurea_fabius_240.webp"
  },
  "/projects/HeySport-Reels/images/Gara.mp4": {
    "type": "video/mp4",
    "etag": "\"2eec86-vu+Twn6LTEsQ5cron9K25+5pt0A\"",
    "mtime": "2026-05-03T22:42:29.388Z",
    "size": 3075206,
    "path": "../public/projects/HeySport-Reels/images/Gara.mp4"
  },
  "/projects/Macello-Castle-VFX/images/VFX_03.webp": {
    "type": "image/webp",
    "etag": "\"e42ec-TKrvjSAviaomKdH3yJhh5nxD0K8\"",
    "mtime": "2026-05-03T22:36:41.692Z",
    "size": 934636,
    "path": "../public/projects/Macello-Castle-VFX/images/VFX_03.webp"
  },
  "/projects/Lauree/images/laurea_fabius_171.webp": {
    "type": "image/webp",
    "etag": "\"b8630-afZ2g+U1951Rrcw0MdZIJMgdvM4\"",
    "mtime": "2026-09-28T11:47:10.067Z",
    "size": 755248,
    "path": "../public/projects/Lauree/images/laurea_fabius_171.webp"
  },
  "/projects/Lauree/images/laurea_fabius_149.webp": {
    "type": "image/webp",
    "etag": "\"d44ae-JjD70MaEPZtwj6hJI80O/CMR3F8\"",
    "mtime": "2026-09-28T11:47:09.453Z",
    "size": 869550,
    "path": "../public/projects/Lauree/images/laurea_fabius_149.webp"
  },
  "/projects/HeySport-Reels/images/Mood.mp4": {
    "type": "video/mp4",
    "etag": "\"2053d6-VAXFeabJWrfYoKE5BBwaloqzMQY\"",
    "mtime": "2026-05-03T22:42:29.388Z",
    "size": 2118614,
    "path": "../public/projects/HeySport-Reels/images/Mood.mp4"
  },
  "/projects/Lauree/images/laurea_fabius_242.webp": {
    "type": "image/webp",
    "etag": "\"800a4-AsS4FjWvN/kz8KDZfNP/7eXfcL4\"",
    "mtime": "2026-09-28T11:47:11.760Z",
    "size": 524452,
    "path": "../public/projects/Lauree/images/laurea_fabius_242.webp"
  },
  "/projects/Lauree/images/laurea_fabius_40.webp": {
    "type": "image/webp",
    "etag": "\"b004e-ERJJZldRfD1VI3yMKOjZQzJYF0Y\"",
    "mtime": "2026-09-28T11:47:12.380Z",
    "size": 720974,
    "path": "../public/projects/Lauree/images/laurea_fabius_40.webp"
  },
  "/projects/Lauree/images/laurea_fabius_56.webp": {
    "type": "image/webp",
    "etag": "\"d9c10-Klx6bKmk7DJfAZpXW/G7H741IIg\"",
    "mtime": "2026-09-28T11:47:13.030Z",
    "size": 891920,
    "path": "../public/projects/Lauree/images/laurea_fabius_56.webp"
  },
  "/projects/HeySport-Reels/images/TutaRossa-Prep.mp4": {
    "type": "video/mp4",
    "etag": "\"206ea8-xqesk2XMID5wxPnDchVrojQH+Uw\"",
    "mtime": "2026-05-03T22:42:29.388Z",
    "size": 2125480,
    "path": "../public/projects/HeySport-Reels/images/TutaRossa-Prep.mp4"
  },
  "/projects/Lauree/images/laurea_fabius_59.webp": {
    "type": "image/webp",
    "etag": "\"9ebb8-ObIDxX3ic9SUxeJWDMvig3uivmc\"",
    "mtime": "2026-09-28T11:47:13.630Z",
    "size": 650168,
    "path": "../public/projects/Lauree/images/laurea_fabius_59.webp"
  },
  "/projects/Lauree/images/laurea_magistrale_ture_110.webp": {
    "type": "image/webp",
    "etag": "\"eddba-RiYOLcxuL7mb81I4cqp+lV4kRhk\"",
    "mtime": "2026-09-28T11:47:14.259Z",
    "size": 974266,
    "path": "../public/projects/Lauree/images/laurea_magistrale_ture_110.webp"
  },
  "/projects/Lauree/images/laurea_magistrale_ture_128.webp": {
    "type": "image/webp",
    "etag": "\"c5f70-s/TCZIOBSxaRIXb9Nxc+S7T/6UA\"",
    "mtime": "2026-09-28T11:47:16.124Z",
    "size": 810864,
    "path": "../public/projects/Lauree/images/laurea_magistrale_ture_128.webp"
  },
  "/projects/Lauree/images/laurea_magistrale_ture_126.webp": {
    "type": "image/webp",
    "etag": "\"da92c-CJmVlgHwjveQK4QE+8ZIpbIN2Io\"",
    "mtime": "2026-09-28T11:47:15.523Z",
    "size": 895276,
    "path": "../public/projects/Lauree/images/laurea_magistrale_ture_126.webp"
  },
  "/projects/Macello-Castle-VFX/images/VFX_02.webp": {
    "type": "image/webp",
    "etag": "\"17799e-ldP5mF2Mu31n/lyJQ/p6mY8OAP4\"",
    "mtime": "2026-05-03T22:36:41.692Z",
    "size": 1538462,
    "path": "../public/projects/Macello-Castle-VFX/images/VFX_02.webp"
  },
  "/projects/Lauree/images/laurea_magistrale_ture_185.webp": {
    "type": "image/webp",
    "etag": "\"fe692-AajMkCict6oUJLabTZP00JBlTow\"",
    "mtime": "2026-09-28T11:47:16.755Z",
    "size": 1042066,
    "path": "../public/projects/Lauree/images/laurea_magistrale_ture_185.webp"
  },
  "/projects/Macello-Castle-VFX/images/VFX_01.webp": {
    "type": "image/webp",
    "etag": "\"18713a-2mCdtqFDX3ni7LDjFJ4qGD/J1s0\"",
    "mtime": "2026-05-03T22:36:41.692Z",
    "size": 1601850,
    "path": "../public/projects/Macello-Castle-VFX/images/VFX_01.webp"
  },
  "/projects/Lauree/images/laurea_magistrale_ture_198.webp": {
    "type": "image/webp",
    "etag": "\"cfcea-e3E3qWbf3+9hpB1joayimRdFDcw\"",
    "mtime": "2026-09-28T11:47:18.003Z",
    "size": 851178,
    "path": "../public/projects/Lauree/images/laurea_magistrale_ture_198.webp"
  },
  "/projects/Lauree/images/laurea_magistrale_ture_120.webp": {
    "type": "image/webp",
    "etag": "\"10a0a8-ffOrWx2n+A3NEl8ox1U95jAH580\"",
    "mtime": "2026-09-28T11:47:14.927Z",
    "size": 1089704,
    "path": "../public/projects/Lauree/images/laurea_magistrale_ture_120.webp"
  },
  "/projects/Lauree/images/laurea_magistrale_ture_19.webp": {
    "type": "image/webp",
    "etag": "\"11e1d0-NH3+uKvWkw9GyLT+ZfpK7lMY8gs\"",
    "mtime": "2026-09-28T11:47:17.410Z",
    "size": 1171920,
    "path": "../public/projects/Lauree/images/laurea_magistrale_ture_19.webp"
  },
  "/projects/Lauree/images/laurea_magistrale_ture_31.webp": {
    "type": "image/webp",
    "etag": "\"116bda-ZG1hcQaWHwSy5hOUn2pKq8HGoMs\"",
    "mtime": "2026-09-28T11:47:18.650Z",
    "size": 1141722,
    "path": "../public/projects/Lauree/images/laurea_magistrale_ture_31.webp"
  },
  "/projects/Lauree/images/laurea_magistrale_ture_315.webp": {
    "type": "image/webp",
    "etag": "\"f16b2-WlTkCx3ywc0d0H1UVm+7tJze0SE\"",
    "mtime": "2026-09-28T11:47:19.285Z",
    "size": 988850,
    "path": "../public/projects/Lauree/images/laurea_magistrale_ture_315.webp"
  },
  "/projects/Lauree/images/laurea_magistrale_ture_355.webp": {
    "type": "image/webp",
    "etag": "\"feb44-/n3LN1ZwFnbhvvh4b8QV+Ubi5eE\"",
    "mtime": "2026-09-28T11:47:20.608Z",
    "size": 1043268,
    "path": "../public/projects/Lauree/images/laurea_magistrale_ture_355.webp"
  },
  "/projects/Lauree/images/laurea_magistrale_ture_378.webp": {
    "type": "image/webp",
    "etag": "\"99d56-Zkt+wCS8E5GMwng83PWYCBhLEqs\"",
    "mtime": "2026-09-28T11:47:21.606Z",
    "size": 630102,
    "path": "../public/projects/Lauree/images/laurea_magistrale_ture_378.webp"
  },
  "/projects/Lauree/images/laurea_magistrale_ture_37.webp": {
    "type": "image/webp",
    "etag": "\"c5f80-ryqbYdtC+CgWW823AQxuGaDpIdo\"",
    "mtime": "2026-09-28T11:47:21.195Z",
    "size": 810880,
    "path": "../public/projects/Lauree/images/laurea_magistrale_ture_37.webp"
  },
  "/projects/Lauree/images/laurea_magistrale_ture_385.webp": {
    "type": "image/webp",
    "etag": "\"e872a-/dRupqLrrDERmJ2EF5UAvkNz+t4\"",
    "mtime": "2026-09-28T11:47:22.230Z",
    "size": 952106,
    "path": "../public/projects/Lauree/images/laurea_magistrale_ture_385.webp"
  },
  "/projects/Lauree/images/laurea_magistrale_ture_388.webp": {
    "type": "image/webp",
    "etag": "\"ee376-vUmqknC7ekFNv1nZ+4yOwXcR7D0\"",
    "mtime": "2026-09-28T11:47:22.872Z",
    "size": 975734,
    "path": "../public/projects/Lauree/images/laurea_magistrale_ture_388.webp"
  },
  "/projects/Lauree/images/laurea_magistrale_ture_51.webp": {
    "type": "image/webp",
    "etag": "\"ebaa0-+lBn9oCrE9YW8OGHCYVDowWTxU8\"",
    "mtime": "2026-09-28T11:47:23.490Z",
    "size": 965280,
    "path": "../public/projects/Lauree/images/laurea_magistrale_ture_51.webp"
  },
  "/projects/Lauree/images/laurea_magistrale_ture_348.webp": {
    "type": "image/webp",
    "etag": "\"12c95e-I+ZpBKBW+B4cZv5IQm/LyGerARM\"",
    "mtime": "2026-09-28T11:47:19.960Z",
    "size": 1231198,
    "path": "../public/projects/Lauree/images/laurea_magistrale_ture_348.webp"
  },
  "/projects/HeySport-Reels/images/Paganella-Prep.mp4": {
    "type": "video/mp4",
    "etag": "\"483428-0XGEEoKjQAOsYcAtxcJ0MKK8g7I\"",
    "mtime": "2026-05-03T22:42:29.388Z",
    "size": 4731944,
    "path": "../public/projects/HeySport-Reels/images/Paganella-Prep.mp4"
  },
  "/projects/Lauree/images/laurea_magistrale_ture_96.webp": {
    "type": "image/webp",
    "etag": "\"d6578-Sy17toYG02mp2s2W1NoeKk1Hrq8\"",
    "mtime": "2026-09-28T11:47:24.770Z",
    "size": 877944,
    "path": "../public/projects/Lauree/images/laurea_magistrale_ture_96.webp"
  },
  "/projects/Lauree/images/laurea_maria_chiara_mattina_129.webp": {
    "type": "image/webp",
    "etag": "\"f061a-oTtvX7mgSxNphw7IeKIX9v21vGo\"",
    "mtime": "2026-09-28T11:47:26.213Z",
    "size": 984602,
    "path": "../public/projects/Lauree/images/laurea_maria_chiara_mattina_129.webp"
  },
  "/projects/Lauree/images/laurea_maria_chiara_mattina_141.webp": {
    "type": "image/webp",
    "etag": "\"f889c-xVzlDPFLokrRhEP4JJzn/7xargE\"",
    "mtime": "2026-09-28T11:47:26.847Z",
    "size": 1018012,
    "path": "../public/projects/Lauree/images/laurea_maria_chiara_mattina_141.webp"
  },
  "/projects/Lauree/images/laurea_maria_chiara_mattina_24.webp": {
    "type": "image/webp",
    "etag": "\"df590-c4Qmc28c3qtjs769//lxbGn42+Q\"",
    "mtime": "2026-09-28T11:47:27.527Z",
    "size": 914832,
    "path": "../public/projects/Lauree/images/laurea_maria_chiara_mattina_24.webp"
  },
  "/projects/Lauree/images/laurea_maria_chiara_mattina_39.webp": {
    "type": "image/webp",
    "etag": "\"e40ec-LMAy7KaDE7MA8YpcYLwvZm3CTJI\"",
    "mtime": "2026-09-28T11:47:28.178Z",
    "size": 934124,
    "path": "../public/projects/Lauree/images/laurea_maria_chiara_mattina_39.webp"
  },
  "/projects/Lauree/images/laurea_maria_chiara_mattina_63.webp": {
    "type": "image/webp",
    "etag": "\"e0766-6cjz0aP09mODGHxELQnp24mA3mU\"",
    "mtime": "2026-09-28T11:47:28.755Z",
    "size": 919398,
    "path": "../public/projects/Lauree/images/laurea_maria_chiara_mattina_63.webp"
  },
  "/projects/Lauree/images/laurea_maria_chiara_mattina_78.webp": {
    "type": "image/webp",
    "etag": "\"a1cc6-3nqXqYMSr6hIsC5hKoVtAEZVAyk\"",
    "mtime": "2026-09-28T11:47:29.189Z",
    "size": 662726,
    "path": "../public/projects/Lauree/images/laurea_maria_chiara_mattina_78.webp"
  },
  "/projects/Lauree/images/laurea_magistrale_ture_56.webp": {
    "type": "image/webp",
    "etag": "\"121ec8-W8SBZRPtj/5mKdOgJt1LK+ow2Oc\"",
    "mtime": "2026-09-28T11:47:24.150Z",
    "size": 1187528,
    "path": "../public/projects/Lauree/images/laurea_magistrale_ture_56.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-11.webp": {
    "type": "image/webp",
    "etag": "\"d20cc-HzbKtuvIeuoG3yZVfUNtoUnzmR4\"",
    "mtime": "2026-05-03T22:36:41.697Z",
    "size": 860364,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-11.webp"
  },
  "/projects/HeySport-Reels/images/Vialattea-PrepAction.mp4": {
    "type": "video/mp4",
    "etag": "\"502bb2-3GpwEu0/7zSu2Y1unZm///GKVig\"",
    "mtime": "2026-05-03T22:42:29.388Z",
    "size": 5254066,
    "path": "../public/projects/HeySport-Reels/images/Vialattea-PrepAction.mp4"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-12.webp": {
    "type": "image/webp",
    "etag": "\"f20d0-+PclaFDjDG+aJ4PlyAvNxAPivoc\"",
    "mtime": "2026-05-03T22:36:41.697Z",
    "size": 991440,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-12.webp"
  },
  "/projects/Lauree/images/laurea_maria_chiara_mattina_120.webp": {
    "type": "image/webp",
    "etag": "\"1c5c92-XBAUYBuGzKm5w8tiVe7Uc5eZhF8\"",
    "mtime": "2026-09-28T11:47:25.546Z",
    "size": 1858706,
    "path": "../public/projects/Lauree/images/laurea_maria_chiara_mattina_120.webp"
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
  "/projects/macello-horse-bts/images/VFXShootingDay-15.webp": {
    "type": "image/webp",
    "etag": "\"7970c-g+nA9U0HNXzb8hGi8q9BcFZM1zU\"",
    "mtime": "2026-05-03T22:36:41.698Z",
    "size": 497420,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-15.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-13.webp": {
    "type": "image/webp",
    "etag": "\"11fd7e-9cqeIi+nNx0tOTGDGjibLpFkrBs\"",
    "mtime": "2026-05-03T22:36:41.697Z",
    "size": 1179006,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-13.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-16.webp": {
    "type": "image/webp",
    "etag": "\"cc71c-JI0TTe5uSkLr95VgpLzKHQL4Dtk\"",
    "mtime": "2026-05-03T22:36:41.698Z",
    "size": 837404,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-16.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-18.webp": {
    "type": "image/webp",
    "etag": "\"c2a6e-CO3PFNMzo7RJZx4EOWpfEJfZABE\"",
    "mtime": "2026-05-03T22:36:41.698Z",
    "size": 797294,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-18.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-20.webp": {
    "type": "image/webp",
    "etag": "\"d3caa-esuSEq/XbiWz11VLbSdHGzCYzic\"",
    "mtime": "2026-05-03T22:36:41.698Z",
    "size": 867498,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-20.webp"
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
  "/projects/macello-horse-bts/images/VFXShootingDay-14.webp": {
    "type": "image/webp",
    "etag": "\"12fdc8-8jt/aFAMc7tOULQGr0RE1+AC/KE\"",
    "mtime": "2026-05-03T22:36:41.698Z",
    "size": 1244616,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-14.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-27.webp": {
    "type": "image/webp",
    "etag": "\"bd06c-pho62zOiZt1Rkyo0wHsMHXkF0Pg\"",
    "mtime": "2026-05-03T22:36:41.699Z",
    "size": 774252,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-27.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-25.webp": {
    "type": "image/webp",
    "etag": "\"ed506-IP0bEFZvi8yZD/vvFeau10IliJI\"",
    "mtime": "2026-05-03T22:36:41.699Z",
    "size": 972038,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-25.webp"
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
  "/projects/macello-horse-bts/images/VFXShootingDay-23.webp": {
    "type": "image/webp",
    "etag": "\"11a106-7WdL7xOlbpWddhS8LwE2OrydaeA\"",
    "mtime": "2026-05-03T22:36:41.698Z",
    "size": 1155334,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-23.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-24.webp": {
    "type": "image/webp",
    "etag": "\"12be24-ebhHas4odEkLXDnTjlGXEfu0cn0\"",
    "mtime": "2026-05-03T22:36:41.699Z",
    "size": 1228324,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-24.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-30.webp": {
    "type": "image/webp",
    "etag": "\"d239a-Yl4iKi3oO7C6SOYB65HFCgy9Z9Y\"",
    "mtime": "2026-05-03T22:36:41.699Z",
    "size": 861082,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-30.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-29.webp": {
    "type": "image/webp",
    "etag": "\"100898-OEJsx6xzASBMCltQT0JriJw3dNI\"",
    "mtime": "2026-05-03T22:36:41.699Z",
    "size": 1050776,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-29.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-28.webp": {
    "type": "image/webp",
    "etag": "\"144630-ly6EjeBziYFtVsVEQr3nsPqWHvo\"",
    "mtime": "2026-05-03T22:36:41.699Z",
    "size": 1328688,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-28.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-3.webp": {
    "type": "image/webp",
    "etag": "\"116080-+v9tnVvmZnQulwPrjTY7EtiBtw8\"",
    "mtime": "2026-05-03T22:36:41.699Z",
    "size": 1138816,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-3.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-4.webp": {
    "type": "image/webp",
    "etag": "\"17dd44-TzbMmLIl0vNfeauFTppE33ubQzI\"",
    "mtime": "2026-05-03T22:36:41.699Z",
    "size": 1563972,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-4.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-5.webp": {
    "type": "image/webp",
    "etag": "\"10041e-P3YMtC4qRCT+W7s1a11dmx/uJtY\"",
    "mtime": "2026-05-03T22:36:41.699Z",
    "size": 1049630,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-5.webp"
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
  "/projects/Making_of_pasta/images/convert.sh": {
    "type": "application/x-sh",
    "etag": "\"106-46a1n+a+SvO62eAu1vOmV2YUgMM\"",
    "mtime": "2026-08-16T12:55:42.279Z",
    "size": 262,
    "path": "../public/projects/Making_of_pasta/images/convert.sh"
  },
  "/projects/Making_of_pasta/images/mpv-shot0012.webp": {
    "type": "image/webp",
    "etag": "\"533e0-+M08ZTwXaFShzjM6GwtR0VLk+qs\"",
    "mtime": "2026-08-16T12:55:42.280Z",
    "size": 340960,
    "path": "../public/projects/Making_of_pasta/images/mpv-shot0012.webp"
  },
  "/projects/Making_of_pasta/images/mpv-shot0013.webp": {
    "type": "image/webp",
    "etag": "\"63e9a-9mNSQBSaITRY7C7SwE/hoBMic80\"",
    "mtime": "2026-08-16T12:55:42.283Z",
    "size": 409242,
    "path": "../public/projects/Making_of_pasta/images/mpv-shot0013.webp"
  },
  "/projects/Making_of_pasta/images/mpv-shot0014.webp": {
    "type": "image/webp",
    "etag": "\"378e4-hwk/fpQRwu0M0yrz6AZE1ivMXrk\"",
    "mtime": "2026-08-16T12:55:42.284Z",
    "size": 227556,
    "path": "../public/projects/Making_of_pasta/images/mpv-shot0014.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-8.webp": {
    "type": "image/webp",
    "etag": "\"b5096-5yX+0Yk29uSeILyAyEB1p3h1sek\"",
    "mtime": "2026-05-03T22:36:41.700Z",
    "size": 741526,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-8.webp"
  },
  "/projects/Making_of_pasta/images/mpv-shot0015.webp": {
    "type": "image/webp",
    "etag": "\"52688-MkFD3Q7wR5DcDrZxBHsK6va7CsU\"",
    "mtime": "2026-08-16T12:55:42.286Z",
    "size": 337544,
    "path": "../public/projects/Making_of_pasta/images/mpv-shot0015.webp"
  },
  "/projects/Making_of_pasta/images/mpv-shot0016.webp": {
    "type": "image/webp",
    "etag": "\"55d32-d+e86JR1lIA0QVSBbbS46FK8tuM\"",
    "mtime": "2026-08-16T12:55:42.288Z",
    "size": 351538,
    "path": "../public/projects/Making_of_pasta/images/mpv-shot0016.webp"
  },
  "/projects/Making_of_pasta/images/mpv-shot0017.webp": {
    "type": "image/webp",
    "etag": "\"30812-XjI0lCCjDk2Ulr9+QFdDOpGR29M\"",
    "mtime": "2026-08-16T12:55:42.289Z",
    "size": 198674,
    "path": "../public/projects/Making_of_pasta/images/mpv-shot0017.webp"
  },
  "/projects/macello-horse-bts/images/VFXShootingDay-9.webp": {
    "type": "image/webp",
    "etag": "\"c8814-6Lce9BRGhIZ2d/J7K8JQdAmJOVc\"",
    "mtime": "2026-05-03T22:36:41.700Z",
    "size": 821268,
    "path": "../public/projects/macello-horse-bts/images/VFXShootingDay-9.webp"
  },
  "/projects/Making_of_pasta/images/mpv-shot0019.webp": {
    "type": "image/webp",
    "etag": "\"3caa8-t8DvJDk6P/gyPT4Z7mTpc59/S8w\"",
    "mtime": "2026-08-16T12:55:42.292Z",
    "size": 248488,
    "path": "../public/projects/Making_of_pasta/images/mpv-shot0019.webp"
  },
  "/projects/Making_of_pasta/images/mpv-shot0018.webp": {
    "type": "image/webp",
    "etag": "\"380d8-GyPz9updcdswpLYkWC7wA7YHO2s\"",
    "mtime": "2026-08-16T12:55:42.290Z",
    "size": 229592,
    "path": "../public/projects/Making_of_pasta/images/mpv-shot0018.webp"
  },
  "/projects/Making_of_pasta/images/mpv-shot0020.webp": {
    "type": "image/webp",
    "etag": "\"5f6ce-OMRu6qmHoRJsBj1QllLnX/oP2o0\"",
    "mtime": "2026-08-16T12:55:42.294Z",
    "size": 390862,
    "path": "../public/projects/Making_of_pasta/images/mpv-shot0020.webp"
  },
  "/projects/Making_of_pasta/images/mpv-shot0021.webp": {
    "type": "image/webp",
    "etag": "\"360f0-Nqny9Rkr5iIzcQgpbv2TtuyIwiI\"",
    "mtime": "2026-08-16T12:55:42.295Z",
    "size": 221424,
    "path": "../public/projects/Making_of_pasta/images/mpv-shot0021.webp"
  },
  "/projects/Making_of_pasta/images/mpv-shot0022.webp": {
    "type": "image/webp",
    "etag": "\"41ef8-5xoNuH0mhi7YTsb8MIULYXUGJtk\"",
    "mtime": "2026-08-16T12:55:42.297Z",
    "size": 270072,
    "path": "../public/projects/Making_of_pasta/images/mpv-shot0022.webp"
  },
  "/projects/Making_of_pasta/images/mpv-shot0023.webp": {
    "type": "image/webp",
    "etag": "\"51a2a-bhbqFJQy7TdaNt2Y8HTA3nuNXlE\"",
    "mtime": "2026-08-16T12:55:42.298Z",
    "size": 334378,
    "path": "../public/projects/Making_of_pasta/images/mpv-shot0023.webp"
  },
  "/projects/Making_of_pasta/images/mpv-shot0024.webp": {
    "type": "image/webp",
    "etag": "\"4cf9e-W7//rRk3voefFOS2QRgxhApIlpU\"",
    "mtime": "2026-08-16T12:55:42.300Z",
    "size": 315294,
    "path": "../public/projects/Making_of_pasta/images/mpv-shot0024.webp"
  },
  "/projects/Making_of_pasta/images/mpv-shot0025.webp": {
    "type": "image/webp",
    "etag": "\"5e6c6-qcDS105yhRbV+zMasrjcoUnb2h4\"",
    "mtime": "2026-08-16T12:55:42.301Z",
    "size": 386758,
    "path": "../public/projects/Making_of_pasta/images/mpv-shot0025.webp"
  },
  "/projects/Making_of_pasta/images/mpv-shot0026.webp": {
    "type": "image/webp",
    "etag": "\"392a4-pLNmtHMO4ZE7xvxLQlbpi1UUpDY\"",
    "mtime": "2026-08-16T12:55:42.302Z",
    "size": 234148,
    "path": "../public/projects/Making_of_pasta/images/mpv-shot0026.webp"
  },
  "/projects/Making_of_pasta/images/mpv-shot0027.webp": {
    "type": "image/webp",
    "etag": "\"540ce-kudfl05o6dVkaNMD83sVItf0LxQ\"",
    "mtime": "2026-08-16T12:55:42.304Z",
    "size": 344270,
    "path": "../public/projects/Making_of_pasta/images/mpv-shot0027.webp"
  },
  "/projects/Making_of_pasta/images/mpv-shot0028.webp": {
    "type": "image/webp",
    "etag": "\"4874a-WTvamD3JnHY7x02M7KQtTBjlpJ8\"",
    "mtime": "2026-08-16T12:55:42.306Z",
    "size": 296778,
    "path": "../public/projects/Making_of_pasta/images/mpv-shot0028.webp"
  },
  "/projects/Making_of_pasta/images/mpv-shot0029.webp": {
    "type": "image/webp",
    "etag": "\"4f50a-LVJNAyxIPOKK5IpObM2qMifoJK0\"",
    "mtime": "2026-08-16T12:55:42.307Z",
    "size": 324874,
    "path": "../public/projects/Making_of_pasta/images/mpv-shot0029.webp"
  },
  "/projects/Making_of_pasta/images/mpv-shot0030.webp": {
    "type": "image/webp",
    "etag": "\"7386c-9rSLYOW26X1oVIvat605wn1awdI\"",
    "mtime": "2026-08-16T12:55:42.310Z",
    "size": 473196,
    "path": "../public/projects/Making_of_pasta/images/mpv-shot0030.webp"
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
  "/projects/Martina_Pace/images/test_canon_c50_130.webp": {
    "type": "image/webp",
    "etag": "\"7b3e4-GKNE4bUP17MZIWrlhskxFrrzKJI\"",
    "mtime": "2026-04-19T20:03:35.289Z",
    "size": 504804,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_130.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_134.webp": {
    "type": "image/webp",
    "etag": "\"7b316-TIHbDYiO7t97rXYYzh/qQPULpsE\"",
    "mtime": "2026-04-19T20:03:35.292Z",
    "size": 504598,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_134.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_22.webp": {
    "type": "image/webp",
    "etag": "\"66bca-mett2a23x9ggLFkI8E3WUy0mDQU\"",
    "mtime": "2026-04-19T20:03:35.295Z",
    "size": 420810,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_22.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_01.webp": {
    "type": "image/webp",
    "etag": "\"d9a2e-E9NN9hWHpAqk7XLa4m7pBOLtpJw\"",
    "mtime": "2026-04-19T20:03:35.275Z",
    "size": 891438,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_01.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_113.webp": {
    "type": "image/webp",
    "etag": "\"c182e-mXC62CAO59SURnZvz/O4ZUew3/g\"",
    "mtime": "2026-04-19T20:03:35.278Z",
    "size": 792622,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_113.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_118.webp": {
    "type": "image/webp",
    "etag": "\"85c60-R4+aCXR/UY9aKrV/ShJbrqDFEAU\"",
    "mtime": "2026-04-19T20:03:35.282Z",
    "size": 547936,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_118.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_115.webp": {
    "type": "image/webp",
    "etag": "\"ad01a-ihEfOCO1WAFzUzdvcLJo+xSOcmw\"",
    "mtime": "2026-04-19T20:03:35.280Z",
    "size": 708634,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_115.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_126.webp": {
    "type": "image/webp",
    "etag": "\"80dc6-WNfopw7YlarzdPtenHgiv2P4fto\"",
    "mtime": "2026-04-19T20:03:35.288Z",
    "size": 527814,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_126.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_135.webp": {
    "type": "image/webp",
    "etag": "\"91400-TQ9bfCyrsDT/pQS06Vb+1BOKkK0\"",
    "mtime": "2026-04-19T20:03:35.294Z",
    "size": 594944,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_135.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_36.webp": {
    "type": "image/webp",
    "etag": "\"809d2-Di5NsnMibQEGORdih/vhkmcZwtA\"",
    "mtime": "2026-04-19T20:03:35.300Z",
    "size": 526802,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_36.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_26.webp": {
    "type": "image/webp",
    "etag": "\"8f874-pcj/tIfDNN4Gz6zttKv0qznymG0\"",
    "mtime": "2026-04-19T20:03:35.298Z",
    "size": 587892,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_26.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_43.webp": {
    "type": "image/webp",
    "etag": "\"85880-XHykGS5aMJEtIKzoJIFKKN6d1U0\"",
    "mtime": "2026-04-19T20:03:35.305Z",
    "size": 546944,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_43.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_37.webp": {
    "type": "image/webp",
    "etag": "\"91764-HLuoXLGMUhxvQVjhpVS5aKTDKPM\"",
    "mtime": "2026-04-19T20:03:35.302Z",
    "size": 595812,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_37.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_89.webp": {
    "type": "image/webp",
    "etag": "\"59906-px8XU4FY7f3VJIl6owsFX1PPgiU\"",
    "mtime": "2026-04-19T20:03:35.318Z",
    "size": 366854,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_89.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_60.webp": {
    "type": "image/webp",
    "etag": "\"d4d24-SWWn/w6bqijE3tcicxDZ92KJSs8\"",
    "mtime": "2026-04-19T20:03:35.312Z",
    "size": 871716,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_60.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_76.webp": {
    "type": "image/webp",
    "etag": "\"9229c-P7H5M6Zx0Ha6460TWd9xE9rMZYU\"",
    "mtime": "2026-04-19T20:03:35.314Z",
    "size": 598684,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_76.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_93.webp": {
    "type": "image/webp",
    "etag": "\"7530a-JW/yNQVqPOj+6S7lNYyrgRixVoQ\"",
    "mtime": "2026-04-19T20:03:35.321Z",
    "size": 480010,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_93.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_46.webp": {
    "type": "image/webp",
    "etag": "\"10e000-Z2nprXbdQX17ETUtM/yLgG18SAg\"",
    "mtime": "2026-04-19T20:03:35.309Z",
    "size": 1105920,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_46.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_79.webp": {
    "type": "image/webp",
    "etag": "\"a23f6-JyhuHVBx81YlD2/eZQ+tJk4/V68\"",
    "mtime": "2026-04-19T20:03:35.316Z",
    "size": 664566,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_79.webp"
  },
  "/projects/Merlo-e-Worker-ADVs/images/merlo_01.webp": {
    "type": "image/webp",
    "etag": "\"27528-3nCLuQaeMPwR4sn8uykBb5U6EG0\"",
    "mtime": "2026-05-03T22:36:41.692Z",
    "size": 161064,
    "path": "../public/projects/Merlo-e-Worker-ADVs/images/merlo_01.webp"
  },
  "/projects/Martina_Pace/images/test_canon_c50_95.webp": {
    "type": "image/webp",
    "etag": "\"7bfba-bPhHB+xNZ7dleFTdyLWwG4wBeN0\"",
    "mtime": "2026-04-19T20:03:35.322Z",
    "size": 507834,
    "path": "../public/projects/Martina_Pace/images/test_canon_c50_95.webp"
  },
  "/projects/Merlo-e-Worker-ADVs/images/merlo_02.webp": {
    "type": "image/webp",
    "etag": "\"2d3e4-oLUf6Zf5jwrmZlwQjjtgoBRwR0Y\"",
    "mtime": "2026-05-03T22:36:41.692Z",
    "size": 185316,
    "path": "../public/projects/Merlo-e-Worker-ADVs/images/merlo_02.webp"
  },
  "/projects/Merlo-e-Worker-ADVs/images/merlo_03.webp": {
    "type": "image/webp",
    "etag": "\"2341e-EpK7TYMw7XMNYNxODsIDUPowRUw\"",
    "mtime": "2026-05-03T22:36:41.692Z",
    "size": 144414,
    "path": "../public/projects/Merlo-e-Worker-ADVs/images/merlo_03.webp"
  },
  "/projects/Merlo-e-Worker-ADVs/images/merlo_04.webp": {
    "type": "image/webp",
    "etag": "\"3af4a-23mdjB2R16n6sd0yU7xqlhrEP5s\"",
    "mtime": "2026-05-03T22:36:41.693Z",
    "size": 241482,
    "path": "../public/projects/Merlo-e-Worker-ADVs/images/merlo_04.webp"
  },
  "/projects/Merlo-e-Worker-ADVs/images/merlo_05.webp": {
    "type": "image/webp",
    "etag": "\"2f26c-GM6KZrbWQsrFeSA5udcH4dwHJMg\"",
    "mtime": "2026-05-03T22:36:41.693Z",
    "size": 193132,
    "path": "../public/projects/Merlo-e-Worker-ADVs/images/merlo_05.webp"
  },
  "/projects/Merlo-e-Worker-ADVs/images/merlo_06.webp": {
    "type": "image/webp",
    "etag": "\"3a916-26RIW1P7tpe34cv0suv3MZY/euI\"",
    "mtime": "2026-05-03T22:36:41.693Z",
    "size": 239894,
    "path": "../public/projects/Merlo-e-Worker-ADVs/images/merlo_06.webp"
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
  "/projects/My-Lamination/images/convert_webp.bat": {
    "type": "application/x-msdownload",
    "etag": "\"46-KHZ7Umv89lb8Pey7AxUXqwOEn4U\"",
    "mtime": "2026-05-03T22:36:41.694Z",
    "size": 70,
    "path": "../public/projects/My-Lamination/images/convert_webp.bat"
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
  "/projects/My-Lamination/images/MyLamination-17.webp": {
    "type": "image/webp",
    "etag": "\"810f0-zzUCVidI8S/1Mv6whWrJ5Opej1g\"",
    "mtime": "2026-05-03T22:36:41.694Z",
    "size": 528624,
    "path": "../public/projects/My-Lamination/images/MyLamination-17.webp"
  },
  "/projects/My-Lamination/images/MyLamination-9.webp": {
    "type": "image/webp",
    "etag": "\"75ad8-mGDrU5/21Ke2V3eNg1FeOZUiG1E\"",
    "mtime": "2026-05-03T22:36:41.694Z",
    "size": 482008,
    "path": "../public/projects/My-Lamination/images/MyLamination-9.webp"
  },
  "/projects/OlioRoi_Rocks_Edit&SoundDesign/images/mpv-shot0001.webp": {
    "type": "image/webp",
    "etag": "\"48c7a-exITzGcRWVC7pnRmF4RdKoRWdqE\"",
    "mtime": "2026-08-30T14:20:17.490Z",
    "size": 298106,
    "path": "../public/projects/OlioRoi_Rocks_Edit&SoundDesign/images/mpv-shot0001.webp"
  },
  "/projects/My-Lamination/images/MyLamination-19.webp": {
    "type": "image/webp",
    "etag": "\"896bc-IRPADobx7Pyhs8Flfjwh8p0jI7M\"",
    "mtime": "2026-05-03T22:36:41.694Z",
    "size": 562876,
    "path": "../public/projects/My-Lamination/images/MyLamination-19.webp"
  },
  "/projects/OlioRoi_Rocks_Edit&SoundDesign/images/mpv-shot0002.webp": {
    "type": "image/webp",
    "etag": "\"6120c-dtYpZI5pGVQ8/muDZvy6nwMWs1Q\"",
    "mtime": "2026-08-30T14:20:17.698Z",
    "size": 397836,
    "path": "../public/projects/OlioRoi_Rocks_Edit&SoundDesign/images/mpv-shot0002.webp"
  },
  "/projects/My-Lamination/images/MyLamination-8.webp": {
    "type": "image/webp",
    "etag": "\"84b26-TRkZHm5RY+0n0iDIBN+SEiRnFko\"",
    "mtime": "2026-05-03T22:36:41.694Z",
    "size": 543526,
    "path": "../public/projects/My-Lamination/images/MyLamination-8.webp"
  },
  "/projects/OlioRoi_Rocks_Edit&SoundDesign/images/mpv-shot0005.webp": {
    "type": "image/webp",
    "etag": "\"44892-cGqJANnD2Y2lN5B4dXQ1FPp2gNY\"",
    "mtime": "2026-08-30T14:20:18.352Z",
    "size": 280722,
    "path": "../public/projects/OlioRoi_Rocks_Edit&SoundDesign/images/mpv-shot0005.webp"
  },
  "/projects/OlioRoi_Rocks_Edit&SoundDesign/images/mpv-shot0004.webp": {
    "type": "image/webp",
    "etag": "\"70320-0HIh7SBqFxLEGAV+10BTPAj8TNM\"",
    "mtime": "2026-08-30T14:20:18.158Z",
    "size": 459552,
    "path": "../public/projects/OlioRoi_Rocks_Edit&SoundDesign/images/mpv-shot0004.webp"
  },
  "/projects/OlioRoi_Rocks_Edit&SoundDesign/images/mpv-shot0006.webp": {
    "type": "image/webp",
    "etag": "\"7e48c-ee58tMPJZldLUk/Q12e9ISJyLkE\"",
    "mtime": "2026-08-30T14:20:18.571Z",
    "size": 517260,
    "path": "../public/projects/OlioRoi_Rocks_Edit&SoundDesign/images/mpv-shot0006.webp"
  },
  "/projects/OlioRoi_Rocks_Edit&SoundDesign/images/mpv-shot0007.webp": {
    "type": "image/webp",
    "etag": "\"57130-HvXcKe587hYwgi3G2XREtNqoI9E\"",
    "mtime": "2026-08-30T14:20:18.774Z",
    "size": 356656,
    "path": "../public/projects/OlioRoi_Rocks_Edit&SoundDesign/images/mpv-shot0007.webp"
  },
  "/projects/OrtoDiSantaChiara/images/convert_webp.bat": {
    "type": "application/x-msdownload",
    "etag": "\"5b-qaB05HWn+X2uRW3zztKrr5rL4AM\"",
    "mtime": "2026-08-16T15:35:35.778Z",
    "size": 91,
    "path": "../public/projects/OrtoDiSantaChiara/images/convert_webp.bat"
  },
  "/projects/OrtoDiSantaChiara/images/mpv-shot0005.webp": {
    "type": "image/webp",
    "etag": "\"32d60-FhqOUKdiRTk5YV82uml2kjZ3bfk\"",
    "mtime": "2026-08-16T15:35:44.184Z",
    "size": 208224,
    "path": "../public/projects/OrtoDiSantaChiara/images/mpv-shot0005.webp"
  },
  "/projects/OrtoDiSantaChiara/images/mpv-shot0010.webp": {
    "type": "image/webp",
    "etag": "\"274b6-j18uth4xncG+P+Akof5LcGNGdBY\"",
    "mtime": "2026-08-16T15:35:44.378Z",
    "size": 160950,
    "path": "../public/projects/OrtoDiSantaChiara/images/mpv-shot0010.webp"
  },
  "/projects/OrtoDiSantaChiara/images/mpv-shot0011.webp": {
    "type": "image/webp",
    "etag": "\"2712a-tanuXuo+6oEO2ahXvsQpmsl38zM\"",
    "mtime": "2026-08-16T15:35:44.570Z",
    "size": 160042,
    "path": "../public/projects/OrtoDiSantaChiara/images/mpv-shot0011.webp"
  },
  "/projects/OlioRoi_Rocks_Edit&SoundDesign/images/mpv-shot0003.webp": {
    "type": "image/webp",
    "etag": "\"c05b6-0eHy15x1I7j09/XV6xDCCLhLHHw\"",
    "mtime": "2026-08-30T14:20:17.944Z",
    "size": 787894,
    "path": "../public/projects/OlioRoi_Rocks_Edit&SoundDesign/images/mpv-shot0003.webp"
  },
  "/projects/OrtoDiSantaChiara/images/mpv-shot0012.webp": {
    "type": "image/webp",
    "etag": "\"56e9a-ZQS8asNEJ/TGr2URXlDzge0RDPQ\"",
    "mtime": "2026-08-16T15:35:44.800Z",
    "size": 355994,
    "path": "../public/projects/OrtoDiSantaChiara/images/mpv-shot0012.webp"
  },
  "/projects/OrtoDiSantaChiara/images/mpv-shot0013.webp": {
    "type": "image/webp",
    "etag": "\"4fad6-dxaLCJStylhdHSlgHD7rzqVF4JQ\"",
    "mtime": "2026-08-16T15:35:45.019Z",
    "size": 326358,
    "path": "../public/projects/OrtoDiSantaChiara/images/mpv-shot0013.webp"
  },
  "/projects/OrtoDiSantaChiara/images/mpv-shot0014.webp": {
    "type": "image/webp",
    "etag": "\"4338c-elElHQRKCW9w9kuwARaURStnoSk\"",
    "mtime": "2026-08-16T15:35:45.236Z",
    "size": 275340,
    "path": "../public/projects/OrtoDiSantaChiara/images/mpv-shot0014.webp"
  },
  "/projects/OrtoDiSantaChiara/images/mpv-shot0015.webp": {
    "type": "image/webp",
    "etag": "\"3489c-R6Ryzqv1zaQrpm8g1ifnegJ2qFk\"",
    "mtime": "2026-08-16T15:35:45.442Z",
    "size": 215196,
    "path": "../public/projects/OrtoDiSantaChiara/images/mpv-shot0015.webp"
  },
  "/projects/OrtoDiSantaChiara/images/mpv-shot0016.webp": {
    "type": "image/webp",
    "etag": "\"4b560-Jz4w2Rm8uxs9ENa0z2J111ocbfU\"",
    "mtime": "2026-08-16T15:35:45.657Z",
    "size": 308576,
    "path": "../public/projects/OrtoDiSantaChiara/images/mpv-shot0016.webp"
  },
  "/projects/OrtoDiSantaChiara/images/mpv-shot0017.webp": {
    "type": "image/webp",
    "etag": "\"5a574-A4nxZus2Gxi79mMpETMBX+dWrTc\"",
    "mtime": "2026-08-16T15:35:45.886Z",
    "size": 370036,
    "path": "../public/projects/OrtoDiSantaChiara/images/mpv-shot0017.webp"
  },
  "/projects/OrtoDiSantaChiara/images/mpv-shot0018.webp": {
    "type": "image/webp",
    "etag": "\"4e09c-uRtQ1/HZ6zxR1pzk72pkI7+ZyRo\"",
    "mtime": "2026-08-16T15:35:46.108Z",
    "size": 319644,
    "path": "../public/projects/OrtoDiSantaChiara/images/mpv-shot0018.webp"
  },
  "/projects/OrtoDiSantaChiara/images/mpv-shot0020.webp": {
    "type": "image/webp",
    "etag": "\"34f0c-G+o1FHHLbRRz3sRoMlnfi7LA7eI\"",
    "mtime": "2026-08-16T15:35:46.536Z",
    "size": 216844,
    "path": "../public/projects/OrtoDiSantaChiara/images/mpv-shot0020.webp"
  },
  "/projects/OrtoDiSantaChiara/images/mpv-shot0019.webp": {
    "type": "image/webp",
    "etag": "\"77078-DsMAo+FcwOSduckXhkvg4KTE8+w\"",
    "mtime": "2026-08-16T15:35:46.346Z",
    "size": 487544,
    "path": "../public/projects/OrtoDiSantaChiara/images/mpv-shot0019.webp"
  },
  "/projects/OrtoDiSantaChiara/images/mpv-shot0021.webp": {
    "type": "image/webp",
    "etag": "\"67440-uj8GzzovuN/bMqN6RHUF6eVpQzM\"",
    "mtime": "2026-08-16T15:35:46.763Z",
    "size": 422976,
    "path": "../public/projects/OrtoDiSantaChiara/images/mpv-shot0021.webp"
  },
  "/projects/OrtoDiSantaChiara/images/mpv-shot0022.webp": {
    "type": "image/webp",
    "etag": "\"46c46-/k6BhJc0irMCIT5Dk9yajhch4pM\"",
    "mtime": "2026-08-16T15:35:46.973Z",
    "size": 289862,
    "path": "../public/projects/OrtoDiSantaChiara/images/mpv-shot0022.webp"
  },
  "/projects/OlioRoi_Rocks_Edit&SoundDesign/06_LAVORAZIONI_2.mp4": {
    "type": "video/mp4",
    "etag": "\"20733f5-f/0IrHtFsql9jWMypQVFBYQQP9U\"",
    "mtime": "2026-08-10T13:29:22.096Z",
    "size": 34026485,
    "path": "../public/projects/OlioRoi_Rocks_Edit&SoundDesign/06_LAVORAZIONI_2.mp4"
  },
  "/projects/OrtoDiSantaChiara/images/mpv-shot0023.webp": {
    "type": "image/webp",
    "etag": "\"43548-drKAfXzBrJRrjn1H5k2li1jySGc\"",
    "mtime": "2026-08-16T15:35:47.185Z",
    "size": 275784,
    "path": "../public/projects/OrtoDiSantaChiara/images/mpv-shot0023.webp"
  },
  "/projects/OrtoDiSantaChiara/images/mpv-shot0024.webp": {
    "type": "image/webp",
    "etag": "\"351ce-/skLkYC62GGGqKbuK3scwbX9JHs\"",
    "mtime": "2026-08-16T15:35:47.390Z",
    "size": 217550,
    "path": "../public/projects/OrtoDiSantaChiara/images/mpv-shot0024.webp"
  },
  "/projects/OrtoDiSantaChiara/images/mpv-shot0025.webp": {
    "type": "image/webp",
    "etag": "\"580ca-Lj+/oZcURH3U6oKrH1a0thzDrTM\"",
    "mtime": "2026-08-16T15:35:47.611Z",
    "size": 360650,
    "path": "../public/projects/OrtoDiSantaChiara/images/mpv-shot0025.webp"
  },
  "/projects/OrtoDiSantaChiara/images/mpv-shot0026.webp": {
    "type": "image/webp",
    "etag": "\"26e9c-cKtlIwTh+jQyVW6uyOAwL512vSE\"",
    "mtime": "2026-08-16T15:35:47.812Z",
    "size": 159388,
    "path": "../public/projects/OrtoDiSantaChiara/images/mpv-shot0026.webp"
  },
  "/projects/OrtoDiSantaChiara/images/mpv-shot0027.webp": {
    "type": "image/webp",
    "etag": "\"2f320-oN//oP03c01XszHRdm8XIgXR63k\"",
    "mtime": "2026-08-16T15:35:48.018Z",
    "size": 193312,
    "path": "../public/projects/OrtoDiSantaChiara/images/mpv-shot0027.webp"
  },
  "/projects/OrtoDiSantaChiara/images/mpv-shot0028.webp": {
    "type": "image/webp",
    "etag": "\"32742-xCZsJspW2nUticNsFilB+Zs+lkc\"",
    "mtime": "2026-08-16T15:35:48.222Z",
    "size": 206658,
    "path": "../public/projects/OrtoDiSantaChiara/images/mpv-shot0028.webp"
  },
  "/projects/OrtoDiSantaChiara/images/mpv-shot0029.webp": {
    "type": "image/webp",
    "etag": "\"3d234-BhOaAqD+OnEp/QdTpOruAXTGBVo\"",
    "mtime": "2026-08-16T15:35:48.441Z",
    "size": 250420,
    "path": "../public/projects/OrtoDiSantaChiara/images/mpv-shot0029.webp"
  },
  "/projects/OrtoDiSantaChiara/images/mpv-shot0030.webp": {
    "type": "image/webp",
    "etag": "\"56fe0-zZijiDLnxBz3yf734y3SHkRqeJ8\"",
    "mtime": "2026-08-16T15:35:48.674Z",
    "size": 356320,
    "path": "../public/projects/OrtoDiSantaChiara/images/mpv-shot0030.webp"
  },
  "/projects/OrtoDiSantaChiara/images/mpv-shot0031.webp": {
    "type": "image/webp",
    "etag": "\"440f4-/wNiQXykdmwQPNBecJKFbBOHHb8\"",
    "mtime": "2026-08-16T15:35:48.893Z",
    "size": 278772,
    "path": "../public/projects/OrtoDiSantaChiara/images/mpv-shot0031.webp"
  },
  "/projects/OrtoDiSantaChiara/images/mpv-shot0032.webp": {
    "type": "image/webp",
    "etag": "\"4edd0-UIcpQT9aB54/uOFYtvrRRRHWkNI\"",
    "mtime": "2026-08-16T15:35:49.118Z",
    "size": 323024,
    "path": "../public/projects/OrtoDiSantaChiara/images/mpv-shot0032.webp"
  },
  "/projects/OrtoDiSantaChiara/images/mpv-shot0033.webp": {
    "type": "image/webp",
    "etag": "\"4af84-5ybT22pFSs3hScC8EjeomzfPeJ4\"",
    "mtime": "2026-08-16T15:35:49.349Z",
    "size": 307076,
    "path": "../public/projects/OrtoDiSantaChiara/images/mpv-shot0033.webp"
  },
  "/projects/OrtoDiSantaChiara/images/mpv-shot0034.webp": {
    "type": "image/webp",
    "etag": "\"27458-iA5haUwAc0Px2BQ3irjRmTC4oRM\"",
    "mtime": "2026-08-16T15:35:49.547Z",
    "size": 160856,
    "path": "../public/projects/OrtoDiSantaChiara/images/mpv-shot0034.webp"
  },
  "/projects/OrtoDiSantaChiara/images/mpv-shot0035.webp": {
    "type": "image/webp",
    "etag": "\"264a4-YyTm9IhTvJ2FuJY5pJV5oVFcCss\"",
    "mtime": "2026-08-16T15:35:49.753Z",
    "size": 156836,
    "path": "../public/projects/OrtoDiSantaChiara/images/mpv-shot0035.webp"
  },
  "/projects/OrtoDiSantaChiara/images/mpv-shot0036.webp": {
    "type": "image/webp",
    "etag": "\"37bb2-v5ZUm6BD+MCOF6373ikb617puMI\"",
    "mtime": "2026-08-16T15:35:49.964Z",
    "size": 228274,
    "path": "../public/projects/OrtoDiSantaChiara/images/mpv-shot0036.webp"
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
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_11.webp": {
    "type": "image/webp",
    "etag": "\"bee6c-sgGLeW8qKSvFIvcU8a8nJ2hiGb4\"",
    "mtime": "2026-05-05T21:45:42.700Z",
    "size": 781932,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_11.webp"
  },
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_13.webp": {
    "type": "image/webp",
    "etag": "\"65c98-llWO0lyGevMk/gvVd4X8xSHwYD0\"",
    "mtime": "2026-05-05T21:45:43.297Z",
    "size": 416920,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_13.webp"
  },
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_12.webp": {
    "type": "image/webp",
    "etag": "\"9f072-85pO+SShlLqHMnqytZ6KUfIWrxo\"",
    "mtime": "2026-05-05T21:45:43.058Z",
    "size": 651378,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_12.webp"
  },
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_14.webp": {
    "type": "image/webp",
    "etag": "\"c5ad0-mAYHhbfFuzYG7sLQiwDrdkJnrPA\"",
    "mtime": "2026-05-05T21:45:43.570Z",
    "size": 809680,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_14.webp"
  },
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_15.webp": {
    "type": "image/webp",
    "etag": "\"966ac-oC2/SvUTq2boR4l0VRyt0eSwGyY\"",
    "mtime": "2026-05-05T21:45:43.815Z",
    "size": 616108,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_15.webp"
  },
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_16.webp": {
    "type": "image/webp",
    "etag": "\"bff88-kyi2i7/3CLJQ5qTZCmZMVPRANdg\"",
    "mtime": "2026-05-05T21:45:44.073Z",
    "size": 786312,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_16.webp"
  },
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_22.webp": {
    "type": "image/webp",
    "etag": "\"723a4-zHcAG45I9Pgor3Sw/VFdeS5/aII\"",
    "mtime": "2026-05-05T21:45:45.514Z",
    "size": 467876,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_22.webp"
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
  "/projects/OrtoDiSantaChiaraPhotos/images/convert_webp.bat": {
    "type": "application/x-msdownload",
    "etag": "\"5b-FnI4L+/MxPZobTbcU/PdtL+Lcqc\"",
    "mtime": "2026-08-30T13:39:42.702Z",
    "size": 91,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/images/convert_webp.bat"
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
  "/projects/OrtoDiSantaChiaraPhotos/images/P1012607.webp": {
    "type": "image/webp",
    "etag": "\"68720-WRyh4HJ1rfZR3mRakyh3nsRsQTY\"",
    "mtime": "2026-08-30T13:39:46.979Z",
    "size": 427808,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/images/P1012607.webp"
  },
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_4.webp": {
    "type": "image/webp",
    "etag": "\"9e5fc-yWiQBYT3amJPDgOqQcJ+lgiiYrs\"",
    "mtime": "2026-05-05T21:45:46.680Z",
    "size": 648700,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_4.webp"
  },
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_5.webp": {
    "type": "image/webp",
    "etag": "\"91e2a-6AeUDa87HD+wQZ6ha/UjWiiElBU\"",
    "mtime": "2026-05-05T21:45:46.914Z",
    "size": 597546,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_5.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/images/P1012610.webp": {
    "type": "image/webp",
    "etag": "\"6b410-aK2UZeYJgbLLPyEalsStvSg7yz8\"",
    "mtime": "2026-08-30T13:39:47.370Z",
    "size": 439312,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/images/P1012610.webp"
  },
  "/projects/Rigolizia-Mon-Amour/images/rigolizia_6.webp": {
    "type": "image/webp",
    "etag": "\"a33a6-wteMFqSoMNHPkCloLfX7qYSMh9s\"",
    "mtime": "2026-05-05T21:45:47.156Z",
    "size": 668582,
    "path": "../public/projects/Rigolizia-Mon-Amour/images/rigolizia_6.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/images/P1012611.webp": {
    "type": "image/webp",
    "etag": "\"7325c-0joaMON7INQaur3iXXaJGByLXqM\"",
    "mtime": "2026-08-30T13:39:47.768Z",
    "size": 471644,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/images/P1012611.webp"
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
  "/projects/OrtoDiSantaChiaraPhotos/images/P1012624.webp": {
    "type": "image/webp",
    "etag": "\"71646-NOFQz0vebl2XvbOqT52sGln/vyg\"",
    "mtime": "2026-08-30T13:39:48.221Z",
    "size": 464454,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/images/P1012624.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/images/P1012636.webp": {
    "type": "image/webp",
    "etag": "\"6c75c-5nq5mLQO926LY3/AYCXgf8M0RXw\"",
    "mtime": "2026-08-30T13:39:48.606Z",
    "size": 444252,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/images/P1012636.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/images/P1012630.webp": {
    "type": "image/webp",
    "etag": "\"920c8-TVI0Qw78O+Ti4EtIJj7NSzjS5kQ\"",
    "mtime": "2026-08-30T13:42:41.508Z",
    "size": 598216,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/images/P1012630.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/images/P1012684.webp": {
    "type": "image/webp",
    "etag": "\"738b6-Zz1hItiuve6a1gpV2+gErXn2Tkk\"",
    "mtime": "2026-08-30T13:39:50.922Z",
    "size": 473270,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/images/P1012684.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/images/P1012694.webp": {
    "type": "image/webp",
    "etag": "\"78eae-I5mUQdXytYf1w7JojWEXv8IFnxU\"",
    "mtime": "2026-08-30T13:39:51.847Z",
    "size": 495278,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/images/P1012694.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/images/P1012705.webp": {
    "type": "image/webp",
    "etag": "\"5c21c-L0vbRtpQd+RQbP65EpFzqHcKzjU\"",
    "mtime": "2026-08-30T13:39:52.279Z",
    "size": 377372,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/images/P1012705.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/images/P1012669.webp": {
    "type": "image/webp",
    "etag": "\"9d43c-xr1a1yxh8CjS5lQ2nDMSH6Rdm4E\"",
    "mtime": "2026-08-30T13:39:49.532Z",
    "size": 644156,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/images/P1012669.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/images/P1012646.webp": {
    "type": "image/webp",
    "etag": "\"ab886-BQfUtLqJUuGLoTMN5przAgNe96o\"",
    "mtime": "2026-08-30T13:39:49.070Z",
    "size": 702598,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/images/P1012646.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/images/P1012677.webp": {
    "type": "image/webp",
    "etag": "\"931ba-hzKzqN/btteyLDbpsh3fWzmjwwE\"",
    "mtime": "2026-08-30T13:39:50.471Z",
    "size": 602554,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/images/P1012677.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/images/P1012676.webp": {
    "type": "image/webp",
    "etag": "\"b7990-ysln08CBucYoHbosjGdB7U1lXEw\"",
    "mtime": "2026-08-30T13:39:49.999Z",
    "size": 752016,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/images/P1012676.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/images/P1012696.webp": {
    "type": "image/webp",
    "etag": "\"a025e-VOeNNEKsYHOR4RQMC7yt5q5634k\"",
    "mtime": "2026-08-30T13:42:41.982Z",
    "size": 655966,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/images/P1012696.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/photos_orto/convert_webp.bat": {
    "type": "application/x-msdownload",
    "etag": "\"5b-FnI4L+/MxPZobTbcU/PdtL+Lcqc\"",
    "mtime": "2026-08-30T13:39:42.702Z",
    "size": 91,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/photos_orto/convert_webp.bat"
  },
  "/projects/OrtoDiSantaChiaraPhotos/images/P1012747.webp": {
    "type": "image/webp",
    "etag": "\"7739e-9frjh28QVIIs5rHxQZgIE6bYEpI\"",
    "mtime": "2026-08-30T13:39:53.597Z",
    "size": 488350,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/images/P1012747.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012607.webp": {
    "type": "image/webp",
    "etag": "\"68720-WRyh4HJ1rfZR3mRakyh3nsRsQTY\"",
    "mtime": "2026-08-30T13:39:46.979Z",
    "size": 427808,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012607.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012610.webp": {
    "type": "image/webp",
    "etag": "\"6b410-aK2UZeYJgbLLPyEalsStvSg7yz8\"",
    "mtime": "2026-08-30T13:39:47.370Z",
    "size": 439312,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012610.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012611.webp": {
    "type": "image/webp",
    "etag": "\"7325c-0joaMON7INQaur3iXXaJGByLXqM\"",
    "mtime": "2026-08-30T13:39:47.768Z",
    "size": 471644,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012611.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012624.webp": {
    "type": "image/webp",
    "etag": "\"71646-NOFQz0vebl2XvbOqT52sGln/vyg\"",
    "mtime": "2026-08-30T13:39:48.221Z",
    "size": 464454,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012624.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012636.webp": {
    "type": "image/webp",
    "etag": "\"6c75c-5nq5mLQO926LY3/AYCXgf8M0RXw\"",
    "mtime": "2026-08-30T13:39:48.606Z",
    "size": 444252,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012636.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/images/P1012726.webp": {
    "type": "image/webp",
    "etag": "\"8e9ee-TRfo/fEMqgdaQcNYlFkWYr9r67c\"",
    "mtime": "2026-08-30T13:39:52.738Z",
    "size": 584174,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/images/P1012726.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/images/P1012734.webp": {
    "type": "image/webp",
    "etag": "\"946a8-wHWrpip/ChO0j5yeljUBBe/4N0o\"",
    "mtime": "2026-08-30T13:39:53.152Z",
    "size": 607912,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/images/P1012734.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/images/P1012752.webp": {
    "type": "image/webp",
    "etag": "\"9b134-DHPHtWon86XAWcVaH5RYiJDJ3a8\"",
    "mtime": "2026-08-30T13:39:54.068Z",
    "size": 635188,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/images/P1012752.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012630.webp": {
    "type": "image/webp",
    "etag": "\"920c8-TVI0Qw78O+Ti4EtIJj7NSzjS5kQ\"",
    "mtime": "2026-08-30T13:42:41.508Z",
    "size": 598216,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012630.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012646.webp": {
    "type": "image/webp",
    "etag": "\"ab886-BQfUtLqJUuGLoTMN5przAgNe96o\"",
    "mtime": "2026-08-30T13:39:49.070Z",
    "size": 702598,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012646.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012669.webp": {
    "type": "image/webp",
    "etag": "\"9d43c-xr1a1yxh8CjS5lQ2nDMSH6Rdm4E\"",
    "mtime": "2026-08-30T13:39:49.532Z",
    "size": 644156,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012669.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012684.webp": {
    "type": "image/webp",
    "etag": "\"738b6-Zz1hItiuve6a1gpV2+gErXn2Tkk\"",
    "mtime": "2026-08-30T13:39:50.922Z",
    "size": 473270,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012684.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012676.webp": {
    "type": "image/webp",
    "etag": "\"b7990-ysln08CBucYoHbosjGdB7U1lXEw\"",
    "mtime": "2026-08-30T13:39:49.999Z",
    "size": 752016,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012676.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012694.webp": {
    "type": "image/webp",
    "etag": "\"78eae-I5mUQdXytYf1w7JojWEXv8IFnxU\"",
    "mtime": "2026-08-30T13:39:51.847Z",
    "size": 495278,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012694.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012677.webp": {
    "type": "image/webp",
    "etag": "\"931ba-hzKzqN/btteyLDbpsh3fWzmjwwE\"",
    "mtime": "2026-08-30T13:39:50.471Z",
    "size": 602554,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012677.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012705.webp": {
    "type": "image/webp",
    "etag": "\"5c21c-L0vbRtpQd+RQbP65EpFzqHcKzjU\"",
    "mtime": "2026-08-30T13:39:52.279Z",
    "size": 377372,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012705.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012747.webp": {
    "type": "image/webp",
    "etag": "\"7739e-9frjh28QVIIs5rHxQZgIE6bYEpI\"",
    "mtime": "2026-08-30T13:39:53.597Z",
    "size": 488350,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012747.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012696.webp": {
    "type": "image/webp",
    "etag": "\"a025e-VOeNNEKsYHOR4RQMC7yt5q5634k\"",
    "mtime": "2026-08-30T13:42:41.982Z",
    "size": 655966,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012696.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012726.webp": {
    "type": "image/webp",
    "etag": "\"8e9ee-TRfo/fEMqgdaQcNYlFkWYr9r67c\"",
    "mtime": "2026-08-30T13:39:52.738Z",
    "size": 584174,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012726.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012734.webp": {
    "type": "image/webp",
    "etag": "\"946a8-wHWrpip/ChO0j5yeljUBBe/4N0o\"",
    "mtime": "2026-08-30T13:39:53.152Z",
    "size": 607912,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012734.webp"
  },
  "/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012752.webp": {
    "type": "image/webp",
    "etag": "\"9b134-DHPHtWon86XAWcVaH5RYiJDJ3a8\"",
    "mtime": "2026-08-30T13:39:54.068Z",
    "size": 635188,
    "path": "../public/projects/OrtoDiSantaChiaraPhotos/photos_orto/P1012752.webp"
  },
  "/projects/Roma/images/roma_2026_104.webp": {
    "type": "image/webp",
    "etag": "\"e4c54-z53Z4x9uGqy66UbT3e6vMwaEXew\"",
    "mtime": "2026-05-05T19:34:18.033Z",
    "size": 937044,
    "path": "../public/projects/Roma/images/roma_2026_104.webp"
  },
  "/projects/Roma/images/roma_2026_132.webp": {
    "type": "image/webp",
    "etag": "\"b4932-s23NGZFE4Lbs8gaGmSNsp5nMlcg\"",
    "mtime": "2026-05-05T19:34:18.064Z",
    "size": 739634,
    "path": "../public/projects/Roma/images/roma_2026_132.webp"
  },
  "/projects/Roma/images/roma_2026_121.webp": {
    "type": "image/webp",
    "etag": "\"f8148-WYG8Cnh3lMWt49jFVFYQqCbNTkM\"",
    "mtime": "2026-05-05T19:34:18.055Z",
    "size": 1016136,
    "path": "../public/projects/Roma/images/roma_2026_121.webp"
  },
  "/projects/Roma/images/roma_2026_15.webp": {
    "type": "image/webp",
    "etag": "\"e741c-GEmyqNpPD+3LFt6sw0J7BztZ6nY\"",
    "mtime": "2026-05-05T19:34:18.087Z",
    "size": 947228,
    "path": "../public/projects/Roma/images/roma_2026_15.webp"
  },
  "/projects/Roma/images/roma_2026_151.webp": {
    "type": "image/webp",
    "etag": "\"e6f70-GBUSN8jI8ZP2AMjK+b8a++P5+8o\"",
    "mtime": "2026-05-05T19:34:18.095Z",
    "size": 946032,
    "path": "../public/projects/Roma/images/roma_2026_151.webp"
  },
  "/projects/Roma/images/roma_2026_16.webp": {
    "type": "image/webp",
    "etag": "\"ebf08-GjJN/yGrV7A5gMMxh8xjuFFwv6w\"",
    "mtime": "2026-05-05T19:34:18.118Z",
    "size": 966408,
    "path": "../public/projects/Roma/images/roma_2026_16.webp"
  },
  "/projects/Roma/images/roma_2026_167.webp": {
    "type": "image/webp",
    "etag": "\"c55b6-atuoWOSVFDjekLsXNAdnccnkoTg\"",
    "mtime": "2026-05-05T19:34:18.125Z",
    "size": 808374,
    "path": "../public/projects/Roma/images/roma_2026_167.webp"
  },
  "/projects/Roma/images/roma_2026_114.webp": {
    "type": "image/webp",
    "etag": "\"135752-UIHtUwsnhIxvZPZfz8Pc0sv6XcM\"",
    "mtime": "2026-05-05T19:34:18.045Z",
    "size": 1267538,
    "path": "../public/projects/Roma/images/roma_2026_114.webp"
  },
  "/projects/Roma/images/roma_2026_168.webp": {
    "type": "image/webp",
    "etag": "\"c7b80-GnXaXQY943IJNE7rF5ZLlFPkbKg\"",
    "mtime": "2026-05-05T19:34:18.135Z",
    "size": 818048,
    "path": "../public/projects/Roma/images/roma_2026_168.webp"
  },
  "/projects/Roma/images/roma_2026_140.webp": {
    "type": "image/webp",
    "etag": "\"11630a-upL4yHROcEI658k+b8OLy9RTYL4\"",
    "mtime": "2026-05-05T19:34:18.077Z",
    "size": 1139466,
    "path": "../public/projects/Roma/images/roma_2026_140.webp"
  },
  "/projects/Roma/images/roma_2026_173.webp": {
    "type": "image/webp",
    "etag": "\"bfe9a-39THK/GgLQFzcVP7+JaFIjEMoOU\"",
    "mtime": "2026-05-05T19:34:18.144Z",
    "size": 786074,
    "path": "../public/projects/Roma/images/roma_2026_173.webp"
  },
  "/projects/Roma/images/roma_2026_153.webp": {
    "type": "image/webp",
    "etag": "\"102a04-qPQKkglY205DQg15P5DMqH6b8mE\"",
    "mtime": "2026-05-05T19:34:18.107Z",
    "size": 1059332,
    "path": "../public/projects/Roma/images/roma_2026_153.webp"
  },
  "/projects/Roma/images/roma_2026_18.webp": {
    "type": "image/webp",
    "etag": "\"10fb7a-W3TjXwtW+HDNEb0MWPG8Tzh3zxQ\"",
    "mtime": "2026-05-05T19:34:18.155Z",
    "size": 1112954,
    "path": "../public/projects/Roma/images/roma_2026_18.webp"
  },
  "/projects/Roma/images/roma_2026_198.webp": {
    "type": "image/webp",
    "etag": "\"c9838-p7+Td8dTQwjZYP9QY/zdGhs0SfY\"",
    "mtime": "2026-05-05T19:34:18.202Z",
    "size": 825400,
    "path": "../public/projects/Roma/images/roma_2026_198.webp"
  },
  "/projects/Roma/images/roma_2026_187.webp": {
    "type": "image/webp",
    "etag": "\"17c9b4-vynKO4OS6rzG6rlDr6TOHcr3XMw\"",
    "mtime": "2026-05-05T19:34:18.169Z",
    "size": 1558964,
    "path": "../public/projects/Roma/images/roma_2026_187.webp"
  },
  "/projects/Roma/images/roma_2026_203.webp": {
    "type": "image/webp",
    "etag": "\"bde6a-0zy+W6HV+zqruYapoyFeHr6HVDs\"",
    "mtime": "2026-05-05T19:34:18.212Z",
    "size": 777834,
    "path": "../public/projects/Roma/images/roma_2026_203.webp"
  },
  "/projects/Roma/images/roma_2026_204.webp": {
    "type": "image/webp",
    "etag": "\"cdd70-XkC1BdNgZT5aZXM5aZ9v13fwImc\"",
    "mtime": "2026-05-05T19:34:18.221Z",
    "size": 843120,
    "path": "../public/projects/Roma/images/roma_2026_204.webp"
  },
  "/projects/Roma/images/roma_2026_188.webp": {
    "type": "image/webp",
    "etag": "\"1608a2-8H69bUZ0PXs40wf9N1n6C5FzwmA\"",
    "mtime": "2026-05-05T19:34:18.182Z",
    "size": 1444002,
    "path": "../public/projects/Roma/images/roma_2026_188.webp"
  },
  "/projects/Roma/images/roma_2026_189.webp": {
    "type": "image/webp",
    "etag": "\"106bbe-3DLZpGuY8m9TYOiPSfZRzd10f/M\"",
    "mtime": "2026-05-05T19:34:18.194Z",
    "size": 1076158,
    "path": "../public/projects/Roma/images/roma_2026_189.webp"
  },
  "/projects/Roma/images/roma_2026_218.webp": {
    "type": "image/webp",
    "etag": "\"f87b0-3Ph1/duhl9jPyM8NUCk8EKFaNiQ\"",
    "mtime": "2026-05-05T19:34:18.233Z",
    "size": 1017776,
    "path": "../public/projects/Roma/images/roma_2026_218.webp"
  },
  "/projects/Roma/images/roma_2026_22.webp": {
    "type": "image/webp",
    "etag": "\"f01f2-YdIHuVewkiVDYmcE6AjY6vdjbek\"",
    "mtime": "2026-05-05T19:34:18.244Z",
    "size": 983538,
    "path": "../public/projects/Roma/images/roma_2026_22.webp"
  },
  "/projects/Roma/images/roma_2026_220.webp": {
    "type": "image/webp",
    "etag": "\"a7c20-3PTq6otuKTORiaOYVhGsOQZ7AuE\"",
    "mtime": "2026-05-05T19:34:18.252Z",
    "size": 687136,
    "path": "../public/projects/Roma/images/roma_2026_220.webp"
  },
  "/projects/Roma/images/roma_2026_23.webp": {
    "type": "image/webp",
    "etag": "\"e9d76-OTHiP3Tm3/UUCzX6ouGIogTHNe0\"",
    "mtime": "2026-05-05T19:34:18.262Z",
    "size": 957814,
    "path": "../public/projects/Roma/images/roma_2026_23.webp"
  },
  "/projects/Roma/images/roma_2026_235.webp": {
    "type": "image/webp",
    "etag": "\"ec1fc-fb6729AabNE1rFc76lMBX8vlx1U\"",
    "mtime": "2026-05-05T19:34:18.273Z",
    "size": 967164,
    "path": "../public/projects/Roma/images/roma_2026_235.webp"
  },
  "/projects/Roma/images/roma_2026_266.webp": {
    "type": "image/webp",
    "etag": "\"d7b62-oaNNjg5XYlW1x62Lgwb9SEb7ieM\"",
    "mtime": "2026-05-05T19:34:18.282Z",
    "size": 883554,
    "path": "../public/projects/Roma/images/roma_2026_266.webp"
  },
  "/projects/Roma/images/roma_2026_272.webp": {
    "type": "image/webp",
    "etag": "\"ff14c-ebQ/WW51FPWIfHOtotdfLhergQQ\"",
    "mtime": "2026-05-05T19:34:18.294Z",
    "size": 1044812,
    "path": "../public/projects/Roma/images/roma_2026_272.webp"
  },
  "/projects/Roma/images/roma_2026_279.webp": {
    "type": "image/webp",
    "etag": "\"d61c6-Vk56pgHngNGOvqeY189CQQph6yg\"",
    "mtime": "2026-05-05T19:34:18.304Z",
    "size": 876998,
    "path": "../public/projects/Roma/images/roma_2026_279.webp"
  },
  "/projects/Roma/images/roma_2026_288.webp": {
    "type": "image/webp",
    "etag": "\"c2fc4-9vHfsDp0twK8nQ/n/2Bmki1mj5w\"",
    "mtime": "2026-05-05T19:34:18.312Z",
    "size": 798660,
    "path": "../public/projects/Roma/images/roma_2026_288.webp"
  },
  "/projects/Roma/images/roma_2026_291.webp": {
    "type": "image/webp",
    "etag": "\"ea260-k6L9VZfC8+9T4W1b7SotfPjA6tA\"",
    "mtime": "2026-05-05T19:34:18.337Z",
    "size": 959072,
    "path": "../public/projects/Roma/images/roma_2026_291.webp"
  },
  "/projects/Roma/images/roma_2026_297.webp": {
    "type": "image/webp",
    "etag": "\"df80c-qdCEkiUHPTXmL7xudnloel+4uwg\"",
    "mtime": "2026-05-05T19:34:18.345Z",
    "size": 915468,
    "path": "../public/projects/Roma/images/roma_2026_297.webp"
  },
  "/projects/Roma/images/roma_2026_298.webp": {
    "type": "image/webp",
    "etag": "\"e49a8-25GOS9NjOwPziJ7sV6GnQxrSG1Y\"",
    "mtime": "2026-05-05T19:34:18.358Z",
    "size": 936360,
    "path": "../public/projects/Roma/images/roma_2026_298.webp"
  },
  "/projects/Roma/images/roma_2026_313.webp": {
    "type": "image/webp",
    "etag": "\"ea360-CVW5fbH6+8SpeyxfhmnSYoMLhmY\"",
    "mtime": "2026-05-05T19:34:18.406Z",
    "size": 959328,
    "path": "../public/projects/Roma/images/roma_2026_313.webp"
  },
  "/projects/Roma/images/roma_2026_290.webp": {
    "type": "image/webp",
    "etag": "\"12c326-FyR0aa7v1rQ6S/5ILDetqR+lwCs\"",
    "mtime": "2026-05-05T19:34:18.325Z",
    "size": 1229606,
    "path": "../public/projects/Roma/images/roma_2026_290.webp"
  },
  "/projects/Roma/images/roma_2026_315.webp": {
    "type": "image/webp",
    "etag": "\"aedf2-og3ctDZFwySJB3aoMPJRk4RkMGE\"",
    "mtime": "2026-05-05T19:34:18.414Z",
    "size": 716274,
    "path": "../public/projects/Roma/images/roma_2026_315.webp"
  },
  "/projects/Roma/images/roma_2026_30.webp": {
    "type": "image/webp",
    "etag": "\"10e08e-WMmYhkEApYmmu5/pKwFQhZuLEC8\"",
    "mtime": "2026-05-05T19:34:18.370Z",
    "size": 1106062,
    "path": "../public/projects/Roma/images/roma_2026_30.webp"
  },
  "/projects/Roma/images/roma_2026_303.webp": {
    "type": "image/webp",
    "etag": "\"108174-uAjMxdH4EuKexsof0/6CmxqLRrw\"",
    "mtime": "2026-05-05T19:34:18.381Z",
    "size": 1081716,
    "path": "../public/projects/Roma/images/roma_2026_303.webp"
  },
  "/projects/Roma/images/roma_2026_31.webp": {
    "type": "image/webp",
    "etag": "\"160378-oBOb/DTqQ0SzGqboRvOoTO3f7Lw\"",
    "mtime": "2026-05-05T19:34:18.395Z",
    "size": 1442680,
    "path": "../public/projects/Roma/images/roma_2026_31.webp"
  },
  "/projects/Roma/images/roma_2026_320.webp": {
    "type": "image/webp",
    "etag": "\"c6720-KcI0yUFpLroA1sRLwJ43aH8KySc\"",
    "mtime": "2026-05-05T19:34:18.425Z",
    "size": 812832,
    "path": "../public/projects/Roma/images/roma_2026_320.webp"
  },
  "/projects/Roma/images/roma_2026_321.webp": {
    "type": "image/webp",
    "etag": "\"ce06e-9lSfxaO5XnI6Xv3d2nK6Hcjea+w\"",
    "mtime": "2026-05-05T19:34:18.433Z",
    "size": 843886,
    "path": "../public/projects/Roma/images/roma_2026_321.webp"
  },
  "/projects/Roma/images/roma_2026_322.webp": {
    "type": "image/webp",
    "etag": "\"9de60-k9q9nVjUwvityNnqE1tboJcRW8o\"",
    "mtime": "2026-05-05T19:34:18.442Z",
    "size": 646752,
    "path": "../public/projects/Roma/images/roma_2026_322.webp"
  },
  "/projects/Roma/images/roma_2026_329.webp": {
    "type": "image/webp",
    "etag": "\"c4044-34fRXxC/OYpsETMGEJCK5HrrhJ4\"",
    "mtime": "2026-05-05T19:34:18.451Z",
    "size": 802884,
    "path": "../public/projects/Roma/images/roma_2026_329.webp"
  },
  "/projects/Roma/images/roma_2026_64.webp": {
    "type": "image/webp",
    "etag": "\"f6086-qbZx9qF3nTfb6IF27XCwAFiCLU0\"",
    "mtime": "2026-05-05T19:34:18.485Z",
    "size": 1007750,
    "path": "../public/projects/Roma/images/roma_2026_64.webp"
  },
  "/projects/Roma/images/roma_2026_72.webp": {
    "type": "image/webp",
    "etag": "\"ef19a-zDC2af4cT9rHfGka3bsuOo6qs4k\"",
    "mtime": "2026-05-05T19:34:18.507Z",
    "size": 979354,
    "path": "../public/projects/Roma/images/roma_2026_72.webp"
  },
  "/projects/Roma/images/roma_2026_33.webp": {
    "type": "image/webp",
    "etag": "\"106696-60+8Vn4+yOKhtqNGeJ4ycLgvaEo\"",
    "mtime": "2026-05-05T19:34:18.463Z",
    "size": 1074838,
    "path": "../public/projects/Roma/images/roma_2026_33.webp"
  },
  "/projects/Roma/images/roma_2026_80.webp": {
    "type": "image/webp",
    "etag": "\"c9682-Mqx25uNre2fEjlolScgqTREsW1M\"",
    "mtime": "2026-05-05T19:34:18.514Z",
    "size": 824962,
    "path": "../public/projects/Roma/images/roma_2026_80.webp"
  },
  "/projects/Roma/images/roma_2026_36.webp": {
    "type": "image/webp",
    "etag": "\"124d44-9lQGBQPERaPY+gntuFCfgCMs668\"",
    "mtime": "2026-05-05T19:34:18.471Z",
    "size": 1199428,
    "path": "../public/projects/Roma/images/roma_2026_36.webp"
  },
  "/projects/Roma/images/roma_2026_82.webp": {
    "type": "image/webp",
    "etag": "\"da4ac-/lMaD0RJQJ9fHCi13JIw2iYNoT0\"",
    "mtime": "2026-05-05T19:34:18.525Z",
    "size": 894124,
    "path": "../public/projects/Roma/images/roma_2026_82.webp"
  },
  "/projects/Roma/images/roma_2026_70.webp": {
    "type": "image/webp",
    "etag": "\"115bfc-BIdb+VoxwjGl6q0I9IdnNXBgIFA\"",
    "mtime": "2026-05-05T19:34:18.495Z",
    "size": 1137660,
    "path": "../public/projects/Roma/images/roma_2026_70.webp"
  },
  "/projects/Roma/images/roma_2026_leica_46.webp": {
    "type": "image/webp",
    "etag": "\"1dd1b2-Z4QqAuU42WiOx8xHuLro7hoTJ2g\"",
    "mtime": "2026-05-05T19:34:18.595Z",
    "size": 1954226,
    "path": "../public/projects/Roma/images/roma_2026_leica_46.webp"
  },
  "/projects/Roma/images/roma_2026_leica_56.webp": {
    "type": "image/webp",
    "etag": "\"1f6068-wP4OAip6tF72eB0j/H1XVHSMNW4\"",
    "mtime": "2026-05-05T19:34:18.631Z",
    "size": 2056296,
    "path": "../public/projects/Roma/images/roma_2026_leica_56.webp"
  },
  "/projects/Roma/images/roma_2026_leica_13.webp": {
    "type": "image/webp",
    "etag": "\"23da60-9spcCLAvzxf2j0otqMeev1rYkO0\"",
    "mtime": "2026-05-05T19:34:18.544Z",
    "size": 2349664,
    "path": "../public/projects/Roma/images/roma_2026_leica_13.webp"
  },
  "/projects/Roma/images/roma_2026_leica_17.webp": {
    "type": "image/webp",
    "etag": "\"229382-Aqy6Mp9uT96FB9nakEvKIgbi09k\"",
    "mtime": "2026-05-05T19:34:18.562Z",
    "size": 2265986,
    "path": "../public/projects/Roma/images/roma_2026_leica_17.webp"
  },
  "/projects/Roma/images/roma_2026_leica_7.webp": {
    "type": "image/webp",
    "etag": "\"1fc5ca-E117FHxuXmPBADRjZc1DT4Au9xY\"",
    "mtime": "2026-05-05T19:34:18.649Z",
    "size": 2082250,
    "path": "../public/projects/Roma/images/roma_2026_leica_7.webp"
  },
  "/projects/Roma/images/roma_2026_leica_45.webp": {
    "type": "image/webp",
    "etag": "\"201458-71mhhHpmNFDTQHonKKLGXMWLsb8\"",
    "mtime": "2026-05-05T19:34:18.580Z",
    "size": 2102360,
    "path": "../public/projects/Roma/images/roma_2026_leica_45.webp"
  },
  "/projects/Roma/images/roma_2026_leica_81.webp": {
    "type": "image/webp",
    "etag": "\"1f63c8-bF2lX88o/15vAYE5HbZ6rh7m5gE\"",
    "mtime": "2026-05-05T19:34:18.681Z",
    "size": 2057160,
    "path": "../public/projects/Roma/images/roma_2026_leica_81.webp"
  },
  "/projects/Roma/images/roma_2026_leica_89.webp": {
    "type": "image/webp",
    "etag": "\"1b5010-FNGrFJK8z+SeXAJboSs9Oe4n9as\"",
    "mtime": "2026-05-05T19:34:18.698Z",
    "size": 1789968,
    "path": "../public/projects/Roma/images/roma_2026_leica_89.webp"
  },
  "/projects/Roma/images/roma_2026_leica_47.webp": {
    "type": "image/webp",
    "etag": "\"215aa2-09bZAIKhd6JrTSo3UQ9sACFRTr8\"",
    "mtime": "2026-05-05T19:34:18.612Z",
    "size": 2185890,
    "path": "../public/projects/Roma/images/roma_2026_leica_47.webp"
  },
  "/projects/Roma/images/roma_2026_leica_78.webp": {
    "type": "image/webp",
    "etag": "\"21a28c-eSH79C3PjGOaqhuieokTrsIePb0\"",
    "mtime": "2026-05-05T19:34:18.664Z",
    "size": 2204300,
    "path": "../public/projects/Roma/images/roma_2026_leica_78.webp"
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

const _lazy_OH1ZS_ = () => import('../routes/api/s3-photos.get.mjs');
const _lazy_tlyLMH = () => import('../routes/renderer.mjs').then(function (n) { return n.r; });

const handlers = [
  { route: '', handler: _wjVw8s, lazy: false, middleware: true, method: undefined },
  { route: '/api/s3-photos', handler: _lazy_OH1ZS_, lazy: true, middleware: false, method: "get" },
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

export { $fetch as $, createHooks as A, executeAsync as B, withLeadingSlash as C, encodeParam as D, parseQuery as E, withTrailingSlash as F, withoutTrailingSlash as G, trapUnhandledNodeErrors as a, useNitroApp as b, defineEventHandler as c, destr as d, buildAssetsURL as e, getResponseStatusText as f, getQuery as g, getResponseStatus as h, encodePath as i, defineRenderHandler as j, createError$1 as k, getRouteRules as l, joinURL as m, parseURL as n, decodePath as o, publicAssetsURL as p, hasProtocol as q, isScriptProtocol as r, setupGracefulShutdown as s, toNodeListener as t, useRuntimeConfig as u, sanitizeStatusCode as v, withQuery as w, getContext as x, baseURL as y, defu as z };
//# sourceMappingURL=nitro.mjs.map
