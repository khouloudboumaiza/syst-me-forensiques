globalThis.__nitro_main__ = import.meta.url;
import { a as FastResponse, n as HTTPError, r as defineLazyEventHandler, t as H3Core } from "./_libs/h3+rou3+srvx.mjs";
import { t as HookableCore } from "./_libs/hookable.mjs";
//#region #nitro-vite-setup
function lazyService(loader) {
	let promise, mod;
	return { fetch(req) {
		if (mod) return mod.fetch(req);
		if (!promise) promise = loader().then((_mod) => mod = _mod.default || _mod);
		return promise.then((mod) => mod.fetch(req));
	} };
}
var services = { ["ssr"]: lazyService(() => import("./_ssr/ssr.mjs")) };
globalThis.__nitro_vite_envs__ = services;
//#endregion
//#region #nitro/virtual/public-assets-data
var public_assets_data_default = {
	"/favicon.ico": {
		"type": "image/vnd.microsoft.icon",
		"etag": "\"4f95-3RXc3p2mhEAs1WBwaIvE0Y0uu0Y\"",
		"mtime": "2026-07-01T14:16:55.845Z",
		"size": 20373,
		"path": "../public/favicon.ico"
	},
	"/assets/alerts-X0q252GA.js": {
		"type": "text/javascript; charset=utf-8",
		"etag": "\"1b14-7kJYCUuf3oAV/AfA4YVDJ8bjo8k\"",
		"mtime": "2026-07-11T15:20:01.903Z",
		"size": 6932,
		"path": "../public/assets/alerts-X0q252GA.js"
	},
	"/assets/app-shell-BTLS-qXU.js": {
		"type": "text/javascript; charset=utf-8",
		"etag": "\"745c-aoLKR9mKImjMsDf/brTo+ApTTpQ\"",
		"mtime": "2026-07-11T15:20:01.903Z",
		"size": 29788,
		"path": "../public/assets/app-shell-BTLS-qXU.js"
	},
	"/assets/arrow-up-right-DumjVE3E.js": {
		"type": "text/javascript; charset=utf-8",
		"etag": "\"a0-nENaNfJMqDAxPQULRk5bvoYaCMQ\"",
		"mtime": "2026-07-11T15:20:01.903Z",
		"size": 160,
		"path": "../public/assets/arrow-up-right-DumjVE3E.js"
	},
	"/assets/artifacts-DruUM0kv.js": {
		"type": "text/javascript; charset=utf-8",
		"etag": "\"dac-zz1v4UyczVJ45Np+7p2MvYA6IBM\"",
		"mtime": "2026-07-11T15:20:01.905Z",
		"size": 3500,
		"path": "../public/assets/artifacts-DruUM0kv.js"
	},
	"/assets/clock-BhyWwt4P.js": {
		"type": "text/javascript; charset=utf-8",
		"etag": "\"a2-cNLqhhKa4vJbreJGLBJw60+urhc\"",
		"mtime": "2026-07-11T15:20:01.906Z",
		"size": 162,
		"path": "../public/assets/clock-BhyWwt4P.js"
	},
	"/assets/circle-x-Dgjto5jP.js": {
		"type": "text/javascript; charset=utf-8",
		"etag": "\"145-aoiWlumflUm9HmmHEll7cAW29ck\"",
		"mtime": "2026-07-11T15:20:01.905Z",
		"size": 325,
		"path": "../public/assets/circle-x-Dgjto5jP.js"
	},
	"/assets/correlations-B7waes8M.js": {
		"type": "text/javascript; charset=utf-8",
		"etag": "\"1bf4-AA61opuSnTG9R9kW00m08NTbyLU\"",
		"mtime": "2026-07-11T15:20:01.906Z",
		"size": 7156,
		"path": "../public/assets/correlations-B7waes8M.js"
	},
	"/assets/funnel-vFmmJeIU.js": {
		"type": "text/javascript; charset=utf-8",
		"etag": "\"f9-9+h92YIGxzyOeiyn42YBPa+bIQs\"",
		"mtime": "2026-07-11T15:20:01.906Z",
		"size": 249,
		"path": "../public/assets/funnel-vFmmJeIU.js"
	},
	"/assets/loader-circle-C3UHMF5j.js": {
		"type": "text/javascript; charset=utf-8",
		"etag": "\"89-2Dq7/FhxwYfGlcdDDUHHl/Tlxh0\"",
		"mtime": "2026-07-11T15:20:01.907Z",
		"size": 137,
		"path": "../public/assets/loader-circle-C3UHMF5j.js"
	},
	"/assets/iocs-o0xxc58a.js": {
		"type": "text/javascript; charset=utf-8",
		"etag": "\"28d6-ZGNX3LUIfdFdcHqbCSXTbsTCbYA\"",
		"mtime": "2026-07-11T15:20:01.906Z",
		"size": 10454,
		"path": "../public/assets/iocs-o0xxc58a.js"
	},
	"/assets/reports-CbDppXdA.js": {
		"type": "text/javascript; charset=utf-8",
		"etag": "\"63cd-ed+2QrwedJVk+wCJNn8DkAp/R5E\"",
		"mtime": "2026-07-11T15:20:01.908Z",
		"size": 25549,
		"path": "../public/assets/reports-CbDppXdA.js"
	},
	"/assets/sparkles-Dzu2PlOq.js": {
		"type": "text/javascript; charset=utf-8",
		"etag": "\"1e7-L2j+WXv+8KWM05ZYoHIT+LTTIiw\"",
		"mtime": "2026-07-11T15:20:01.909Z",
		"size": 487,
		"path": "../public/assets/sparkles-Dzu2PlOq.js"
	},
	"/assets/styles-C-T-n6XQ.css": {
		"type": "text/css; charset=utf-8",
		"etag": "\"17d38-M3G8P+V//v7vGx7nRircKJgIgWw\"",
		"mtime": "2026-07-11T15:20:01.912Z",
		"size": 97592,
		"path": "../public/assets/styles-C-T-n6XQ.css"
	},
	"/assets/triangle-alert-CyRN40Fi.js": {
		"type": "text/javascript; charset=utf-8",
		"etag": "\"102-ZkGsYsxUtW+dvamEhc4fK9mVqpg\"",
		"mtime": "2026-07-11T15:20:01.910Z",
		"size": 258,
		"path": "../public/assets/triangle-alert-CyRN40Fi.js"
	},
	"/assets/index-BNm-5eCw.js": {
		"type": "text/javascript; charset=utf-8",
		"etag": "\"54cba-SBg26H3clbEGGAb2jzYAWvnnD3E\"",
		"mtime": "2026-07-11T15:20:01.902Z",
		"size": 347322,
		"path": "../public/assets/index-BNm-5eCw.js"
	},
	"/assets/timeline-BOMx7Mdr.js": {
		"type": "text/javascript; charset=utf-8",
		"etag": "\"1a1a-S37n6ioghdzPLdQtmCW+BIAJo0k\"",
		"mtime": "2026-07-11T15:20:01.909Z",
		"size": 6682,
		"path": "../public/assets/timeline-BOMx7Mdr.js"
	},
	"/assets/shield-CgN0Aqq0.js": {
		"type": "text/javascript; charset=utf-8",
		"etag": "\"1c6-kO359Fnh+e/2efblFR90BSqIqhM\"",
		"mtime": "2026-07-11T15:20:01.909Z",
		"size": 454,
		"path": "../public/assets/shield-CgN0Aqq0.js"
	},
	"/assets/upload-CwD-GR3a.js": {
		"type": "text/javascript; charset=utf-8",
		"etag": "\"2321-jRX6Q6NOnqdv3VwuNMGVr9UMMPU\"",
		"mtime": "2026-07-11T15:20:01.911Z",
		"size": 8993,
		"path": "../public/assets/upload-CwD-GR3a.js"
	},
	"/assets/routes-DeERSCVj.js": {
		"type": "text/javascript; charset=utf-8",
		"etag": "\"65a36-C0syGpIoFEzOoarg70TtnBxsTEU\"",
		"mtime": "2026-07-11T15:20:01.908Z",
		"size": 416310,
		"path": "../public/assets/routes-DeERSCVj.js"
	}
};
//#endregion
//#region #nitro/virtual/public-assets
var publicAssetBases = {};
function isPublicAssetURL(id = "") {
	if (public_assets_data_default[id]) return true;
	for (const base in publicAssetBases) if (id.startsWith(base)) return true;
	return false;
}
//#endregion
//#region node_modules/nitro/dist/runtime/internal/route-rules.mjs
var headers = ((m) => function headersRouteRule(event) {
	for (const [key, value] of Object.entries(m.options || {})) event.res.headers.set(key, value);
});
//#endregion
//#region #nitro/virtual/routing
var findRouteRules = /* @__PURE__ */ (() => {
	const $0 = [{
		name: "headers",
		route: "/assets/**",
		handler: headers,
		options: { "cache-control": "public, max-age=31536000, immutable" }
	}];
	return (m, p) => {
		let r = [];
		if (p.charCodeAt(p.length - 1) === 47) p = p.slice(0, -1) || "/";
		let s = p.split("/");
		if (s.length > 1) {
			if (s[1] === "assets") r.unshift({
				data: $0,
				params: { "_": s.slice(2).join("/") }
			});
		}
		return r;
	};
})();
var _lazy__K_6Lt = defineLazyEventHandler(() => import("./_chunks/ssr-renderer.mjs"));
var findRoute = /* @__PURE__ */ (() => {
	const data = {
		route: "/**",
		handler: _lazy__K_6Lt
	};
	return ((_m, p) => {
		return {
			data,
			params: { "_": p.slice(1) }
		};
	});
})();
[].filter(Boolean);
//#endregion
//#region node_modules/nitro/dist/runtime/internal/error/prod.mjs
var errorHandler = (error, event) => {
	const res = defaultHandler(error, event);
	return new FastResponse(typeof res.body === "string" ? res.body : JSON.stringify(res.body, null, 2), res);
};
function defaultHandler(error, event) {
	const unhandled = error.unhandled ?? !HTTPError.isError(error);
	const { status = 500, statusText = "" } = unhandled ? {} : error;
	if (status === 404) {
		const url = event.url || new URL(event.req.url);
		const baseURL = "/";
		if (/^\/[^/]/.test(baseURL) && !url.pathname.startsWith(baseURL)) return {
			status: 302,
			headers: new Headers({ location: `${baseURL}${url.pathname.slice(1)}${url.search}` })
		};
	}
	const headers = new Headers(unhandled ? {} : error.headers);
	headers.set("content-type", "application/json; charset=utf-8");
	return {
		status,
		statusText,
		headers,
		body: {
			error: true,
			...unhandled ? {
				status,
				unhandled: true
			} : typeof error.toJSON === "function" ? error.toJSON() : {
				status,
				statusText,
				message: error.message
			}
		}
	};
}
//#endregion
//#region #nitro/virtual/error-handler
var errorHandlers = [errorHandler];
async function error_handler_default(error, event) {
	for (const handler of errorHandlers) try {
		const response = await handler(error, event, { defaultHandler });
		if (response) return response;
	} catch (error) {
		console.error(error);
	}
}
//#endregion
//#region #nitro/virtual/app
function createNitroApp() {
	const captureError = (error, errorCtx) => {
		if (errorCtx?.event) {
			const errors = errorCtx.event.req.context?.nitro?.errors;
			if (errors) errors.push({
				error,
				context: errorCtx
			});
		}
	};
	const h3App = createH3App({ onError(error, event) {
		return error_handler_default(error, event);
	} });
	let appHandler = (req) => {
		req.context ||= {};
		req.context.nitro = req.context.nitro || { errors: [] };
		return h3App.fetch(req);
	};
	return {
		fetch: appHandler,
		h3: h3App,
		hooks: void 0,
		captureError
	};
}
function createH3App(config) {
	const h3App = new H3Core(config);
	h3App["~findRoute"] = (event) => findRoute(event.req.method, event.url.pathname);
	h3App["~getMiddleware"] = (event, route) => {
		const pathname = event.url.pathname;
		const method = event.req.method;
		const middleware = [];
		const routeRules = getRouteRules(method, pathname);
		event.context.routeRules = routeRules?.routeRules;
		if (routeRules?.routeRuleMiddleware.length) middleware.push(...routeRules.routeRuleMiddleware);
		if (route?.data?.middleware?.length) middleware.push(...route.data.middleware);
		return middleware;
	};
	return h3App;
}
//#endregion
//#region node_modules/nitro/dist/runtime/internal/app.mjs
var APP_ID = "default";
function useNitroApp() {
	let instance = useNitroApp._instance;
	if (instance) return instance;
	instance = useNitroApp._instance = createNitroApp();
	globalThis.__nitro__ = globalThis.__nitro__ || {};
	globalThis.__nitro__[APP_ID] = instance;
	return instance;
}
function useNitroHooks() {
	const nitroApp = useNitroApp();
	const hooks = nitroApp.hooks;
	if (hooks) return hooks;
	return nitroApp.hooks = new HookableCore();
}
function getRouteRules(method, pathname) {
	const m = findRouteRules(method, pathname);
	if (!m?.length) return { routeRuleMiddleware: [] };
	const routeRules = {};
	for (const layer of m) for (const rule of layer.data) {
		const currentRule = routeRules[rule.name];
		if (currentRule) {
			if (rule.options === false) {
				delete routeRules[rule.name];
				continue;
			}
			if (typeof currentRule.options === "object" && typeof rule.options === "object") currentRule.options = {
				...currentRule.options,
				...rule.options
			};
			else currentRule.options = rule.options;
			currentRule.route = rule.route;
			currentRule.params = {
				...currentRule.params,
				...layer.params
			};
		} else if (rule.options !== false) routeRules[rule.name] = {
			...rule,
			params: layer.params
		};
	}
	const middleware = [];
	const orderedRules = Object.values(routeRules).sort((a, b) => (a.handler?.order || 0) - (b.handler?.order || 0));
	for (const rule of orderedRules) {
		if (rule.options === false || !rule.handler) continue;
		middleware.push(rule.handler(rule));
	}
	return {
		routeRules,
		routeRuleMiddleware: middleware
	};
}
//#endregion
//#region node_modules/nitro/dist/presets/cloudflare/runtime/_module-handler.mjs
function createHandler(hooks) {
	const nitroApp = useNitroApp();
	const nitroHooks = useNitroHooks();
	return {
		async fetch(request, env, context) {
			globalThis.__env__ = env;
			augmentReq(request, {
				env,
				context
			});
			const ctxExt = {};
			const url = new URL(request.url);
			if (hooks.fetch) {
				const res = await hooks.fetch(request, env, context, url, ctxExt);
				if (res) return res;
			}
			return await nitroApp.fetch(request);
		},
		scheduled(controller, env, context) {
			globalThis.__env__ = env;
			context.waitUntil(nitroHooks.callHook("cloudflare:scheduled", {
				controller,
				env,
				context
			}) || Promise.resolve());
		},
		email(message, env, context) {
			globalThis.__env__ = env;
			context.waitUntil(nitroHooks.callHook("cloudflare:email", {
				message,
				event: message,
				env,
				context
			}) || Promise.resolve());
		},
		queue(batch, env, context) {
			globalThis.__env__ = env;
			context.waitUntil(nitroHooks.callHook("cloudflare:queue", {
				batch,
				event: batch,
				env,
				context
			}) || Promise.resolve());
		},
		tail(traces, env, context) {
			globalThis.__env__ = env;
			context.waitUntil(nitroHooks.callHook("cloudflare:tail", {
				traces,
				env,
				context
			}) || Promise.resolve());
		},
		trace(traces, env, context) {
			globalThis.__env__ = env;
			context.waitUntil(nitroHooks.callHook("cloudflare:trace", {
				traces,
				env,
				context
			}) || Promise.resolve());
		}
	};
}
function augmentReq(cfReq, ctx) {
	const req = cfReq;
	req.ip = cfReq.headers.get("cf-connecting-ip") || void 0;
	req.runtime ??= { name: "cloudflare" };
	req.runtime.cloudflare = {
		...req.runtime.cloudflare,
		...ctx
	};
	req.waitUntil = ctx.context?.waitUntil.bind(ctx.context);
}
//#endregion
//#region node_modules/nitro/dist/presets/cloudflare/runtime/cloudflare-module.mjs
var cloudflare_module_default = createHandler({ fetch(cfRequest, env, context, url) {
	if (env.ASSETS && isPublicAssetURL(url.pathname)) return env.ASSETS.fetch(cfRequest);
} });
//#endregion
export { cloudflare_module_default as default };
