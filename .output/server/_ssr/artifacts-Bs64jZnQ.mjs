import { a as require_jsx_runtime } from "../_libs/react+tanstack__react-query.mjs";
import { E as File, a as TriangleAlert, g as LoaderCircle } from "../_libs/lucide-react.mjs";
import { a as ToolBadge, c as useArtifacts, n as AppShell, r as Card } from "./app-shell-CXKz5zjF.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/artifacts-Bs64jZnQ.js
var import_jsx_runtime = require_jsx_runtime();
var tagColor = {
	malware: "bg-[color:var(--critical)]/15 text-[color:var(--critical)] border-[color:var(--critical)]/30",
	suspicious: "bg-[color:var(--high)]/15 text-[color:var(--high)] border-[color:var(--high)]/30",
	"ransom-note": "bg-[color:var(--critical)]/15 text-[color:var(--critical)] border-[color:var(--critical)]/30",
	log: "bg-[color:var(--info)]/15 text-[color:var(--info)] border-[color:var(--info)]/30",
	image: "bg-muted text-muted-foreground border-border"
};
function ArtifactsPage() {
	const { data: artifacts, isLoading, isError } = useArtifacts();
	const artifactList = Array.isArray(artifacts) ? artifacts : [];
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(AppShell, {
		title: "Artefacts",
		subtitle: isLoading ? "Chargement…" : `${artifactList.length} artefact(s) extrait(s) des sources forensiques`,
		children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, { children: [
			isLoading && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "flex items-center justify-center gap-2 py-12 text-sm text-muted-foreground",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(LoaderCircle, { className: "h-4 w-4 animate-spin" }), " Chargement des artefacts…"]
			}),
			isError && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "flex items-center justify-center gap-2 py-12 text-sm text-destructive",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(TriangleAlert, { className: "h-4 w-4" }), " Impossible de contacter le backend (localhost:8000)."]
			}),
			!isLoading && !isError && artifactList.length === 0 && /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
				className: "py-12 text-center text-sm text-muted-foreground",
				children: "Aucun artefact pour l'instant. Uploadez un fichier Loki ou Hayabusa depuis la page Import."
			}),
			!isLoading && !isError && artifactList.length > 0 && /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
				className: "overflow-x-auto",
				children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("table", {
					className: "w-full text-sm",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("thead", {
						className: "text-xs uppercase text-muted-foreground border-b border-border",
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("tr", { children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
								className: "text-left px-4 py-3",
								children: "Nom"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
								className: "text-left px-4 py-3",
								children: "Chemin"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
								className: "text-left px-4 py-3",
								children: "Hash / MITRE"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
								className: "text-left px-4 py-3",
								children: "Source"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
								className: "text-left px-4 py-3",
								children: "Horodatage"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
								className: "text-left px-4 py-3",
								children: "Tag"
							})
						] })
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("tbody", {
						className: "divide-y divide-border",
						children: artifactList.map((a, i) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("tr", {
							className: "hover:bg-muted/30 transition-colors",
							children: [
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
									className: "px-4 py-3",
									children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
										className: "flex items-center gap-2",
										children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(File, { className: "h-3.5 w-3.5 text-muted-foreground shrink-0" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
											className: "font-medium truncate max-w-xs",
											children: a.name
										})]
									})
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
									className: "px-4 py-3 font-mono text-xs text-muted-foreground truncate max-w-xs",
									children: a.path
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
									className: "px-4 py-3 font-mono text-xs text-muted-foreground truncate max-w-xs",
									children: a.hash
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
									className: "px-4 py-3",
									children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ToolBadge, { tool: a.source })
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
									className: "px-4 py-3 font-mono text-xs text-muted-foreground",
									children: String(a.timestamp ?? "—").slice(0, 19)
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
									className: "px-4 py-3",
									children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
										className: `text-[10px] uppercase tracking-wider px-2 py-0.5 rounded border ${tagColor[a.tag] ?? "bg-muted text-muted-foreground border-border"}`,
										children: a.tag
									})
								})
							]
						}, i))
					})]
				})
			})
		] })
	});
}
//#endregion
export { ArtifactsPage as component };
