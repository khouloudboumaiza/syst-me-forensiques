import { i as __toESM } from "../_runtime.mjs";
import { a as require_jsx_runtime, o as require_react } from "../_libs/react+tanstack__react-query.mjs";
import { S as Funnel, V as ChevronDown, c as Sparkles, g as LoaderCircle, p as Search, z as ChevronUp } from "../_libs/lucide-react.mjs";
import { a as ToolBadge, i as SeverityBadge, n as AppShell, o as useAlerts, r as Card } from "./app-shell-CXKz5zjF.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/alerts-BCFnl4Fk.js
var import_react = /* @__PURE__ */ __toESM(require_react());
var import_jsx_runtime = require_jsx_runtime();
var API_URL = "http://localhost:8000";
var explanationCache = {};
async function fetchAIExplanation(rule, target, source, details) {
	const cacheKey = `${rule}|${target}|${source}`;
	if (explanationCache[cacheKey]) return explanationCache[cacheKey];
	const res = await fetch(`${API_URL}/explain-alert`, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			rule,
			target,
			source,
			details
		})
	});
	if (!res.ok) throw new Error("Erreur API");
	const data = await res.json();
	explanationCache[cacheKey] = data.explanation;
	return data.explanation;
}
function normalizeAlert(a, index) {
	const rule = a.title ?? a.rule ?? a.RuleTitle ?? "Alerte";
	const target = a.target ?? a.dst_ip ?? a.FilePath ?? a.Computer ?? "";
	const source = a.tool ?? a.source ?? "unknown";
	return {
		id: a.id ?? index,
		timestamp: a.timestamp ?? "—",
		severity: (a.severity ?? "medium").toLowerCase(),
		source,
		rule,
		target,
		description: a.details ?? a.description ?? ""
	};
}
function AIExplainCell({ rule, target, source, details }) {
	const [state, setState] = (0, import_react.useState)("idle");
	const [explanation, setExplanation] = (0, import_react.useState)("");
	const [expanded, setExpanded] = (0, import_react.useState)(false);
	const handleExplain = (0, import_react.useCallback)(async (e) => {
		e.stopPropagation();
		if (state === "loading") return;
		setState("loading");
		try {
			const text = await fetchAIExplanation(rule, target, source, details);
			setExplanation(text);
			setState("done");
			setExpanded(true);
		} catch {
			setState("error");
		}
	}, [
		rule,
		target,
		source,
		details,
		state
	]);
	if (state === "idle") return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
		onClick: handleExplain,
		className: "inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium border border-primary/30 text-primary bg-primary/5 hover:bg-primary/15 transition-all duration-200 group",
		children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Sparkles, { className: "h-3.5 w-3.5 group-hover:animate-pulse" }), "Expliquer via IA"]
	});
	if (state === "loading") return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "inline-flex items-center gap-2 px-3 py-1.5 text-xs text-muted-foreground",
		children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(LoaderCircle, { className: "h-3.5 w-3.5 animate-spin text-primary" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
			className: "animate-pulse",
			children: "Analyse IA en cours…"
		})]
	});
	if (state === "error") return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "flex items-center gap-2",
		children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
			className: "text-xs text-destructive",
			children: "Erreur IA"
		}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
			onClick: handleExplain,
			className: "text-xs underline text-muted-foreground hover:text-foreground",
			children: "Réessayer"
		})]
	});
	const preview = explanation.slice(0, 120);
	const isLong = explanation.length > 120;
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "text-xs bg-gradient-to-br from-primary/8 to-violet-500/5 border border-primary/20 rounded-lg p-3 leading-relaxed space-y-2 max-w-xs",
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "flex items-center gap-1.5 text-primary font-semibold mb-1",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Sparkles, { className: "h-3 w-3" }), "Analyse IA"]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "text-foreground/80",
				children: expanded || !isLong ? explanation : `${preview}…`
			}),
			isLong && /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
				onClick: (e) => {
					e.stopPropagation();
					setExpanded(!expanded);
				},
				className: "inline-flex items-center gap-1 text-primary/70 hover:text-primary text-[11px] font-medium transition-colors",
				children: expanded ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(import_jsx_runtime.Fragment, { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(ChevronUp, { className: "h-3 w-3" }), " Réduire"] }) : /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(import_jsx_runtime.Fragment, { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(ChevronDown, { className: "h-3 w-3" }), " Voir plus"] })
			})
		]
	});
}
function AlertsPage() {
	const [q, setQ] = (0, import_react.useState)("");
	const [sev, setSev] = (0, import_react.useState)("all");
	const { data: rawAlerts, isLoading, isError } = useAlerts();
	const alerts = Array.isArray(rawAlerts) ? rawAlerts.map(normalizeAlert) : [];
	const filtered = alerts.filter((a) => (sev === "all" || a.severity === sev) && (q === "" || (a.rule + a.target + a.description).toLowerCase().includes(q.toLowerCase())));
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(AppShell, {
		title: "Alertes",
		subtitle: isLoading ? "Chargement…" : `${filtered.length} alertes filtrées sur ${alerts.length}`,
		children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, {
			className: "p-4 mb-4 flex flex-wrap items-center gap-3",
			children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "flex items-center gap-2 px-3 py-1.5 rounded-md bg-muted border border-border flex-1 min-w-64",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Search, { className: "h-3.5 w-3.5 text-muted-foreground" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
					value: q,
					onChange: (e) => setQ(e.target.value),
					placeholder: "Filtrer par règle, chemin, description…",
					className: "bg-transparent text-sm outline-none flex-1"
				})]
			}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "flex items-center gap-2",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Funnel, { className: "h-4 w-4 text-muted-foreground" }), [
					"all",
					"critical",
					"high",
					"medium",
					"low"
				].map((s) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
					onClick: () => setSev(s),
					className: `px-2.5 py-1 rounded text-xs capitalize border transition-colors ${sev === s ? "bg-primary text-primary-foreground border-primary" : "border-border hover:bg-muted"}`,
					children: s
				}, s))]
			})]
		}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, { children: [
			isLoading && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "flex items-center justify-center gap-2 py-12 text-sm text-muted-foreground",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(LoaderCircle, { className: "h-4 w-4 animate-spin" }), " Chargement des alertes…"]
			}),
			isError && /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
				className: "py-12 text-center text-sm text-destructive",
				children: "Impossible de contacter le backend (localhost:8000). Vérifiez qu'uvicorn tourne."
			}),
			!isLoading && !isError && filtered.length === 0 && /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
				className: "py-12 text-center text-sm text-muted-foreground",
				children: "Aucune alerte pour l'instant. Uploadez un fichier depuis la page Import."
			}),
			!isLoading && !isError && filtered.length > 0 && /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
				className: "overflow-x-auto",
				children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("table", {
					className: "w-full text-sm",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("thead", {
						className: "text-xs uppercase text-muted-foreground border-b border-border",
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("tr", { children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
								className: "text-left px-4 py-3",
								children: "ID"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
								className: "text-left px-4 py-3",
								children: "Horodatage"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
								className: "text-left px-4 py-3",
								children: "Sévérité"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
								className: "text-left px-4 py-3",
								children: "Source"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
								className: "text-left px-4 py-3",
								children: "Règle"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
								className: "text-left px-4 py-3",
								children: "Cible / Description"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
								className: "text-left px-4 py-3 min-w-[220px]",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", {
									className: "inline-flex items-center gap-1.5",
									children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Sparkles, { className: "h-3.5 w-3.5 text-primary" }), "Explication (IA)"]
								})
							})
						] })
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("tbody", {
						className: "divide-y divide-border",
						children: filtered.map((a) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("tr", {
							className: "hover:bg-muted/30 transition-colors align-top",
							children: [
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
									className: "px-4 py-3 font-mono text-xs text-muted-foreground",
									children: a.id
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
									className: "px-4 py-3 font-mono text-xs tabular-nums",
									children: a.timestamp
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
									className: "px-4 py-3",
									children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(SeverityBadge, { severity: a.severity })
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
									className: "px-4 py-3",
									children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ToolBadge, { tool: a.source })
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
									className: "px-4 py-3 font-medium max-w-[200px]",
									children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
										className: "line-clamp-2",
										title: a.rule,
										children: a.rule
									})
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("td", {
									className: "px-4 py-3",
									children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
										className: "font-mono text-xs text-muted-foreground truncate max-w-[200px]",
										title: a.target,
										children: a.target
									}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
										className: "text-xs mt-0.5 line-clamp-2 text-muted-foreground",
										title: a.description,
										children: a.description
									})]
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
									className: "px-4 py-3",
									children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(AIExplainCell, {
										rule: a.rule,
										target: a.target,
										source: a.source,
										details: a.description
									})
								})
							]
						}, a.id))
					})]
				})
			})
		] })]
	});
}
//#endregion
export { AlertsPage as component };
