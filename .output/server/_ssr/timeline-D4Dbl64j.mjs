import { i as __toESM } from "../_runtime.mjs";
import { a as require_jsx_runtime, o as require_react } from "../_libs/react+tanstack__react-query.mjs";
import { P as Clock, a as TriangleAlert, g as LoaderCircle, t as X, y as Info } from "../_libs/lucide-react.mjs";
import { a as ToolBadge, h as useTimeline, i as SeverityBadge, n as AppShell, r as Card } from "./app-shell-CXKz5zjF.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/timeline-D4Dbl64j.js
var import_react = /* @__PURE__ */ __toESM(require_react());
var import_jsx_runtime = require_jsx_runtime();
function TimelinePage() {
	const { data: events, isLoading, isError } = useTimeline();
	const [showSummary, setShowSummary] = (0, import_react.useState)(false);
	const eventList = Array.isArray(events) ? events : [];
	const criticalCount = eventList.filter((e) => e.severity === "critical").length;
	const highCount = eventList.filter((e) => e.severity === "high").length;
	const firstEvent = eventList[0];
	const lastEvent = eventList[eventList.length - 1];
	const dangerousEvents = eventList.filter((e) => e.severity === "critical" || e.severity === "high").slice(0, 5);
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(AppShell, {
		title: "Timeline corrélée",
		subtitle: isLoading ? "Chargement…" : `${eventList.length} événement(s) ordonnés chronologiquement depuis le backend`,
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
				className: "flex justify-end mb-4",
				children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
					onClick: () => setShowSummary(true),
					disabled: eventList.length === 0,
					className: "flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground text-sm font-medium rounded-md hover:opacity-90 disabled:opacity-50 transition-opacity",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Info, { className: "h-4 w-4" }), "Résumé de la Timeline"]
				})
			}),
			showSummary && /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
				className: "fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm p-4",
				children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "w-full max-w-lg bg-card border border-border shadow-lg rounded-xl flex flex-col max-h-[90vh]",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "flex items-center justify-between p-4 border-b border-border sticky top-0 bg-card z-10 rounded-t-xl",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("h2", {
							className: "text-xl font-semibold flex items-center gap-2",
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Clock, { className: "h-5 w-5 text-primary" }), " Résumé de l'Investigation"]
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
							onClick: () => setShowSummary(false),
							className: "p-1.5 rounded-md hover:bg-muted text-muted-foreground transition-colors",
							title: "Fermer (Échap)",
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(X, { className: "h-5 w-5" })
						})]
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "p-6 overflow-y-auto space-y-4 text-sm",
						children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", { children: [
								"Cette timeline contient ",
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: eventList.length }),
								" événements horodatés."
							] }),
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
								className: "bg-muted p-3 rounded border border-border space-y-2",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
									className: "flex justify-between",
									children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
										className: "text-muted-foreground",
										children: "Premier événement :"
									}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
										className: "font-mono",
										children: firstEvent?.time
									})]
								}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
									className: "flex justify-between",
									children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
										className: "text-muted-foreground",
										children: "Dernier événement :"
									}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
										className: "font-mono",
										children: lastEvent?.time
									})]
								})]
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
								className: "grid grid-cols-2 gap-3 mt-4",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
									className: "p-3 border border-destructive/20 bg-destructive/5 rounded flex flex-col",
									children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
										className: "text-xs text-muted-foreground uppercase tracking-wider",
										children: "Alertes Critiques"
									}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
										className: "text-2xl font-semibold text-destructive",
										children: criticalCount
									})]
								}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
									className: "p-3 border border-[color:var(--high)]/20 bg-[color:var(--high)]/5 rounded flex flex-col",
									children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
										className: "text-xs text-muted-foreground uppercase tracking-wider",
										children: "Alertes Hautes"
									}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
										className: "text-2xl font-semibold text-[color:var(--high)]",
										children: highCount
									})]
								})]
							}),
							criticalCount > 0 && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
								className: "mt-4 p-3 bg-destructive/10 text-destructive text-xs rounded border border-destructive/20",
								children: [
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)(TriangleAlert, { className: "h-4 w-4 inline-block mr-1 mb-0.5" }),
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: "Attention :" }),
									" Des événements critiques ont été détectés, veuillez examiner la timeline de près."
								]
							}),
							dangerousEvents.length > 0 && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
								className: "mt-4 border-t border-border pt-4",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("h3", {
									className: "font-semibold mb-3 flex items-center gap-2",
									children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(TriangleAlert, { className: "h-4 w-4 text-destructive" }), "Événements les plus dangereux"]
								}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
									className: "space-y-3",
									children: dangerousEvents.map((de, i) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
										className: "bg-muted p-3 rounded-md border border-border text-xs",
										children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
											className: "flex justify-between items-start mb-1",
											children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
												className: "font-semibold",
												children: de.title
											}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
												className: "font-mono text-muted-foreground",
												children: de.time
											})]
										}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
											className: "flex items-center gap-2 mt-2",
											children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(SeverityBadge, { severity: de.severity }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ToolBadge, { tool: de.source })]
										})]
									}, i))
								})]
							})
						]
					})]
				})
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, {
				className: "p-6",
				children: [
					isLoading && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "flex items-center justify-center gap-2 py-12 text-sm text-muted-foreground",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(LoaderCircle, { className: "h-4 w-4 animate-spin" }), " Chargement de la timeline…"]
					}),
					isError && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "flex items-center justify-center gap-2 py-12 text-sm text-destructive",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(TriangleAlert, { className: "h-4 w-4" }), " Impossible de contacter le backend (localhost:8000)."]
					}),
					!isLoading && !isError && eventList.length === 0 && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "py-12 text-center text-sm text-muted-foreground",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Clock, { className: "h-8 w-8 mx-auto mb-3 opacity-30" }), "Aucun événement horodaté pour l'instant. Uploadez un fichier depuis la page Import."]
					}),
					!isLoading && !isError && eventList.length > 0 && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "relative",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", { className: "absolute left-[92px] top-0 bottom-0 w-px bg-border" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
							className: "space-y-4",
							children: eventList.map((e, idx) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
								className: "relative flex gap-4 items-start group",
								children: [
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
										className: "w-20 text-right pt-1 shrink-0",
										children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
											className: "text-xs font-mono tabular-nums text-muted-foreground",
											children: e.time
										})
									}),
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
										className: "relative shrink-0",
										children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", { className: `h-3 w-3 rounded-full ring-4 ring-background mt-1.5 transition-transform group-hover:scale-125 ${e.severity === "critical" ? "bg-[color:var(--critical)]" : e.severity === "high" ? "bg-[color:var(--high)]" : e.severity === "medium" ? "bg-[color:var(--medium)]" : "bg-primary"}` })
									}),
									/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
										className: "flex-1 pb-4",
										children: [
											/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
												className: "flex items-center gap-2 flex-wrap",
												children: [
													/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
														className: "text-sm font-medium",
														children: e.title
													}),
													/* @__PURE__ */ (0, import_jsx_runtime.jsx)(SeverityBadge, { severity: e.severity }),
													/* @__PURE__ */ (0, import_jsx_runtime.jsx)(ToolBadge, { tool: e.source })
												]
											}),
											e.target && /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
												className: "text-xs font-mono text-muted-foreground mt-0.5 truncate max-w-lg",
												children: e.target
											}),
											e.detail && /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
												className: "text-xs text-muted-foreground mt-1",
												children: e.detail
											})
										]
									})
								]
							}, idx))
						})]
					})
				]
			})
		]
	});
}
//#endregion
export { TimelinePage as component };
