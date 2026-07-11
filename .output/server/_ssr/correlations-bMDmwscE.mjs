import { a as require_jsx_runtime } from "../_libs/react+tanstack__react-query.mjs";
import { D as FileText, P as Clock, _ as Link2, a as TriangleAlert, b as Hash, g as LoaderCircle, h as Network, l as Shield, s as Target, x as Globe } from "../_libs/lucide-react.mjs";
import { i as SeverityBadge, l as useCorrelations, n as AppShell, r as Card } from "./app-shell-CXKz5zjF.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/correlations-bMDmwscE.js
var import_jsx_runtime = require_jsx_runtime();
var TYPE_CONFIG = {
	ip: {
		label: "IP partagée",
		icon: Globe,
		color: "text-blue-400",
		bg: "bg-blue-500/10 border-blue-500/20"
	},
	hash: {
		label: "Hash partagé",
		icon: Hash,
		color: "text-red-400",
		bg: "bg-red-500/10 border-red-500/20"
	},
	target: {
		label: "Cible commune",
		icon: Target,
		color: "text-amber-400",
		bg: "bg-amber-500/10 border-amber-500/20"
	},
	temporal: {
		label: "Corrélation temporelle",
		icon: Clock,
		color: "text-emerald-400",
		bg: "bg-emerald-500/10 border-emerald-500/20"
	}
};
function CorrelationsPage() {
	const { data: correlationsData, isLoading, isError } = useCorrelations();
	const correlated = Array.isArray(correlationsData?.correlated_events) ? correlationsData.correlated_events : [];
	const hostCount = correlationsData?.total_host_alerts ?? 0;
	const networkCount = correlationsData?.total_network_alerts ?? 0;
	const riskScore = correlationsData?.combined_risk_score ?? 0;
	const corrTypes = correlationsData?.correlation_types ?? [];
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(AppShell, {
		title: "Corrélations intelligentes",
		subtitle: "Analyse multi-dimensionnelle : IPs, hashs, cibles et fenêtres temporelles croisés entre tous les fichiers uploadés",
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "grid grid-cols-1 md:grid-cols-4 gap-3 mb-6",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "rounded-lg border border-border bg-card p-4",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "text-xs text-muted-foreground uppercase tracking-wider",
							children: "Score de risque"
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: `text-3xl font-semibold mt-2 tabular-nums ${riskScore > 100 ? "text-[color:var(--critical)]" : riskScore > 30 ? "text-[color:var(--high)]" : "text-[color:var(--medium)]"}`,
							children: riskScore
						})]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "rounded-lg border border-border bg-card p-4",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "text-xs text-muted-foreground uppercase tracking-wider",
							children: "Corrélations trouvées"
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "text-3xl font-semibold mt-2 tabular-nums",
							children: correlated.length
						})]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "rounded-lg border border-border bg-card p-4",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "text-xs text-muted-foreground uppercase tracking-wider",
							children: "Alertes host"
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "text-3xl font-semibold mt-2 tabular-nums",
							children: hostCount
						})]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "rounded-lg border border-border bg-card p-4",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "text-xs text-muted-foreground uppercase tracking-wider",
							children: "Alertes réseau"
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "text-3xl font-semibold mt-2 tabular-nums",
							children: networkCount
						})]
					})
				]
			}),
			corrTypes.length > 0 && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "flex items-center gap-2 flex-wrap mb-4",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
					className: "text-xs text-muted-foreground",
					children: "Types de corrélation :"
				}), corrTypes.map((t) => {
					const cfg = TYPE_CONFIG[t] || TYPE_CONFIG.ip;
					const Icon = cfg.icon;
					return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", {
						className: `inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold border ${cfg.bg} ${cfg.color}`,
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Icon, { className: "h-3 w-3" }), cfg.label]
					}, t);
				})]
			}),
			isLoading && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "flex items-center justify-center gap-2 py-12 text-sm text-muted-foreground",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(LoaderCircle, { className: "h-4 w-4 animate-spin" }), " Calcul des corrélations…"]
			}),
			isError && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "flex items-center justify-center gap-2 py-12 text-sm text-destructive",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(TriangleAlert, { className: "h-4 w-4" }), " Impossible de contacter le backend (localhost:8000)."]
			}),
			!isLoading && !isError && correlated.length === 0 && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, {
				className: "p-10 text-center",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Network, { className: "h-10 w-10 mx-auto mb-3 text-muted-foreground opacity-30" }), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "text-sm text-muted-foreground",
					children: [
						"Aucune corrélation détectée. Les corrélations apparaissent automatiquement quand des indicateurs (IPs, hashs, cibles) sont partagés entre ",
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: "2+ fichiers" }),
						" uploadés dans le même cas."
					]
				})]
			}),
			!isLoading && !isError && correlated.length > 0 && /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
				className: "space-y-4",
				children: correlated.map((c, idx) => {
					const cfg = TYPE_CONFIG[c.type] || TYPE_CONFIG.ip;
					const Icon = cfg.icon;
					return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Card, {
						className: "p-5",
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
							className: "flex items-start justify-between gap-4 flex-wrap",
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
								className: "flex items-start gap-3 min-w-0 flex-1",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
									className: `h-10 w-10 rounded-md border grid place-items-center shrink-0 ${cfg.bg}`,
									children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Icon, { className: `h-4 w-4 ${cfg.color}` })
								}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
									className: "min-w-0",
									children: [
										/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
											className: "flex items-center gap-2 flex-wrap",
											children: [
												/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", {
													className: "text-xs font-mono text-muted-foreground",
													children: ["CORR-", String(idx + 1).padStart(2, "0")]
												}),
												/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
													className: `inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold border ${cfg.bg} ${cfg.color}`,
													children: cfg.label
												}),
												/* @__PURE__ */ (0, import_jsx_runtime.jsx)(SeverityBadge, { severity: c.risk ?? "high" })
											]
										}),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h3", {
											className: "text-base font-semibold mt-1 font-mono break-all",
											children: c.indicator
										}),
										/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
											className: "mt-2 flex flex-wrap gap-2",
											children: [(c.tools ?? []).map((tool, ti) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", {
												className: "inline-flex items-center gap-1 text-[10px] font-bold px-1.5 py-0.5 rounded bg-primary/10 text-primary border border-primary/20",
												children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Shield, { className: "h-2.5 w-2.5" }), tool.toUpperCase()]
											}, ti)), (c.files ?? []).map((file, fi) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", {
												className: "inline-flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded bg-muted border border-border",
												children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(FileText, { className: "h-2.5 w-2.5" }), file]
											}, fi))]
										}),
										c.time_window && c.time_window !== "—" && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
											className: "text-sm text-muted-foreground mt-2",
											children: [
												/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Clock, { className: "h-3 w-3 inline mr-1" }),
												"Fenêtre : ",
												/* @__PURE__ */ (0, import_jsx_runtime.jsx)("code", {
													className: "font-mono text-xs",
													children: c.time_window
												})
											]
										}),
										/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
											className: "mt-3",
											children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
												className: "text-xs text-muted-foreground mb-1",
												children: [c.alert_count, " alerte(s) liée(s) :"]
											}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
												className: "flex flex-col gap-1",
												children: (c.network_events ?? []).map((ne, ni) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", {
													className: "flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded bg-muted border border-border w-fit max-w-full truncate",
													children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Link2, { className: "h-2.5 w-2.5 shrink-0" }), ne]
												}, ni))
											})]
										})
									]
								})]
							}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
								className: "text-right shrink-0",
								children: [
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
										className: "text-[10px] uppercase tracking-widest text-muted-foreground",
										children: "Risque"
									}),
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
										className: `text-lg font-semibold mt-1 uppercase ${c.risk === "critical" ? "text-[color:var(--critical)]" : c.risk === "high" ? "text-[color:var(--high)]" : "text-[color:var(--medium)]"}`,
										children: c.risk
									}),
									/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
										className: "text-xs text-muted-foreground mt-1",
										children: [c.alert_count, " alertes"]
									})
								]
							})]
						})
					}, idx);
				})
			})
		]
	});
}
//#endregion
export { CorrelationsPage as component };
