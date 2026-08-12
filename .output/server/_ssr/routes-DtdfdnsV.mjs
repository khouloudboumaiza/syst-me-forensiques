import { a as require_jsx_runtime } from "../_libs/react+tanstack__react-query.mjs";
import { H as Boxes, T as Files, W as ArrowUpRight, f as ShieldAlert, g as LoaderCircle, o as TrendingUp, w as FingerprintPattern } from "../_libs/lucide-react.mjs";
import { a as ToolBadge, g as useToolDistribution, i as SeverityBadge, l as useCorrelations, m as useStats, n as AppShell, o as useAlerts, p as useSeverityDistribution, r as Card, t as API_URL } from "./app-shell-CXKz5zjF.mjs";
import { a as XAxis, c as Bar, d as ResponsiveContainer, f as Tooltip, i as YAxis, l as Pie, n as PieChart, o as Area, r as BarChart, s as CartesianGrid, t as AreaChart, u as Cell } from "../_libs/recharts+[...].mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/routes-DtdfdnsV.js
var import_jsx_runtime = require_jsx_runtime();
var SEVERITY_COLORS = {
	critical: "var(--critical)",
	high: "var(--high)",
	medium: "var(--medium)",
	low: "var(--success)"
};
function Kpi({ label, value, icon: Icon, trend, tone = "primary" }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Card, {
		className: "p-4",
		children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
			className: "flex items-start justify-between",
			children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
					className: "text-xs text-muted-foreground uppercase tracking-wider",
					children: label
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
					className: "text-2xl font-semibold mt-2 tabular-nums",
					children: value
				}),
				trend && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "flex items-center gap-1 mt-1 text-xs text-[color:var(--success)]",
					children: [
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)(TrendingUp, { className: "h-3 w-3" }),
						" ",
						trend
					]
				})
			] }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
				className: `h-9 w-9 rounded-md grid place-items-center border ${{
					primary: "text-primary bg-primary/10 border-primary/20",
					critical: "text-[color:var(--critical)] bg-[color:var(--critical)]/10 border-[color:var(--critical)]/20",
					high: "text-[color:var(--high)] bg-[color:var(--high)]/10 border-[color:var(--high)]/20",
					medium: "text-[color:var(--medium)] bg-[color:var(--medium)]/10 border-[color:var(--medium)]/20"
				}[tone]}`,
				children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Icon, { className: "h-4 w-4" })
			})]
		})
	});
}
function buildTimeline(rawAlerts) {
	const buckets = {};
	for (const a of rawAlerts) {
		const ts = a.timestamp ?? "";
		const hour = String(ts).slice(11, 16) || "??:??";
		buckets[hour] = (buckets[hour] || 0) + 1;
	}
	return Object.entries(buckets).sort(([a], [b]) => a.localeCompare(b)).map(([time, events]) => ({
		time,
		events
	}));
}
function Overview() {
	const { data: stats, isLoading: statsLoading } = useStats();
	const { data: rawAlerts, isLoading: alertsLoading } = useAlerts();
	const { data: severityDistribution } = useSeverityDistribution();
	const { data: toolDistribution } = useToolDistribution();
	const { data: correlations } = useCorrelations();
	const alerts = Array.isArray(rawAlerts) ? rawAlerts : [];
	const timelineActivity = buildTimeline(alerts);
	const isLoading = statsLoading || alertsLoading;
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(AppShell, {
		title: "Vue d'ensemble",
		subtitle: `Dossier : demo`,
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, {
				className: "p-5 mb-6 relative overflow-hidden",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
					className: "absolute inset-0 opacity-40 pointer-events-none",
					style: { background: "radial-gradient(600px 200px at 10% 0%, color-mix(in oklab, var(--primary) 25%, transparent), transparent)" }
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "relative flex flex-wrap items-center justify-between gap-4",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
							className: "flex items-center gap-2 text-xs text-muted-foreground",
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { className: "h-1.5 w-1.5 rounded-full bg-[color:var(--high)] animate-pulse" }), isLoading ? "Chargement…" : "Investigation en cours"]
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
							className: "text-xl font-semibold mt-1",
							children: "Dossier demo"
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
							className: "text-sm text-muted-foreground mt-1 max-w-2xl",
							children: correlations?.correlated_events?.length ? `${correlations.correlated_events.length} corrélation(s) host/réseau détectée(s).` : "En attente de corrélations entre événements host et réseau."
						})
					] }), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "flex items-center gap-2",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
							className: "text-right",
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
								className: "text-[10px] uppercase tracking-widest text-muted-foreground",
								children: "Score de risque combiné"
							}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
								className: "text-lg font-semibold text-[color:var(--high)]",
								children: correlations?.combined_risk_score ?? "—"
							})]
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("a", {
							href: `${API_URL}/cases/demo/report`,
							target: "_blank",
							rel: "noreferrer",
							className: "inline-flex items-center gap-1.5 rounded-md bg-primary text-primary-foreground px-3 py-2 text-sm font-medium hover:opacity-90",
							children: ["Générer rapport ", /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ArrowUpRight, { className: "h-3.5 w-3.5" })]
						})]
					})]
				})]
			}),
			isLoading ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "flex items-center gap-2 text-sm text-muted-foreground mb-6",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(LoaderCircle, { className: "h-4 w-4 animate-spin" }), " Chargement des statistiques…"]
			}) : /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 mb-6",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Kpi, {
						label: "Fichiers analysés",
						value: stats?.files_analyzed ?? 0,
						icon: Files
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Kpi, {
						label: "Alertes",
						value: stats?.alerts ?? alerts.length,
						icon: ShieldAlert,
						tone: "high"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Kpi, {
						label: "IOCs",
						value: stats?.iocs ?? 0,
						icon: FingerprintPattern,
						tone: "critical"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Kpi, {
						label: "Artefacts",
						value: stats?.artifacts ?? 0,
						icon: Boxes
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Kpi, {
						label: "Corrélations",
						value: correlations?.correlated_events?.length ?? 0,
						icon: TrendingUp,
						tone: "medium"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Kpi, {
						label: "Sources",
						value: stats?.sources ?? 0,
						icon: Boxes
					})
				]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, {
					className: "lg:col-span-2 p-5",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
						className: "flex items-center justify-between mb-4",
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h3", {
							className: "text-sm font-semibold",
							children: "Activité d'événements"
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
							className: "text-xs text-muted-foreground",
							children: "Volume d'alertes par horodatage"
						})] })
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
						className: "h-64",
						children: timelineActivity.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "h-full grid place-items-center text-sm text-muted-foreground",
							children: "Pas encore de données — uploadez un fichier."
						}) : /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ResponsiveContainer, {
							width: "100%",
							height: "100%",
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(AreaChart, {
								data: timelineActivity,
								children: [
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)("defs", { children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("linearGradient", {
										id: "g1",
										x1: "0",
										y1: "0",
										x2: "0",
										y2: "1",
										children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("stop", {
											offset: "0%",
											stopColor: "var(--primary)",
											stopOpacity: .5
										}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("stop", {
											offset: "100%",
											stopColor: "var(--primary)",
											stopOpacity: 0
										})]
									}) }),
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)(CartesianGrid, {
										strokeDasharray: "3 3",
										stroke: "var(--border)",
										vertical: false
									}),
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)(XAxis, {
										dataKey: "time",
										stroke: "var(--muted-foreground)",
										fontSize: 11
									}),
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)(YAxis, {
										stroke: "var(--muted-foreground)",
										fontSize: 11
									}),
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Tooltip, { contentStyle: {
										background: "var(--popover)",
										border: "1px solid var(--border)",
										borderRadius: 8,
										fontSize: 12
									} }),
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Area, {
										type: "monotone",
										dataKey: "events",
										stroke: "var(--primary)",
										strokeWidth: 2,
										fill: "url(#g1)"
									})
								]
							})
						})
					})]
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, {
					className: "p-5",
					children: [
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h3", {
							className: "text-sm font-semibold mb-1",
							children: "Répartition par sévérité"
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
							className: "text-xs text-muted-foreground mb-3",
							children: "Toutes sources confondues"
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "h-48",
							children: !severityDistribution || severityDistribution.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
								className: "h-full grid place-items-center text-sm text-muted-foreground",
								children: "Aucune donnée"
							}) : /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ResponsiveContainer, {
								width: "100%",
								height: "100%",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(PieChart, { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Pie, {
									data: severityDistribution,
									dataKey: "count",
									nameKey: "level",
									innerRadius: 45,
									outerRadius: 75,
									paddingAngle: 2,
									children: severityDistribution.map((e, i) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Cell, { fill: e.color ?? SEVERITY_COLORS[e.level] ?? "var(--primary)" }, i))
								}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Tooltip, { contentStyle: {
									background: "var(--popover)",
									border: "1px solid var(--border)",
									borderRadius: 8,
									fontSize: 12
								} })] })
							})
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "grid grid-cols-2 gap-2 mt-3",
							children: (severityDistribution ?? []).map((s) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
								className: "flex items-center gap-2 text-xs",
								children: [
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
										className: "h-2 w-2 rounded-sm",
										style: { background: s.color ?? SEVERITY_COLORS[s.level] }
									}),
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
										className: "text-muted-foreground",
										children: s.level
									}),
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
										className: "ml-auto font-medium tabular-nums",
										children: s.count
									})
								]
							}, s.level))
						})
					]
				})]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "grid grid-cols-1 lg:grid-cols-3 gap-4",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, {
					className: "lg:col-span-1 p-5",
					children: [
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h3", {
							className: "text-sm font-semibold mb-1",
							children: "Par outil forensique"
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
							className: "text-xs text-muted-foreground mb-3",
							children: "Alertes générées par source"
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "h-56",
							children: !toolDistribution || toolDistribution.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
								className: "h-full grid place-items-center text-sm text-muted-foreground",
								children: "Aucune donnée"
							}) : /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ResponsiveContainer, {
								width: "100%",
								height: "100%",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(BarChart, {
									data: toolDistribution,
									layout: "vertical",
									margin: { left: 10 },
									children: [
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)(CartesianGrid, {
											strokeDasharray: "3 3",
											stroke: "var(--border)",
											horizontal: false
										}),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)(XAxis, {
											type: "number",
											stroke: "var(--muted-foreground)",
											fontSize: 11
										}),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)(YAxis, {
											dataKey: "tool",
											type: "category",
											stroke: "var(--muted-foreground)",
											fontSize: 11,
											width: 70
										}),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Tooltip, { contentStyle: {
											background: "var(--popover)",
											border: "1px solid var(--border)",
											borderRadius: 8,
											fontSize: 12
										} }),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Bar, {
											dataKey: "alerts",
											fill: "var(--primary)",
											radius: [
												0,
												4,
												4,
												0
											]
										})
									]
								})
							})
						})
					]
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, {
					className: "lg:col-span-2",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "p-5 border-b border-border flex items-center justify-between",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h3", {
							className: "text-sm font-semibold",
							children: "Alertes récentes"
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
							className: "text-xs text-muted-foreground",
							children: "Dernières détections"
						})] }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("a", {
							href: "/alerts",
							className: "text-xs text-primary hover:underline",
							children: "Tout voir →"
						})]
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "divide-y divide-border",
						children: [alerts.length === 0 && /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "px-5 py-6 text-sm text-muted-foreground",
							children: "Aucune alerte pour l'instant."
						}), alerts.slice(0, 5).map((a, i) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
							className: "px-5 py-3 hover:bg-muted/30 transition-colors flex items-center gap-4",
							children: [
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)(SeverityBadge, { severity: (a.severity ?? "medium").toLowerCase() }),
								/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
									className: "min-w-0 flex-1",
									children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
										className: "text-sm font-medium truncate",
										children: a.title ?? a.rule ?? "Alerte"
									}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
										className: "text-xs text-muted-foreground truncate font-mono",
										children: a.target ?? a.dst_ip ?? ""
									})]
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)(ToolBadge, { tool: a.tool ?? a.source ?? "unknown" }),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
									className: "text-xs text-muted-foreground tabular-nums hidden md:block",
									children: String(a.timestamp ?? "").split(" ")[1] ?? ""
								})
							]
						}, a.id ?? i))]
					})]
				})]
			})
		]
	});
}
//#endregion
export { Overview as component };
