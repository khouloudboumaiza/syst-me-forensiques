import { a as require_jsx_runtime } from "../_libs/react+tanstack__react-query.mjs";
import { n as useFileSelection } from "./useFileSelection-BQQdt2sG.mjs";
import { _ as useNavigate } from "../_libs/@tanstack/react-router+[...].mjs";
import { A as Download, B as ChevronRight, D as FileText, I as CircleX, O as FileExclamationPoint, R as CircleCheck, S as Funnel, W as ArrowUpRight, a as TriangleAlert, h as Network, j as Cpu, l as Shield, m as Printer, w as FingerprintPattern, x as Globe } from "../_libs/lucide-react.mjs";
import { d as useIOCs, f as useReport, l as useCorrelations, m as useStats, n as AppShell, o as useAlerts, s as useAnalysisStatus, t as API_URL, u as useFilesList } from "./app-shell-CXKz5zjF.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/reports-BWeij0nT.js
var import_jsx_runtime = require_jsx_runtime();
var SEV_COLOR = {
	critical: "#dc2626",
	high: "#f97316",
	medium: "#eab308",
	low: "#22c55e",
	info: "#3b82f6"
};
var SEV_BG = {
	critical: "rgba(220,38,38,0.12)",
	high: "rgba(249,115,22,0.12)",
	medium: "rgba(234,179,8,0.12)",
	low: "rgba(34,197,94,0.12)",
	info: "rgba(59,130,246,0.12)"
};
function sevLabel(s) {
	return {
		critical: "CRITIQUE",
		high: "ÉLEVÉ",
		medium: "MOYEN",
		low: "FAIBLE",
		info: "INFO"
	}[s] ?? s.toUpperCase();
}
function now() {
	return (/* @__PURE__ */ new Date()).toLocaleString("fr-FR", {
		day: "2-digit",
		month: "long",
		year: "numeric",
		hour: "2-digit",
		minute: "2-digit"
	});
}
function threatLevel(alerts) {
	if (alerts.some((a) => a.severity === "critical")) return {
		label: "CRITIQUE",
		color: "#dc2626"
	};
	if (alerts.some((a) => a.severity === "high")) return {
		label: "ÉLEVÉ",
		color: "#f97316"
	};
	if (alerts.some((a) => a.severity === "medium")) return {
		label: "MODÉRÉ",
		color: "#eab308"
	};
	return {
		label: "FAIBLE",
		color: "#22c55e"
	};
}
function Section({ title, icon: Icon, children }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
		className: "mb-10 print-section",
		children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
			className: "flex items-center gap-3 mb-4 pb-2 border-b-2 border-primary/30",
			children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
				className: "h-8 w-8 rounded-lg bg-primary/15 border border-primary/30 grid place-items-center shrink-0",
				children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Icon, { className: "h-4 w-4 text-primary" })
			}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
				className: "text-base font-bold uppercase tracking-widest text-primary",
				children: title
			})]
		}), children]
	});
}
function StatBox({ label, value, color }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "rounded-xl border border-border bg-card p-4 text-center",
		children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
			className: "text-2xl font-bold tabular-nums",
			style: color ? { color } : {},
			children: value
		}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
			className: "text-[11px] uppercase tracking-wider text-muted-foreground mt-1",
			children: label
		})]
	});
}
function SevBadge({ severity }) {
	const sev = (severity ?? "info").toLowerCase();
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
		className: "inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider",
		style: {
			color: SEV_COLOR[sev] ?? "#888",
			background: SEV_BG[sev] ?? "transparent",
			border: `1px solid ${SEV_COLOR[sev] ?? "#888"}44`
		},
		children: sevLabel(sev)
	});
}
function ReportsPage() {
	const { data: stats } = useStats();
	const { data: correlationsData } = useCorrelations();
	const { data: rawAlerts } = useAlerts();
	const { data: report } = useReport();
	const { data: iocData } = useIOCs();
	const { data: files } = useFilesList();
	const { data: statusData } = useAnalysisStatus();
	const { setFileFilter } = useFileSelection();
	const navigate = useNavigate();
	const alerts = Array.isArray(rawAlerts) ? rawAlerts : [];
	const iocs = Array.isArray(iocData) ? iocData : [];
	const filesList = Array.isArray(files) ? files : [];
	const correlated = Array.isArray(correlationsData?.correlated_events) ? correlationsData.correlated_events : [];
	const tools = [...new Set(alerts.map((a) => a.tool).filter(Boolean))];
	const threat = threatLevel(alerts);
	const reportDate = now();
	const topAlerts = alerts.filter((a) => ["critical", "high"].includes(a.severity)).slice(0, 20);
	const allAlerts = alerts.slice(0, 50);
	const sevCounts = alerts.reduce((acc, a) => {
		acc[a.severity] = (acc[a.severity] ?? 0) + 1;
		return acc;
	}, {});
	const handlePrint = () => window.print();
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(AppShell, {
		title: "Rapport d'investigation",
		subtitle: "Rapport professionnel à destination du management",
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "flex items-center justify-between mb-6 gap-3 flex-wrap no-print",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "flex items-center gap-2 text-sm text-muted-foreground",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Shield, { className: "h-4 w-4 text-primary" }), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", { children: ["Rapport généré automatiquement depuis les données forensiques du dossier ", /* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", {
						className: "text-foreground",
						children: "demo"
					})] })]
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "flex items-center gap-2",
					children: [
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
							onClick: handlePrint,
							className: "inline-flex items-center gap-2 rounded-lg border border-border bg-card px-4 py-2 text-sm font-medium hover:bg-muted transition-colors",
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Printer, { className: "h-4 w-4" }), " Imprimer"]
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("a", {
							href: `${API_URL}/cases/demo/report/pdf`,
							target: "_blank",
							rel: "noreferrer",
							className: "inline-flex items-center gap-2 rounded-lg bg-primary text-primary-foreground px-4 py-2 text-sm font-medium hover:opacity-90 transition-opacity",
							children: [
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Download, { className: "h-4 w-4" }),
								" Télécharger PDF ",
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)(ArrowUpRight, { className: "h-3.5 w-3.5" })
							]
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("a", {
							href: `${API_URL}/cases/demo/report`,
							target: "_blank",
							rel: "noreferrer",
							className: "inline-flex items-center gap-2 rounded-lg border border-border bg-card px-4 py-2 text-sm font-medium hover:bg-muted transition-colors",
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(FileText, { className: "h-4 w-4" }), " Export JSON"]
						})
					]
				})]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "max-w-5xl mx-auto",
				id: "report-body",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "rounded-2xl border border-border bg-card overflow-hidden mb-8",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "px-8 py-5",
							style: { background: "linear-gradient(135deg, oklch(0.20 0.04 250), oklch(0.16 0.06 220))" },
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
								className: "flex items-start justify-between flex-wrap gap-4",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [
									/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
										className: "flex items-center gap-3 mb-2",
										children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
											className: "h-10 w-10 rounded-xl bg-primary/20 border border-primary/30 grid place-items-center",
											children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Shield, { className: "h-5 w-5 text-primary" })
										}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
											className: "text-xs uppercase tracking-widest text-primary font-semibold",
											children: "ForensiQ"
										}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
											className: "text-[10px] text-muted-foreground",
											children: "Plateforme d'analyse forensique"
										})] })]
									}),
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h1", {
										className: "text-2xl font-bold mt-3",
										children: "Rapport d'Investigation Forensique"
									}),
									/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
										className: "text-sm text-muted-foreground mt-1",
										children: ["Dossier : ", /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
											className: "text-foreground font-mono font-medium",
											children: "CASE-demo"
										})]
									})
								] }), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
									className: "text-right",
									children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
										className: "inline-flex items-center gap-2 px-4 py-2 rounded-xl font-bold text-sm",
										style: {
											color: threat.color,
											background: `${threat.color}22`,
											border: `1px solid ${threat.color}44`
										},
										children: [
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)(TriangleAlert, { className: "h-4 w-4" }),
											"MENACE ",
											threat.label
										]
									}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
										className: "text-xs text-muted-foreground mt-3 space-y-1",
										children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: ["Date : ", /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
											className: "text-foreground font-mono",
											children: reportDate
										})] }), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: ["Classification : ", /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
											className: "text-[color:var(--high)] font-semibold",
											children: "CONFIDENTIEL"
										})] })]
									})]
								})]
							})
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "grid grid-cols-2 md:grid-cols-4 divide-x divide-y divide-border border-t border-border",
							children: [
								{
									label: "Référence",
									value: "CASE-demo"
								},
								{
									label: "Outils utilisés",
									value: tools.length > 0 ? tools.join(", ") : "—"
								},
								{
									label: "Période d'analyse",
									value: alerts.length > 0 ? String(alerts[alerts.length - 1]?.timestamp ?? "").slice(0, 10) || "—" : "—"
								},
								{
									label: "Niveau de confidentialité",
									value: "Confidentiel"
								}
							].map((m) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
								className: "px-5 py-3",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
									className: "text-[10px] uppercase tracking-wider text-muted-foreground",
									children: m.label
								}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
									className: "text-sm font-medium mt-0.5 truncate",
									children: m.value
								})]
							}, m.label))
						})]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Section, {
						title: "Résumé exécutif",
						icon: FileText,
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "rounded-xl border border-border bg-card/60 p-6",
							children: alerts.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
								className: "text-sm text-muted-foreground italic",
								children: "Aucune donnée disponible. Uploadez un fichier forensique pour générer ce rapport."
							}) : /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
								className: "space-y-4 text-sm leading-relaxed",
								children: [
									/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", { children: [
										"Dans le cadre de l'investigation forensique du dossier ",
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: "CASE-demo" }),
										", une analyse approfondie a été conduite à l'aide de la plateforme ForensiQ. L'analyse a porté sur",
										" ",
										/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("strong", { children: [filesList.length, " fichier(s)"] }),
										" soumis par l'équipe technique, générant au total",
										" ",
										/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("strong", { children: [stats?.alerts ?? alerts.length, " alertes"] }),
										" issues de",
										" ",
										/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("strong", { children: [tools.length || 1, " source(s)"] }),
										" forensique(s) différente(s)",
										tools.length > 0 && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(import_jsx_runtime.Fragment, { children: [
											" (",
											tools.join(", "),
											")"
										] }),
										"."
									] }),
									/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", { children: [
										"L'évaluation du niveau de risque est jugée",
										" ",
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", {
											style: { color: threat.color },
											children: threat.label
										}),
										".",
										" ",
										sevCounts["critical"] > 0 && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(import_jsx_runtime.Fragment, { children: [
											"On dénombre ",
											/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("strong", { children: [sevCounts["critical"], " alerte(s) de niveau critique"] }),
											" nécessitant une action immédiate.",
											" "
										] }),
										sevCounts["high"] > 0 && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(import_jsx_runtime.Fragment, { children: [
											/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("strong", { children: [sevCounts["high"], " alerte(s) de niveau élevé"] }),
											" ont également été identifiées.",
											" "
										] }),
										(stats?.iocs ?? 0) > 0 && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(import_jsx_runtime.Fragment, { children: [
											"Au total, ",
											/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("strong", { children: [stats?.iocs, " indicateur(s) de compromission (IOC)"] }),
											" ont été extraits et documentés.",
											" "
										] }),
										correlated.length > 0 && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(import_jsx_runtime.Fragment, { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("strong", { children: [correlated.length, " corrélation(s) host/réseau"] }), " ont été détectées, suggérant une chaîne d'attaque coordonnée."] })
									] }),
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
										className: "border-l-2 border-primary/50 pl-4 text-muted-foreground italic",
										children: "Ce rapport est destiné à la direction et aux équipes de sécurité. Les conclusions présentées reposent exclusivement sur les artefacts forensiques analysés et les règles de détection appliquées."
									})
								]
							})
						})
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Section, {
						title: "Indicateurs clés",
						icon: Cpu,
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
							className: "grid grid-cols-2 md:grid-cols-4 gap-3 mb-4",
							children: [
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)(StatBox, {
									label: "Fichiers analysés",
									value: stats?.files_analyzed ?? filesList.length
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)(StatBox, {
									label: "Alertes totales",
									value: stats?.alerts ?? alerts.length,
									color: threat.color
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)(StatBox, {
									label: "IOCs détectés",
									value: stats?.iocs ?? iocs.length,
									color: "#f97316"
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)(StatBox, {
									label: "Corrélations",
									value: correlated.length,
									color: "#a78bfa"
								})
							]
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "grid grid-cols-2 md:grid-cols-4 gap-3",
							children: [
								{
									label: "Critique",
									key: "critical",
									color: "#dc2626"
								},
								{
									label: "Élevé",
									key: "high",
									color: "#f97316"
								},
								{
									label: "Moyen",
									key: "medium",
									color: "#eab308"
								},
								{
									label: "Faible",
									key: "low",
									color: "#22c55e"
								}
							].map((s) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
								className: "rounded-xl border p-4 flex items-center gap-3",
								style: {
									borderColor: `${s.color}33`,
									background: `${s.color}0d`
								},
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
									className: "h-3 w-3 rounded-full shrink-0",
									style: { background: s.color }
								}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
									className: "text-lg font-bold tabular-nums",
									style: { color: s.color },
									children: sevCounts[s.key] ?? 0
								}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
									className: "text-[10px] text-muted-foreground uppercase tracking-wider",
									children: s.label
								})] })]
							}, s.key))
						})]
					}),
					filesList.length > 0 && /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Section, {
						title: "Fichiers analysés",
						icon: FileExclamationPoint,
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "rounded-xl border border-border overflow-hidden",
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("table", {
								className: "w-full text-sm",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("thead", {
									className: "bg-muted/40 text-xs uppercase text-muted-foreground",
									children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("tr", { children: [
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
											className: "text-left px-4 py-3",
											children: "Nom du fichier"
										}),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
											className: "text-left px-4 py-3",
											children: "Outil détecté"
										}),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
											className: "text-left px-4 py-3",
											children: "Alertes extraites"
										}),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
											className: "text-left px-4 py-3",
											children: "Statut"
										}),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
											className: "text-left px-4 py-3",
											children: "Date d'import"
										}),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
											className: "text-right px-4 py-3 no-print",
											children: "Action"
										})
									] })
								}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("tbody", {
									className: "divide-y divide-border",
									children: filesList.map((f, i) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("tr", {
										className: "hover:bg-muted/20",
										children: [
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
												className: "px-4 py-3 font-mono text-xs font-medium",
												children: f.filename
											}),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
												className: "px-4 py-3",
												children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
													className: "px-2 py-0.5 rounded text-[10px] font-medium bg-primary/10 text-primary border border-primary/20",
													children: (f.tool ?? "unknown").toUpperCase()
												})
											}),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
												className: "px-4 py-3 tabular-nums font-semibold",
												children: f.alert_count ?? 0
											}),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
												className: "px-4 py-3",
												children: f.status === "parsed" ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", {
													className: "flex items-center gap-1 text-[color:var(--success)] text-xs",
													children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(CircleCheck, { className: "h-3 w-3" }), " Analysé"]
												}) : f.status === "error" ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", {
													className: "flex items-center gap-1 text-destructive text-xs",
													children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(CircleX, { className: "h-3 w-3" }), " Erreur"]
												}) : /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
													className: "text-xs text-muted-foreground",
													children: f.status
												})
											}),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
												className: "px-4 py-3 font-mono text-xs text-muted-foreground",
												children: String(f.uploaded_at ?? "").slice(0, 19)
											}),
											/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("td", {
												className: "px-4 py-3 text-right no-print flex items-center justify-end gap-2",
												children: [f.status === "parsed" && /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
													onClick: () => {
														setFileFilter(f.id, f.filename);
														navigate({ to: "/" });
													},
													className: "inline-flex items-center gap-1.5 px-2.5 py-1.5 border border-primary/20 hover:bg-primary/10 text-primary text-xs font-medium rounded transition-colors",
													title: "Filtrer le dashboard pour ce fichier",
													children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Funnel, { className: "h-3.5 w-3.5" })
												}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("a", {
													href: `http://localhost:8000/cases/demo/files/${f.id}/report/pdf`,
													target: "_blank",
													rel: "noreferrer",
													className: "inline-flex items-center gap-1.5 px-3 py-1.5 bg-primary/10 hover:bg-primary/20 text-primary text-xs font-medium rounded transition-colors",
													title: "Télécharger le rapport détaillé de ce fichier",
													children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Download, { className: "h-3.5 w-3.5" }), " PDF"]
												})]
											})
										]
									}, i))
								})]
							})
						})
					}),
					topAlerts.length > 0 && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Section, {
						title: "Alertes critiques et élevées",
						icon: TriangleAlert,
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "rounded-xl border border-border overflow-hidden",
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("table", {
								className: "w-full text-sm",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("thead", {
									className: "bg-muted/40 text-xs uppercase text-muted-foreground",
									children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("tr", { children: [
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
											className: "text-left px-4 py-3 w-8",
											children: "#"
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
											children: "Règle & Cible"
										}),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
											className: "text-left px-4 py-3",
											children: "Horodatage"
										})
									] })
								}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("tbody", {
									className: "divide-y divide-border",
									children: topAlerts.map((a, i) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("tr", {
										className: "hover:bg-muted/20 transition-colors",
										children: [
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
												className: "px-4 py-3 text-xs text-muted-foreground tabular-nums",
												children: i + 1
											}),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
												className: "px-4 py-3",
												children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(SevBadge, { severity: a.severity })
											}),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
												className: "px-4 py-3",
												children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
													className: "text-[10px] font-mono px-1.5 py-0.5 rounded bg-muted border border-border",
													children: (a.tool ?? "?").toUpperCase()
												})
											}),
											/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("td", {
												className: "px-4 py-3 font-medium max-w-xs",
												children: [
													/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
														className: "truncate",
														children: a.title ?? "—"
													}),
													a.mitre_attack && /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
														className: "text-[10px] text-muted-foreground font-mono mt-0.5",
														children: a.mitre_attack
													}),
													/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
														className: "text-xs text-muted-foreground font-mono mt-1 truncate max-w-xs",
														title: a.target ?? a.dst_ip,
														children: ["Cible: ", a.target ?? a.dst_ip ?? "—"]
													})
												]
											}),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
												className: "px-4 py-3 font-mono text-xs text-muted-foreground tabular-nums",
												children: String(a.timestamp ?? "—").slice(0, 19)
											})
										]
									}, i))
								})]
							})
						}), alerts.filter((a) => ["critical", "high"].includes(a.severity)).length > 20 && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
							className: "text-xs text-muted-foreground mt-2 text-center",
							children: [
								"… et ",
								alerts.filter((a) => ["critical", "high"].includes(a.severity)).length - 20,
								" alerte(s) supplémentaire(s). Consultez la page Alertes pour la liste complète."
							]
						})]
					}),
					allAlerts.length > 0 && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Section, {
						title: "Journal complet des alertes",
						icon: Shield,
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "rounded-xl border border-border overflow-hidden",
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("table", {
								className: "w-full text-sm",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("thead", {
									className: "bg-muted/40 text-xs uppercase text-muted-foreground",
									children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("tr", { children: [
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
											children: "Titre"
										}),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
											className: "text-left px-4 py-3",
											children: "Cible"
										}),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
											className: "text-left px-4 py-3",
											children: "Horodatage"
										})
									] })
								}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("tbody", {
									className: "divide-y divide-border",
									children: allAlerts.map((a, i) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("tr", {
										className: "hover:bg-muted/20 transition-colors",
										children: [
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
												className: "px-4 py-2",
												children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(SevBadge, { severity: a.severity })
											}),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
												className: "px-4 py-2",
												children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
													className: "text-[10px] font-mono px-1.5 py-0.5 rounded bg-muted border border-border",
													children: (a.tool ?? "?").toUpperCase()
												})
											}),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
												className: "px-4 py-2 font-medium text-xs max-w-xs",
												children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
													className: "truncate",
													children: a.title ?? "—"
												})
											}),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
												className: "px-4 py-2 font-mono text-xs text-muted-foreground max-w-xs",
												children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
													className: "truncate",
													children: a.target ?? a.dst_ip ?? "—"
												})
											}),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
												className: "px-4 py-2 font-mono text-xs text-muted-foreground",
												children: String(a.timestamp ?? "—").slice(0, 19)
											})
										]
									}, i))
								})]
							})
						}), alerts.length > 50 && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
							className: "text-xs text-muted-foreground mt-2 text-center",
							children: [
								"Affichage des 50 premières alertes sur ",
								alerts.length,
								" au total."
							]
						})]
					}),
					iocs.length > 0 && /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Section, {
						title: "Indicateurs de compromission (IOCs)",
						icon: FingerprintPattern,
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "rounded-xl border border-border overflow-hidden",
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("table", {
								className: "w-full text-sm",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("thead", {
									className: "bg-muted/40 text-xs uppercase text-muted-foreground",
									children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("tr", { children: [
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
											className: "text-left px-4 py-3",
											children: "Type"
										}),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
											className: "text-left px-4 py-3",
											children: "Valeur"
										}),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
											className: "text-left px-4 py-3",
											children: "Source"
										}),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
											className: "text-left px-4 py-3",
											children: "Occurrences"
										}),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
											className: "text-left px-4 py-3",
											children: "1ère détection"
										})
									] })
								}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("tbody", {
									className: "divide-y divide-border",
									children: iocs.slice(0, 30).map((ioc, i) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("tr", {
										className: "hover:bg-muted/20 transition-colors",
										children: [
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
												className: "px-4 py-3",
												children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
													className: "text-[10px] uppercase tracking-wider px-2 py-0.5 rounded border border-border bg-muted",
													children: ioc.type
												})
											}),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
												className: "px-4 py-3 font-mono text-xs max-w-xs truncate",
												children: ioc.value
											}),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
												className: "px-4 py-3",
												children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
													className: "text-[10px] font-mono px-1.5 py-0.5 rounded bg-muted border border-border",
													children: (ioc.source ?? "?").toUpperCase()
												})
											}),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
												className: "px-4 py-3 tabular-nums font-semibold",
												children: ioc.hits
											}),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
												className: "px-4 py-3 font-mono text-xs text-muted-foreground",
												children: String(ioc.firstSeen ?? "—").slice(0, 19)
											})
										]
									}, i))
								})]
							})
						})
					}),
					correlated.length > 0 && /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Section, {
						title: "Corrélations host / réseau",
						icon: Network,
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "space-y-3",
							children: correlated.map((c, i) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
								className: "rounded-xl border border-[#dc262633] bg-[#dc26260a] p-5",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
									className: "flex items-start gap-3",
									children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
										className: "h-8 w-8 rounded-lg bg-[#dc2626]/15 border border-[#dc2626]/30 grid place-items-center shrink-0 mt-0.5",
										children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Network, { className: "h-4 w-4 text-[#dc2626]" })
									}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
										className: "flex-1 min-w-0",
										children: [
											/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
												className: "flex items-center gap-2 flex-wrap mb-1",
												children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", {
													className: "text-xs font-mono text-muted-foreground",
													children: ["CORR-", String(i + 1).padStart(2, "0")]
												}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(SevBadge, { severity: c.risk ?? "critical" })]
											}),
											/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
												className: "font-semibold text-sm mb-1",
												children: c.host_event
											}),
											/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
												className: "text-xs text-muted-foreground",
												children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
													className: "mr-2",
													children: "Fenêtre temporelle :"
												}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("code", {
													className: "font-mono bg-muted px-1 rounded",
													children: c.time_window
												})]
											}),
											c.network_events?.length > 0 && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
												className: "mt-2 flex items-center gap-1 flex-wrap",
												children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
													className: "text-[10px] text-muted-foreground mr-1",
													children: "Événements réseau corrélés :"
												}), c.network_events.slice(0, 3).map((ne, ni) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
													className: "text-[10px] font-mono px-1.5 py-0.5 rounded bg-muted border border-border",
													children: ne
												}, ni))]
											})
										]
									})]
								})
							}, i))
						})
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Section, {
						title: "Recommandations",
						icon: CircleCheck,
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "space-y-3",
							children: [
								{
									priority: "IMMÉDIAT",
									color: "#dc2626",
									show: alerts.some((a) => a.severity === "critical"),
									items: [
										"Isoler immédiatement le(s) système(s) compromis du réseau de production.",
										"Révoquer et réinitialiser tous les comptes d'utilisateurs potentiellement compromis.",
										"Activer le plan de réponse aux incidents et notifier l'équipe CSIRT."
									]
								},
								{
									priority: "COURT TERME (< 48h)",
									color: "#f97316",
									show: true,
									items: [
										iocs.filter((i) => i.type === "IP").length > 0 ? `Bloquer les ${iocs.filter((i) => i.type === "IP").length} adresse(s) IP malveillante(s) identifiées sur le pare-feu et les équipements réseau.` : "Mettre à jour les règles de filtrage réseau.",
										"Effectuer une analyse approfondie des autres postes du même segment réseau pour détecter une éventuelle propagation latérale.",
										"Collecter et conserver toutes les preuves numériques (images disque, logs) pour l'investigation judiciaire."
									]
								},
								{
									priority: "MOYEN TERME (< 2 semaines)",
									color: "#eab308",
									show: true,
									items: [
										"Restaurer les systèmes compromis à partir de sauvegardes vérifiées et saines.",
										"Mettre à jour et renforcer les politiques de sécurité (MFA, privilèges minimaux).",
										"Déployer des règles de détection supplémentaires basées sur les IOCs identifiés dans ce rapport.",
										"Planifier une revue complète des journaux d'accès pour la période concernée."
									]
								},
								{
									priority: "LONG TERME",
									color: "#22c55e",
									show: true,
									items: [
										"Renforcer la formation des équipes aux bonnes pratiques de sécurité.",
										"Implémenter une solution SIEM/SOAR pour une détection continue des menaces.",
										"Effectuer des tests d'intrusion réguliers pour identifier les faiblesses résiduelles."
									]
								}
							].filter((r) => r.show).map((r) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
								className: "rounded-xl border p-5",
								style: {
									borderColor: `${r.color}33`,
									background: `${r.color}08`
								},
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
									className: "text-[11px] font-bold uppercase tracking-widest mb-3 flex items-center gap-2",
									style: { color: r.color },
									children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
										className: "h-1.5 w-1.5 rounded-full",
										style: { background: r.color }
									}), r.priority]
								}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
									className: "space-y-2",
									children: r.items.map((item, i) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
										className: "flex items-start gap-2 text-sm",
										children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(ChevronRight, {
											className: "h-4 w-4 shrink-0 mt-0.5",
											style: { color: r.color }
										}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { children: item })]
									}, i))
								})]
							}, r.priority))
						})
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Section, {
						title: "Conclusion",
						icon: Globe,
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
							className: "rounded-xl border border-border bg-card/60 p-6 text-sm leading-relaxed space-y-3",
							children: [
								/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", { children: [
									"Cette investigation forensique a permis d'identifier et de documenter les menaces présentes dans le système analysé. Le niveau de risque global est évalué à",
									" ",
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", {
										style: { color: threat.color },
										children: threat.label
									}),
									" sur la base des",
									" ",
									stats?.alerts ?? alerts.length,
									" alertes générées."
								] }),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: "Les recommandations formulées dans ce rapport doivent être mises en œuvre dans les délais indiqués afin de contenir la menace et de rétablir la sécurité opérationnelle. Une surveillance continue est préconisée dans les semaines suivant cet incident." }),
								/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
									className: "text-muted-foreground text-xs border-t border-border pt-3 mt-3",
									children: [
										"Ce rapport a été généré automatiquement par la plateforme ForensiQ le ",
										reportDate,
										". Les résultats présentés sont basés sur l'analyse des artefacts fournis et ne constituent pas un avis juridique. Pour toute question, contactez l'équipe de cybersécurité."
									]
								})
							]
						})
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "border-t border-border pt-6 pb-4 flex items-center justify-between text-xs text-muted-foreground",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
							className: "flex items-center gap-2",
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Shield, { className: "h-4 w-4 text-primary" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { children: "ForensiQ — Plateforme d'analyse forensique" })]
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [
							"Rapport généré le ",
							reportDate,
							" · CASE-demo · CONFIDENTIEL"
						] })]
					})
				]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("style", { children: `
        @media print {
          .no-print { display: none !important; }
          aside, header { display: none !important; }
          main { padding: 0 !important; }
          body { background: white !important; color: black !important; }
          .print-section { break-inside: avoid; }
          #report-body { max-width: 100% !important; }
        }
      ` })
		]
	});
}
//#endregion
export { ReportsPage as component };
