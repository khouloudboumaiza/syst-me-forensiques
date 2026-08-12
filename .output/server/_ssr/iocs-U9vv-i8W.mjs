import { i as __toESM } from "../_runtime.mjs";
import { a as require_jsx_runtime, n as useQuery, o as require_react } from "../_libs/react+tanstack__react-query.mjs";
import { M as Copy, a as TriangleAlert, c as Sparkles, d as ShieldCheck, f as ShieldAlert, g as LoaderCircle, u as ShieldX, w as FingerprintPattern } from "../_libs/lucide-react.mjs";
import { a as ToolBadge, d as useIOCs, n as AppShell, r as Card, t as API_URL, u as useFilesList } from "./app-shell-CXKz5zjF.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/iocs-U9vv-i8W.js
var import_react = /* @__PURE__ */ __toESM(require_react());
var import_jsx_runtime = require_jsx_runtime();
var IOC_TYPES = [
	"IP",
	"Hash",
	"Domain",
	"File",
	"Registry"
];
var classifyCache = {};
var STATUS_CONFIG = {
	true_positive: {
		label: "Vrai Positif",
		icon: ShieldX,
		cls: "bg-destructive/15 text-destructive border-destructive/30"
	},
	likely_false_positive: {
		label: "Faux Positif (Probable)",
		icon: ShieldCheck,
		cls: "bg-[color:var(--success)]/15 text-[color:var(--success)] border-[color:var(--success)]/30"
	},
	potential_false_negative: {
		label: "Faux Négatif (Potentiel)",
		icon: ShieldAlert,
		cls: "bg-orange-500/15 text-orange-500 border-orange-500/30"
	},
	suspicious_review: {
		label: "Suspect (À revoir)",
		icon: ShieldAlert,
		cls: "bg-[color:var(--medium)]/15 text-[color:var(--medium)] border-[color:var(--medium)]/30"
	},
	clean: {
		label: "Sain",
		icon: ShieldCheck,
		cls: "bg-[color:var(--success)]/15 text-[color:var(--success)] border-[color:var(--success)]/30"
	}
};
var isHashLike = (value) => typeof value === "string" && /[a-f0-9]{8,64}/i.test(value);
function VirusTotalCell({ ioc }) {
	const lookupHash = ioc.linkedHash || (ioc.type === "Hash" ? ioc.value : "");
	const isHash = ioc.type === "Hash" || ioc.type === "IP" || Boolean(lookupHash);
	if (ioc.vtScore && ioc.vtScore !== "—") return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
		className: `inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold border ${ioc.vtVerdict === "malicious" ? "bg-destructive/15 text-destructive border-destructive/30" : ioc.vtVerdict === "clean" ? "bg-success/15 text-success border-success/30" : "bg-medium/15 text-medium border-medium/30"}`,
		children: ioc.vtScore
	});
	const { data, isLoading } = useQuery({
		queryKey: [
			"vt",
			ioc.type,
			lookupHash || ioc.value
		],
		queryFn: () => fetch(`${API_URL}/vt/hash/${encodeURIComponent(lookupHash || ioc.value)}`).then((r) => r.json()),
		enabled: isHash && isHashLike(lookupHash || ioc.value) && !ioc.vtScore,
		staleTime: Infinity
	});
	if (!isHash || !isHashLike(lookupHash || ioc.value)) return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
		className: "text-xs text-muted-foreground",
		children: "—"
	});
	if (isLoading) return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(LoaderCircle, { className: "h-3 w-3 animate-spin text-muted-foreground" });
	if (data && data.found) {
		const total = (data.malicious || 0) + (data.suspicious || 0) + (data.harmless || 0);
		const scoreStr = `${data.malicious}/${total}`;
		return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
			className: `inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold border ${data.verdict === "malicious" ? "bg-destructive/15 text-destructive border-destructive/30" : data.verdict === "clean" ? "bg-success/15 text-success border-success/30" : "bg-medium/15 text-medium border-medium/30"}`,
			children: scoreStr
		});
	}
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
		className: "text-[10px] text-muted-foreground",
		children: "0/0"
	});
}
function AIClassifyCell({ ioc }) {
	const [state, setState] = (0, import_react.useState)("idle");
	const [result, setResult] = (0, import_react.useState)(null);
	const lookupHash = ioc.linkedHash || (ioc.type === "Hash" ? ioc.value : "");
	const { data: vtData } = useQuery({
		queryKey: [
			"vt",
			ioc.type,
			lookupHash || ioc.value
		],
		queryFn: () => fetch(`${API_URL}/vt/hash/${encodeURIComponent(lookupHash || ioc.value)}`).then((r) => r.json()),
		enabled: isHashLike(lookupHash || ioc.value),
		staleTime: Infinity
	});
	const handleClassify = (0, import_react.useCallback)(async (e) => {
		e.stopPropagation();
		if (state === "loading") return;
		const cacheKey = `${ioc.value}|${ioc.type}|${lookupHash || ""}`;
		if (classifyCache[cacheKey]) {
			setResult(classifyCache[cacheKey]);
			setState("done");
			return;
		}
		setState("loading");
		try {
			const body = {
				hash_value: lookupHash || (ioc.type === "Hash" ? ioc.value : ""),
				file_path: ioc.filename || ioc.value || "",
				tool: ioc.source || "",
				vt_malicious: 0,
				vt_total: 0,
				vt_verdict: "unknown"
			};
			if (vtData && vtData.found) {
				const total = (vtData.malicious || 0) + (vtData.suspicious || 0) + (vtData.harmless || 0);
				body.vt_malicious = vtData.malicious || 0;
				body.vt_total = total;
				body.vt_verdict = vtData.verdict || "unknown";
			}
			const res = await fetch(`${API_URL}/classify-ioc`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(body)
			});
			if (!res.ok) throw new Error("Erreur API");
			const data = await res.json();
			classifyCache[cacheKey] = data;
			setResult(data);
			setState("done");
		} catch {
			setState("error");
		}
	}, [
		ioc,
		vtData,
		state
	]);
	if (state === "idle") return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
		onClick: handleClassify,
		className: "inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-[11px] font-medium border border-violet-500/30 text-violet-400 bg-violet-500/5 hover:bg-violet-500/15 transition-all group",
		children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Sparkles, { className: "h-3 w-3 group-hover:animate-pulse" }), "Classer via IA"]
	});
	if (state === "loading") return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "inline-flex items-center gap-1.5 text-[11px] text-muted-foreground",
		children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(LoaderCircle, { className: "h-3 w-3 animate-spin text-violet-400" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
			className: "animate-pulse",
			children: "Analyse IA…"
		})]
	});
	if (state === "error") return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
		onClick: handleClassify,
		className: "text-[11px] text-destructive underline",
		children: "Erreur — Réessayer"
	});
	const cfg = STATUS_CONFIG[result?.status] || STATUS_CONFIG["suspicious_review"];
	const Icon = cfg.icon;
	const confValue = result?.confidence !== void 0 ? Math.round(result.confidence) : 0;
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "space-y-2 max-w-xs",
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: `inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-bold border ${cfg.cls}`,
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Icon, { className: "h-3 w-3" }),
					cfg.label,
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", {
						className: "opacity-60 text-[9px]",
						children: [
							"(",
							confValue,
							"%)"
						]
					})
				]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "text-[11px] text-muted-foreground leading-relaxed line-clamp-3",
				title: result?.explanation,
				children: result?.explanation
			}),
			result?.recommendation && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
				className: "text-[10px] text-primary/70 bg-primary/5 rounded p-1.5 border border-primary/10 leading-snug",
				children: ["💡 ", result.recommendation]
			})
		]
	});
}
function IocsPage() {
	const { data: iocs, isLoading, isError } = useIOCs();
	const { data: files } = useFilesList();
	const [copied, setCopied] = (0, import_react.useState)(null);
	const [filter, setFilter] = (0, import_react.useState)("all");
	const iocList = Array.isArray(iocs) ? iocs : [];
	const enrichedIocs = (0, import_react.useMemo)(() => {
		const filesMap = (Array.isArray(files) ? files : []).reduce((acc, f) => ({
			...acc,
			[f.id]: f.filename
		}), {});
		return iocList.map((ioc) => ({
			...ioc,
			filename: ioc.file_id ? filesMap[ioc.file_id] || "Inconnu" : "Inconnu"
		}));
	}, [iocList, files]);
	const filtered = filter === "all" ? enrichedIocs : enrichedIocs.filter((i) => i.type === filter);
	const handleCopy = (value) => {
		navigator.clipboard.writeText(value);
		setCopied(value);
		setTimeout(() => setCopied(null), 2e3);
	};
	enrichedIocs.filter((i) => i.type === "Hash");
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(AppShell, {
		title: "Indicateurs de compromission",
		subtitle: isLoading ? "Chargement depuis le backend…" : `${iocList.length} IOC(s) extraits et normalisés depuis les alertes`,
		children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
			className: "grid grid-cols-2 md:grid-cols-6 gap-3 mb-4",
			children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
				onClick: () => setFilter("all"),
				className: `col-span-1 rounded-lg border p-4 text-left transition-colors ${filter === "all" ? "border-primary bg-primary/10" : "border-border bg-card hover:border-primary/40"}`,
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "flex items-center gap-2 text-xs text-muted-foreground",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(FingerprintPattern, { className: "h-3.5 w-3.5" }), " Tous"]
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
					className: "text-2xl font-semibold mt-2 tabular-nums",
					children: iocList.length
				})]
			}), IOC_TYPES.map((t) => {
				const count = iocList.filter((i) => i.type === t).length;
				return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
					onClick: () => setFilter(t),
					className: `rounded-lg border p-4 text-left transition-colors ${filter === t ? "border-primary bg-primary/10" : "border-border bg-card hover:border-primary/40"}`,
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "flex items-center gap-2 text-xs text-muted-foreground",
						children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(FingerprintPattern, { className: "h-3.5 w-3.5" }),
							" ",
							t
						]
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
						className: "text-2xl font-semibold mt-2 tabular-nums",
						children: count
					})]
				}, t);
			})]
		}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, { children: [
			isLoading && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "flex items-center justify-center gap-2 py-12 text-sm text-muted-foreground",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(LoaderCircle, { className: "h-4 w-4 animate-spin" }), " Chargement des IOCs depuis le backend…"]
			}),
			isError && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "flex items-center justify-center gap-2 py-12 text-sm text-destructive",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(TriangleAlert, { className: "h-4 w-4" }), " Impossible de contacter le backend (localhost:8000)."]
			}),
			!isLoading && !isError && filtered.length === 0 && /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
				className: "py-12 text-center text-sm text-muted-foreground",
				children: "Aucun IOC extrait. Uploadez un fichier depuis la page Import."
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
								children: "Type"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
								className: "text-left px-4 py-3",
								children: "Valeur"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
								className: "text-left px-4 py-3",
								children: "Outil"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
								className: "text-left px-4 py-3",
								children: "Fichier analysé"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
								className: "text-left px-4 py-3",
								children: "VirusTotal"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
								className: "text-left px-4 py-3",
								children: "Occurrences"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
								className: "text-left px-4 py-3",
								children: "1ère détection"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", {
								className: "text-left px-4 py-3 min-w-55",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", {
									className: "inline-flex items-center gap-1",
									children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Sparkles, { className: "h-3 w-3 text-violet-400" }), " Classification IA"]
								})
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("th", { className: "px-4 py-3" })
						] })
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("tbody", {
						className: "divide-y divide-border",
						children: filtered.map((i) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("tr", {
							className: "hover:bg-muted/30 transition-colors align-top",
							children: [
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
									className: "px-4 py-3",
									children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
										className: "text-[10px] uppercase tracking-wider px-2 py-0.5 rounded border border-border bg-muted",
										children: i.type
									})
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
									className: "px-4 py-3 font-mono text-xs max-w-xs truncate",
									title: i.value,
									children: i.value
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
									className: "px-4 py-3",
									children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ToolBadge, { tool: i.source })
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
									className: "px-4 py-3 font-mono text-xs text-muted-foreground max-w-xs truncate",
									title: i.filename,
									children: i.filename
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
									className: "px-4 py-3",
									children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(VirusTotalCell, { ioc: i })
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
									className: "px-4 py-3 tabular-nums",
									children: i.hits
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
									className: "px-4 py-3 font-mono text-xs text-muted-foreground",
									children: String(i.firstSeen ?? "—").slice(0, 19)
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
									className: "px-4 py-3",
									children: i.type === "Hash" || i.type === "File" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(AIClassifyCell, { ioc: i }) : /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
										className: "text-xs text-muted-foreground",
										children: "—"
									})
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("td", {
									className: "px-4 py-3",
									children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
										onClick: () => handleCopy(i.value),
										title: "Copier la valeur",
										className: "h-7 w-7 grid place-items-center rounded border border-border hover:bg-muted transition-colors",
										children: copied === i.value ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
											className: "text-[8px] text-success font-bold",
											children: "OK"
										}) : /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Copy, { className: "h-3 w-3" })
									})
								})
							]
						}, i.value))
					})]
				})
			})
		] })]
	});
}
//#endregion
export { IocsPage as component };
