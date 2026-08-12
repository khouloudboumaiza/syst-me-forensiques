import { a as require_jsx_runtime, i as useQueryClient, n as useQuery, t as useMutation } from "../_libs/react+tanstack__react-query.mjs";
import { n as useFileSelection } from "./useFileSelection-BQQdt2sG.mjs";
import { g as Link, l as useRouterState } from "../_libs/@tanstack/react-router+[...].mjs";
import { C as FunnelX, D as FileText, F as Clock3, K as Activity, L as CircleUser, T as Files, U as Bell, f as ShieldAlert, h as Network, i as Upload, k as FileCheck, n as Wifi, p as Search, r as WifiOff, v as LayoutDashboard, w as FingerprintPattern } from "../_libs/lucide-react.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/app-shell-CXKz5zjF.js
var import_jsx_runtime = require_jsx_runtime();
var API_URL = "http://localhost:8000";
var CASE_ID = "demo";
var STALE_TIME = 4e3;
var IDLE_POLL = 8e3;
var ACTIVE_POLL = 1500;
function buildIOCsFromAlerts(alerts, filesMap) {
	if (!Array.isArray(alerts)) return [];
	const iocMap = /* @__PURE__ */ new Map();
	for (const a of alerts) {
		const addIoc = (value, type, extra = {}) => {
			if (!value || value.length < 4) return;
			const key = `${type}:${value}`;
			if (!iocMap.has(key)) iocMap.set(key, {
				value,
				type,
				source: a.tool ?? "unknown",
				file_id: a.file_id,
				filename: filesMap?.[a.file_id] || "Inconnu",
				hits: 0,
				firstSeen: a.timestamp ?? "—",
				severity: a.severity ?? "info",
				...extra
			});
			iocMap.get(key).hits += 1;
		};
		let linkedHash = "";
		let vtScore = "—";
		let vtVerdict;
		if (a.threat_intel) try {
			const tiList = typeof a.threat_intel === "string" ? JSON.parse(a.threat_intel) : a.threat_intel;
			if (Array.isArray(tiList)) {
				const hashEntry = tiList.find((ti) => ti.type === "hash" && ti.value);
				if (hashEntry) {
					linkedHash = hashEntry.value;
					vtScore = hashEntry.found ? `${hashEntry.malicious}/${(hashEntry.malicious || 0) + (hashEntry.suspicious || 0) + (hashEntry.harmless || 0)}` : "—";
					vtVerdict = hashEntry.verdict;
				}
				for (const ti of tiList) if (ti.type === "hash" || ti.type === "ip") {
					const score = ti.found ? `${ti.malicious}/${(ti.malicious || 0) + (ti.suspicious || 0) + (ti.harmless || 0)}` : "—";
					const typeLabel = ti.type === "hash" ? "Hash" : "IP";
					addIoc(ti.value, typeLabel, {
						vtScore: score,
						vtVerdict: ti.verdict
					});
				}
			}
		} catch (e) {
			console.error("Error parsing threat_intel", e);
		}
		addIoc(a.dst_ip, "IP");
		addIoc(a.src_ip, "IP");
		const fileValue = a.file_path ?? a.target ?? "";
		if (fileValue) addIoc(fileValue, "File", {
			linkedHash,
			vtScore,
			vtVerdict
		});
		const textToSearch = `${a.title} ${a.details} ${a.target}`.toLowerCase();
		const ips = textToSearch.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g);
		if (ips) ips.forEach((ip) => addIoc(ip, "IP"));
		const hashes = textToSearch.match(/\b[a-f0-9]{32,64}\b/g);
		if (hashes) hashes.forEach((hash) => addIoc(hash, "Hash"));
		const files = textToSearch.match(/\b[a-z0-9_.-]+\.(exe|dll|ps1|bat|sh|bin|vbs)\b/g);
		if (files) files.forEach((f) => addIoc(f, "File"));
	}
	return Array.from(iocMap.values());
}
function buildTimelineFromAlerts(alerts) {
	if (!Array.isArray(alerts)) return [];
	return [...alerts].filter((a) => a.timestamp).sort((a, b) => String(a.timestamp).localeCompare(String(b.timestamp))).map((a) => ({
		time: String(a.timestamp ?? "").slice(11, 19) || "—",
		fullTimestamp: a.timestamp,
		source: a.tool ?? "unknown",
		severity: (a.severity ?? "info").toLowerCase(),
		title: a.title ?? a.rule ?? "Événement",
		detail: a.details ?? a.description ?? "",
		target: a.target ?? a.dst_ip ?? ""
	}));
}
function buildArtifactsFromAlerts(alerts) {
	if (!Array.isArray(alerts)) return [];
	const seen = /* @__PURE__ */ new Set();
	const result = [];
	for (const a of alerts) {
		const path = a.file_path ?? a.target ?? "";
		if (!path || seen.has(path)) continue;
		seen.add(path);
		const parts = path.replace(/\\/g, "/").split("/");
		const name = parts[parts.length - 1] || path;
		const dir = parts.slice(0, -1).join("/") || "/";
		const sev = (a.severity ?? "").toLowerCase();
		result.push({
			name,
			path: dir,
			hash: a.mitre_attack ? `MITRE: ${a.mitre_attack}` : "—",
			source: a.tool ?? "unknown",
			tag: sev === "critical" ? "malware" : sev === "high" ? "suspicious" : "log",
			severity: a.severity ?? "info",
			timestamp: a.timestamp ?? "—"
		});
	}
	return result;
}
var _lastUploadAt = 0;
var ACTIVE_WINDOW_MS = 3e4;
function getRefetchInterval() {
	return Date.now() - _lastUploadAt < ACTIVE_WINDOW_MS ? ACTIVE_POLL : IDLE_POLL;
}
function useStats() {
	const { selectedFileId } = useFileSelection();
	return useQuery({
		queryKey: [
			"stats",
			CASE_ID,
			selectedFileId
		],
		queryFn: () => fetch(`${API_URL}/cases/${CASE_ID}/stats${selectedFileId ? `?file_id=${selectedFileId}` : ""}`).then((r) => r.json()),
		staleTime: STALE_TIME,
		refetchInterval: getRefetchInterval
	});
}
/** Requête principale : partagée avec les hooks dérivés via `select`. */
function useAlerts() {
	const { selectedFileId } = useFileSelection();
	return useQuery({
		queryKey: [
			"alerts",
			CASE_ID,
			selectedFileId
		],
		queryFn: () => fetch(`${API_URL}/cases/${CASE_ID}/alerts?limit=500${selectedFileId ? `&file_id=${selectedFileId}` : ""}`).then((r) => r.json()),
		staleTime: STALE_TIME,
		refetchInterval: getRefetchInterval
	});
}
function useSeverityDistribution() {
	const { selectedFileId } = useFileSelection();
	return useQuery({
		queryKey: [
			"severity-distribution",
			CASE_ID,
			selectedFileId
		],
		queryFn: () => fetch(`${API_URL}/cases/${CASE_ID}/severity-distribution${selectedFileId ? `?file_id=${selectedFileId}` : ""}`).then((r) => r.json()),
		staleTime: STALE_TIME,
		refetchInterval: getRefetchInterval
	});
}
function useToolDistribution() {
	const { selectedFileId } = useFileSelection();
	return useQuery({
		queryKey: [
			"tool-distribution",
			CASE_ID,
			selectedFileId
		],
		queryFn: () => fetch(`${API_URL}/cases/${CASE_ID}/tool-distribution${selectedFileId ? `?file_id=${selectedFileId}` : ""}`).then((r) => r.json()),
		staleTime: STALE_TIME,
		refetchInterval: getRefetchInterval
	});
}
function useFilesList() {
	return useQuery({
		queryKey: ["files", CASE_ID],
		queryFn: () => fetch(`${API_URL}/cases/${CASE_ID}/files`).then((r) => r.json()),
		staleTime: STALE_TIME,
		refetchInterval: getRefetchInterval
	});
}
function useCorrelations() {
	const { selectedFileId } = useFileSelection();
	return useQuery({
		queryKey: [
			"correlations",
			CASE_ID,
			selectedFileId
		],
		queryFn: () => fetch(`${API_URL}/cases/${CASE_ID}/correlations${selectedFileId ? `?file_id=${selectedFileId}` : ""}`).then((r) => r.json()),
		staleTime: STALE_TIME,
		refetchInterval: getRefetchInterval
	});
}
function useReport() {
	const { selectedFileId } = useFileSelection();
	return useQuery({
		queryKey: [
			"report",
			CASE_ID,
			selectedFileId
		],
		queryFn: () => fetch(`${API_URL}/cases/${CASE_ID}/report${selectedFileId ? `?file_id=${selectedFileId}` : ""}`).then((r) => r.json()),
		staleTime: 1e4,
		refetchInterval: IDLE_POLL
	});
}
function useIOCs() {
	const { selectedFileId } = useFileSelection();
	return useQuery({
		queryKey: [
			"alerts",
			CASE_ID,
			selectedFileId
		],
		queryFn: () => fetch(`${API_URL}/cases/${CASE_ID}/alerts?limit=500${selectedFileId ? `&file_id=${selectedFileId}` : ""}`).then((r) => r.json()),
		select: buildIOCsFromAlerts,
		staleTime: STALE_TIME,
		refetchInterval: getRefetchInterval
	});
}
function useTimeline() {
	const { selectedFileId } = useFileSelection();
	return useQuery({
		queryKey: [
			"alerts",
			CASE_ID,
			selectedFileId
		],
		queryFn: () => fetch(`${API_URL}/cases/${CASE_ID}/alerts?limit=500${selectedFileId ? `&file_id=${selectedFileId}` : ""}`).then((r) => r.json()),
		select: buildTimelineFromAlerts,
		staleTime: STALE_TIME,
		refetchInterval: getRefetchInterval
	});
}
function useArtifacts() {
	const { selectedFileId } = useFileSelection();
	return useQuery({
		queryKey: [
			"alerts",
			CASE_ID,
			selectedFileId
		],
		queryFn: () => fetch(`${API_URL}/cases/${CASE_ID}/alerts?limit=500${selectedFileId ? `&file_id=${selectedFileId}` : ""}`).then((r) => r.json()),
		select: buildArtifactsFromAlerts,
		staleTime: STALE_TIME,
		refetchInterval: getRefetchInterval
	});
}
function useBackendStatus() {
	return useQuery({
		queryKey: ["backend-status"],
		queryFn: () => fetch(`${API_URL}/`).then((r) => {
			if (!r.ok) throw new Error("Backend down");
			return r.json();
		}),
		staleTime: 4e3,
		refetchInterval: 6e3,
		retry: 1
	});
}
function useAnalysisStatus() {
	return useQuery({
		queryKey: ["status", CASE_ID],
		queryFn: () => fetch(`${API_URL}/cases/${CASE_ID}/status`).then((r) => r.json()),
		staleTime: 500,
		refetchInterval: (data) => {
			return data?.processing ? 1500 : 8e3;
		},
		retry: 1
	});
}
function useUploadFile() {
	const queryClient = useQueryClient();
	return useMutation({
		mutationFn: async (files) => {
			const fileArray = Array.isArray(files) ? files : [files];
			const formData = new FormData();
			if (fileArray.length === 1) {
				formData.append("file", fileArray[0]);
				const res = await fetch(`${API_URL}/cases/${CASE_ID}/upload`, {
					method: "POST",
					body: formData
				});
				if (!res.ok) throw new Error("Échec de l'upload");
				return res.json();
			} else {
				for (const f of fileArray) formData.append("files", f);
				const res = await fetch(`${API_URL}/cases/${CASE_ID}/upload-multi`, {
					method: "POST",
					body: formData
				});
				if (!res.ok) throw new Error("Échec de l'upload");
				return res.json();
			}
		},
		onMutate: () => {
			_lastUploadAt = Date.now();
		},
		onSuccess: () => {
			_lastUploadAt = Date.now();
			queryClient.invalidateQueries({ queryKey: ["stats", CASE_ID] });
			queryClient.invalidateQueries({ queryKey: ["alerts", CASE_ID] });
			queryClient.invalidateQueries({ queryKey: ["correlations", CASE_ID] });
			queryClient.invalidateQueries({ queryKey: ["files", CASE_ID] });
			queryClient.invalidateQueries({ queryKey: ["report", CASE_ID] });
			queryClient.invalidateQueries({ queryKey: ["severity-distribution", CASE_ID] });
			queryClient.invalidateQueries({ queryKey: ["tool-distribution", CASE_ID] });
		}
	});
}
var nav = [
	{
		to: "/",
		label: "Overview",
		icon: LayoutDashboard
	},
	{
		to: "/alerts",
		label: "Alertes",
		icon: ShieldAlert
	},
	{
		to: "/iocs",
		label: "IOCs",
		icon: FingerprintPattern
	},
	{
		to: "/timeline",
		label: "Timeline",
		icon: Clock3
	},
	{
		to: "/artifacts",
		label: "Artefacts",
		icon: Files
	},
	{
		to: "/correlations",
		label: "Corrélations",
		icon: Network
	},
	{
		to: "/reports",
		label: "Rapports",
		icon: FileText
	},
	{
		to: "/upload",
		label: "Import",
		icon: Upload
	}
];
function AppShell({ children, title, subtitle }) {
	const pathname = useRouterState({ select: (s) => s.location.pathname });
	const { data: backendData, isError: backendDown } = useBackendStatus();
	const { data: statusData } = useAnalysisStatus();
	const { selectedFileId, selectedFileName, clearFileFilter } = useFileSelection();
	const analysisInProgress = statusData?.processing === true;
	const backendOnline = !backendDown && backendData;
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "flex min-h-screen bg-background text-foreground",
		children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("aside", {
			className: "hidden md:flex w-64 flex-col border-r border-sidebar-border bg-sidebar",
			children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
					className: "px-5 py-5 border-b border-sidebar-border",
					children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "flex items-center gap-2",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "h-8 w-8 rounded-md bg-primary/15 border border-primary/30 grid place-items-center",
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ShieldAlert, { className: "h-4 w-4 text-primary" })
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "text-sm font-semibold tracking-tight text-sidebar-foreground",
							children: "ForensiQ"
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "text-[10px] uppercase tracking-widest text-muted-foreground",
							children: "Post-Analysis"
						})] })]
					})
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("nav", {
					className: "flex-1 px-3 py-4 space-y-1",
					children: nav.map(({ to, label, icon: Icon }) => {
						return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Link, {
							to,
							className: `flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${pathname === to ? "bg-sidebar-accent text-sidebar-accent-foreground border-l-2 border-primary" : "text-sidebar-foreground/80 hover:bg-sidebar-accent/50 hover:text-sidebar-foreground"}`,
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Icon, { className: "h-4 w-4" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { children: label })]
						}, to);
					})
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "p-4 border-t border-sidebar-border space-y-3",
					children: [
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "flex items-center gap-2 text-xs",
							children: backendOnline ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(import_jsx_runtime.Fragment, { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Wifi, { className: "h-3.5 w-3.5 text-[color:var(--success)]" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
								className: "text-[color:var(--success)]",
								children: "Backend connecté"
							})] }) : /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(import_jsx_runtime.Fragment, { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(WifiOff, { className: "h-3.5 w-3.5 text-destructive" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
								className: "text-destructive",
								children: "Backend hors-ligne"
							})] })
						}),
						analysisInProgress && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
							className: "flex items-center gap-2 text-xs text-[color:var(--medium)] animate-pulse",
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Activity, { className: "h-3.5 w-3.5" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { children: "Analyse en cours…" })]
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
							className: "rounded-md bg-sidebar-accent/60 p-3",
							children: [
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
									className: "text-[10px] uppercase tracking-widest text-muted-foreground",
									children: "Dossier actif"
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
									className: "text-sm font-medium mt-1 text-sidebar-foreground",
									children: "CASE-demo"
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
									className: "text-xs text-muted-foreground mt-0.5 truncate",
									children: "Investigation active"
								})
							]
						})
					]
				})
			]
		}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
			className: "flex-1 flex flex-col min-w-0",
			children: [
				analysisInProgress && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "bg-[color:var(--medium)]/10 border-b border-[color:var(--medium)]/30 px-6 py-2 flex items-center gap-3",
					children: [
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Activity, { className: "h-4 w-4 text-[color:var(--medium)] animate-pulse shrink-0" }),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
							className: "text-sm text-[color:var(--medium)] font-medium",
							children: "Analyse en cours — le dashboard se met à jour automatiquement dès que les résultats arrivent"
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
							className: "ml-auto flex gap-1",
							children: [
								0,
								1,
								2
							].map((i) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
								className: "h-1.5 w-1.5 rounded-full bg-[color:var(--medium)] animate-bounce",
								style: { animationDelay: `${i * .15}s` }
							}, i))
						})
					]
				}),
				!backendOnline && !analysisInProgress && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "bg-destructive/10 border-b border-destructive/30 px-6 py-2 flex items-center gap-3",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(WifiOff, { className: "h-4 w-4 text-destructive shrink-0" }), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", {
						className: "text-sm text-destructive",
						children: [
							"Backend non joignable sur ",
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("code", {
								className: "font-mono text-xs",
								children: "localhost:8000"
							}),
							" — lancez",
							" ",
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("code", {
								className: "font-mono text-xs",
								children: "uvicorn main:app --reload --port 8000"
							}),
							" dans le dossier",
							" ",
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("code", {
								className: "font-mono text-xs",
								children: "backend/"
							})
						]
					})]
				}),
				selectedFileId && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "bg-primary/10 border-b border-primary/30 px-6 py-2 flex items-center gap-3",
					children: [
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)(FileCheck, { className: "h-4 w-4 text-primary shrink-0" }),
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", {
							className: "text-sm text-primary font-medium",
							children: [
								"Mode Filtré : Vous visualisez uniquement les résultats du fichier ",
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", {
									className: "font-mono",
									children: selectedFileName
								}),
								"."
							]
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
							onClick: clearFileFilter,
							className: "ml-auto flex items-center gap-1.5 px-3 py-1 bg-background border border-primary/20 text-primary hover:bg-primary hover:text-primary-foreground text-xs font-semibold rounded transition-colors",
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(FunnelX, { className: "h-3.5 w-3.5" }), "Voir tout le dossier"]
						})
					]
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("header", {
					className: "h-16 border-b border-border bg-card/40 backdrop-blur flex items-center justify-between px-6",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h1", {
						className: "text-lg font-semibold tracking-tight",
						children: title
					}), subtitle && /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "text-xs text-muted-foreground mt-0.5",
						children: subtitle
					})] }), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "flex items-center gap-3",
						children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
								className: "hidden md:flex items-center gap-2 px-3 py-1.5 rounded-md bg-muted border border-border w-72",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Search, { className: "h-3.5 w-3.5 text-muted-foreground" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									placeholder: "Rechercher IOC, hash, fichier…",
									className: "bg-transparent text-sm outline-none flex-1 placeholder:text-muted-foreground"
								})]
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
								className: "relative h-9 w-9 grid place-items-center rounded-md border border-border hover:bg-muted",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Bell, { className: "h-4 w-4" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { className: "absolute top-1.5 right-1.5 h-2 w-2 rounded-full bg-destructive" })]
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
								className: "flex items-center gap-2 pl-3 border-l border-border",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(CircleUser, { className: "h-6 w-6 text-muted-foreground" }), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
									className: "text-xs",
									children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
										className: "font-medium",
										children: "Analyste"
									}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
										className: "text-muted-foreground",
										children: "Forensique"
									})]
								})]
							})
						]
					})]
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("main", {
					className: "flex-1 p-6 overflow-x-hidden",
					children
				})
			]
		})]
	});
}
function SeverityBadge({ severity }) {
	const map = {
		critical: "bg-[color:var(--critical)]/15 text-[color:var(--critical)] border-[color:var(--critical)]/30",
		high: "bg-[color:var(--high)]/15 text-[color:var(--high)] border-[color:var(--high)]/30",
		medium: "bg-[color:var(--medium)]/15 text-[color:var(--medium)] border-[color:var(--medium)]/30",
		low: "bg-[color:var(--low)]/15 text-[color:var(--low)] border-[color:var(--low)]/30",
		info: "bg-[color:var(--info)]/15 text-[color:var(--info)] border-[color:var(--info)]/30"
	};
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
		className: `inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider border ${map[severity] ?? map.info}`,
		children: severity
	});
}
function ToolBadge({ tool }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
		className: `inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium border ${{
			loki: "bg-purple-500/15 text-purple-300 border-purple-500/30",
			hayabusa: "bg-sky-500/15 text-sky-300 border-sky-500/30",
			autopsy: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
			kuiper: "bg-amber-500/15 text-amber-300 border-amber-500/30",
			"ml-network": "bg-rose-500/15 text-rose-300 border-rose-500/30",
			"ml network": "bg-rose-500/15 text-rose-300 border-rose-500/30",
			unknown: "bg-muted text-muted-foreground border-border"
		}[(tool ?? "").toLowerCase()] ?? "bg-muted text-muted-foreground border-border"}`,
		children: tool
	});
}
function Card({ children, className = "" }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
		className: `rounded-lg border border-border bg-card ${className}`,
		children
	});
}
//#endregion
export { useUploadFile as _, ToolBadge as a, useArtifacts as c, useIOCs as d, useReport as f, useToolDistribution as g, useTimeline as h, SeverityBadge as i, useCorrelations as l, useStats as m, AppShell as n, useAlerts as o, useSeverityDistribution as p, Card as r, useAnalysisStatus as s, API_URL as t, useFilesList as u };
