import { i as __toESM } from "../_runtime.mjs";
import { a as require_jsx_runtime, i as useQueryClient, o as require_react } from "../_libs/react+tanstack__react-query.mjs";
import { n as useFileSelection } from "./useFileSelection-BQQdt2sG.mjs";
import { _ as useNavigate } from "../_libs/@tanstack/react-router+[...].mjs";
import { D as FileText, G as ArrowRight, I as CircleX, K as Activity, N as CloudUpload, P as Clock, R as CircleCheck, S as Funnel, f as ShieldAlert, g as LoaderCircle, w as FingerprintPattern } from "../_libs/lucide-react.mjs";
import { _ as useUploadFile, a as ToolBadge, m as useStats, n as AppShell, r as Card, s as useAnalysisStatus, u as useFilesList } from "./app-shell-CXKz5zjF.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/upload-BEW7wjnq.js
var import_react = /* @__PURE__ */ __toESM(require_react());
var import_jsx_runtime = require_jsx_runtime();
var PIPELINE_STEPS = [
	{
		label: "Détection du type",
		icon: FileText
	},
	{
		label: "Parsing",
		icon: LoaderCircle
	},
	{
		label: "Normalisation",
		icon: Activity
	},
	{
		label: "Analyse / Scoring",
		icon: ShieldAlert
	},
	{
		label: "Enrichissement IOCs",
		icon: FingerprintPattern
	},
	{
		label: "Corrélation",
		icon: Clock
	},
	{
		label: "Stockage",
		icon: CircleCheck
	}
];
function UploadPage() {
	const [dragging, setDragging] = (0, import_react.useState)(false);
	const fileInputRef = (0, import_react.useRef)(null);
	const navigate = useNavigate();
	const upload = useUploadFile();
	const { data: files, isLoading: filesLoading } = useFilesList();
	const { setFileFilter } = useFileSelection();
	const { data: stats } = useStats();
	const { data: statusData } = useAnalysisStatus();
	const queryClient = useQueryClient();
	const wasProcessing = (0, import_react.useRef)(false);
	(0, import_react.useEffect)(() => {
		if (statusData?.processing) wasProcessing.current = true;
		else if (wasProcessing.current && !statusData?.processing) {
			wasProcessing.current = false;
			queryClient.invalidateQueries();
		}
	}, [statusData?.processing, queryClient]);
	const [currentStep, setCurrentStep] = (0, import_react.useState)(-1);
	(0, import_react.useEffect)(() => {
		if (upload.isPending) {
			setCurrentStep(0);
			const interval = setInterval(() => {
				setCurrentStep((prev) => {
					if (prev < PIPELINE_STEPS.length - 2) return prev + 1;
					return prev;
				});
			}, 700);
			return () => clearInterval(interval);
		} else if (upload.isSuccess) setCurrentStep(PIPELINE_STEPS.length - 1);
		else setCurrentStep(-1);
	}, [upload.isPending, upload.isSuccess]);
	const handleFiles = (fileList) => {
		const arr = Array.from(fileList);
		if (arr.length === 0) return;
		if (arr.length === 1) upload.mutate(arr[0]);
		else upload.mutate(arr);
	};
	const onDrop = (e) => {
		e.preventDefault();
		setDragging(false);
		const droppedFiles = e.dataTransfer.files;
		if (droppedFiles && droppedFiles.length > 0) handleFiles(droppedFiles);
	};
	const filesArray = Array.isArray(files) ? files : [];
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(AppShell, {
		title: "Import de résultats forensiques",
		subtitle: "Glissez-déposez les fichiers générés par vos outils",
		children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
			className: "grid grid-cols-1 lg:grid-cols-3 gap-4",
			children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
				className: `lg:col-span-2 rounded-lg bg-card p-10 border-2 border-dashed transition-all duration-300 ${dragging ? "border-primary bg-primary/5 scale-[1.01]" : upload.isPending ? "border-[color:var(--medium)] bg-[color:var(--medium)]/5" : upload.isSuccess ? "border-[color:var(--success)] bg-[color:var(--success)]/5" : upload.isError ? "border-destructive bg-destructive/5" : "border-border"}`,
				onDragOver: (e) => {
					e.preventDefault();
					setDragging(true);
				},
				onDragLeave: () => setDragging(false),
				onDrop,
				children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "flex flex-col items-center text-center py-8",
					children: [
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: `h-16 w-16 rounded-full grid place-items-center mb-4 border transition-all duration-300 ${upload.isPending ? "bg-[color:var(--medium)]/10 border-[color:var(--medium)]/30" : upload.isSuccess ? "bg-[color:var(--success)]/10 border-[color:var(--success)]/30" : upload.isError ? "bg-destructive/10 border-destructive/30" : "bg-primary/10 border-primary/20"}`,
							children: upload.isPending ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
								className: "relative",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(LoaderCircle, { className: "h-8 w-8 text-[color:var(--medium)] animate-spin" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Activity, { className: "h-4 w-4 text-[color:var(--medium)] absolute top-2 left-2" })]
							}) : upload.isSuccess ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(CircleCheck, { className: "h-8 w-8 text-[color:var(--success)]" }) : upload.isError ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(CircleX, { className: "h-8 w-8 text-destructive" }) : /* @__PURE__ */ (0, import_jsx_runtime.jsx)(CloudUpload, { className: "h-8 w-8 text-primary" })
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h3", {
							className: "text-xl font-semibold",
							children: upload.isPending ? "Analyse en cours…" : upload.isSuccess ? "Analyse terminée !" : upload.isError ? "Erreur d'analyse" : "Déposez vos fichiers ici"
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
							className: "text-sm text-muted-foreground mt-2 max-w-md",
							children: upload.isPending ? "Les fichiers sont en cours de traitement par le backend. Le dashboard se mettra à jour automatiquement." : upload.isSuccess ? upload.data?.count ? `${upload.data.count} fichier(s) envoyé(s) en analyse.` : `Outil détecté : ${upload.data?.tool_detected ?? "—"} — ${upload.data?.alerts_extracted ?? 0} alertes extraites` : upload.isError ? "Échec de l'analyse. Vérifiez que le backend tourne sur localhost:8000." : "Formats supportés : CSV, JSON, logs. Sélectionnez ou glissez un ou plusieurs fichiers à la fois."
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
							ref: fileInputRef,
							type: "file",
							multiple: true,
							accept: ".json,.txt,.csv,.xlsx",
							className: "hidden",
							onChange: (e) => e.target.files && e.target.files.length > 0 && handleFiles(e.target.files)
						}),
						!upload.isPending && /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
							onClick: () => fileInputRef.current?.click(),
							disabled: upload.isPending,
							className: "mt-5 inline-flex items-center gap-2 rounded-md bg-primary text-primary-foreground px-4 py-2 text-sm font-medium hover:opacity-90 disabled:opacity-50 transition-opacity",
							children: upload.isSuccess ? "Analyser d'autres fichiers" : "Parcourir les fichiers"
						}),
						upload.isSuccess && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", {
							onClick: () => navigate({ to: "/" }),
							className: "mt-3 inline-flex items-center gap-1.5 text-sm text-primary hover:underline",
							children: ["Voir le dashboard ", /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ArrowRight, { className: "h-3.5 w-3.5" })]
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
							className: "mt-6 flex items-center gap-2 flex-wrap justify-center",
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
								className: "text-xs text-muted-foreground",
								children: "Compatible :"
							}), [
								"Loki",
								"Hayabusa",
								"Kuiper",
								"ML-Network"
							].map((t) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ToolBadge, { tool: t }, t))]
						})
					]
				})
			}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, {
				className: "p-5",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h3", {
						className: "text-sm font-semibold mb-1",
						children: "Pipeline de traitement"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "text-xs text-muted-foreground mb-4",
						children: "Étapes appliquées à chaque fichier"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("ol", {
						className: "space-y-3 text-sm",
						children: PIPELINE_STEPS.map((step, i) => {
							const done = upload.isSuccess || upload.isPending && i < currentStep;
							const active = upload.isPending && i === currentStep;
							const pending = !upload.isPending && !upload.isSuccess;
							return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
								className: "flex items-center gap-3",
								children: [
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
										className: `h-6 w-6 rounded-full grid place-items-center text-[10px] font-semibold border transition-all duration-300 ${done ? "bg-[color:var(--success)]/15 border-[color:var(--success)]/30 text-[color:var(--success)]" : active ? "bg-[color:var(--medium)]/15 border-[color:var(--medium)]/30 text-[color:var(--medium)] animate-pulse" : "bg-primary/15 border-primary/30 text-primary"}`,
										children: done ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(CircleCheck, { className: "h-3.5 w-3.5" }) : i + 1
									}),
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
										className: done ? "text-[color:var(--success)]" : active ? "text-[color:var(--medium)] font-medium" : pending ? "text-foreground/50" : "text-foreground",
										children: step.label
									}),
									active && /* @__PURE__ */ (0, import_jsx_runtime.jsx)(LoaderCircle, { className: "h-3.5 w-3.5 text-[color:var(--medium)] animate-spin ml-auto" }),
									done && i === PIPELINE_STEPS.length - 1 && /* @__PURE__ */ (0, import_jsx_runtime.jsx)(CircleCheck, { className: "h-3.5 w-3.5 text-[color:var(--success)] ml-auto" })
								]
							}, step.label);
						})
					}),
					stats && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "mt-5 pt-4 border-t border-border space-y-2",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
							className: "text-xs text-muted-foreground uppercase tracking-wider mb-2",
							children: "Stats actuelles"
						}), [
							{
								label: "Fichiers",
								value: stats.files_analyzed ?? 0
							},
							{
								label: "Alertes",
								value: stats.alerts ?? 0
							},
							{
								label: "IOCs",
								value: stats.iocs ?? 0
							}
						].map((s) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
							className: "flex items-center justify-between text-xs",
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
								className: "text-muted-foreground",
								children: s.label
							}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
								className: "font-semibold tabular-nums",
								children: s.value
							})]
						}, s.label))]
					})
				]
			})]
		}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Card, {
			className: "mt-4",
			children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "p-5 border-b border-border flex items-center justify-between",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h3", {
					className: "text-sm font-semibold",
					children: "Fichiers importés"
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
					className: "text-xs text-muted-foreground mt-0.5",
					children: [filesArray.length, " fichier(s) pour ce dossier"]
				})] }), filesArray.some((f) => f.status === "processing") && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "flex items-center gap-2 text-xs text-[color:var(--medium)]",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Activity, { className: "h-3.5 w-3.5 animate-pulse" }), "Traitement en cours…"]
				})]
			}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "divide-y divide-border",
				children: [
					filesLoading && /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "px-5 py-6 text-sm text-muted-foreground flex items-center gap-2",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(LoaderCircle, { className: "h-4 w-4 animate-spin" }), " Chargement…"]
					}),
					!filesLoading && filesArray.length === 0 && /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
						className: "px-5 py-6 text-sm text-muted-foreground",
						children: "Aucun fichier importé pour ce dossier."
					}),
					filesArray.map((f, i) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "px-5 py-3 flex items-center gap-4 hover:bg-muted/30 transition-colors",
						children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(FileText, { className: "h-4 w-4 text-muted-foreground shrink-0" }),
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
								className: "flex-1 min-w-0",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
									className: "text-sm font-medium truncate",
									children: f.filename ?? f.name
								}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
									className: "text-xs text-muted-foreground font-mono",
									children: [
										f.uploaded_at ? String(f.uploaded_at).slice(0, 19) : "—",
										" · ",
										f.alert_count ?? 0,
										" alerte(s)"
									]
								})]
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(ToolBadge, { tool: f.tool ?? f.tool_detected ?? "unknown" }),
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", {
								className: `text-[10px] uppercase tracking-widest flex items-center gap-1 ${f.status === "parsed" ? "text-[color:var(--success)]" : f.status === "processing" ? "text-[color:var(--medium)] animate-pulse" : f.status === "error" ? "text-destructive" : "text-muted-foreground"}`,
								children: [f.status === "error" && /* @__PURE__ */ (0, import_jsx_runtime.jsx)(CircleX, { className: "h-3 w-3" }), f.status ?? "—"]
							}),
							f.status === "parsed" && /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
								onClick: () => {
									setFileFilter(f.id, f.filename);
									navigate({ to: "/" });
								},
								className: "ml-4 h-8 w-8 grid place-items-center rounded-md border border-border hover:bg-primary/10 hover:text-primary transition-colors",
								title: "Voir uniquement les résultats de ce fichier",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Funnel, { className: "h-4 w-4" })
							})
						]
					}, f.id ?? i))
				]
			})]
		})]
	});
}
//#endregion
export { UploadPage as component };
