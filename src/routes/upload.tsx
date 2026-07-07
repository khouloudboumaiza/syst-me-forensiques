import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useRef, useState, useEffect } from "react";
import { AppShell, Card, ToolBadge } from "@/components/app-shell";
import {
  UploadCloud,
  CheckCircle2,
  FileText,
  Loader2,
  XCircle,
  ArrowRight,
  Activity,
  ShieldAlert,
  Fingerprint,
  Clock,
  Filter,
} from "lucide-react";
import { useUploadFile, useFilesList, useStats, useAnalysisStatus } from "@/hooks/useCaseData";
import { useFileSelection } from "@/hooks/useFileSelection";
import { useQueryClient } from "@tanstack/react-query";

export const Route = createFileRoute("/upload")({
  head: () => ({ meta: [{ title: "Import — ForensiQ" }] }),
  component: UploadPage,
});

function formatSize(bytes: number) {
  if (!bytes) return "—";
  const kb = bytes / 1024;
  return kb > 1024 ? `${(kb / 1024).toFixed(1)} MB` : `${kb.toFixed(0)} KB`;
}

// Étapes du pipeline affichées pendant l'analyse
const PIPELINE_STEPS = [
  { label: "Détection du type", icon: FileText },
  { label: "Parsing", icon: Loader2 },
  { label: "Normalisation", icon: Activity },
  { label: "Analyse / Scoring", icon: ShieldAlert },
  { label: "Enrichissement IOCs", icon: Fingerprint },
  { label: "Corrélation", icon: Clock },
  { label: "Stockage", icon: CheckCircle2 },
];

function UploadPage() {
  const [dragging, setDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();
  const upload = useUploadFile();
  const { data: files, isLoading: filesLoading } = useFilesList();
  const { setFileFilter } = useFileSelection();
  const { data: stats } = useStats();
  const { data: statusData } = useAnalysisStatus();
  const queryClient = useQueryClient();

  // Dès que l'analyse se termine (processing → false), forcer le rechargement
  // de toutes les données pour afficher les résultats immédiatement
  const wasProcessing = useRef(false);
  useEffect(() => {
    if (statusData?.processing) {
      wasProcessing.current = true;
    } else if (wasProcessing.current && !statusData?.processing) {
      wasProcessing.current = false;
      // Invalide tout pour forcer un rechargement immédiat
      queryClient.invalidateQueries();
    }
  }, [statusData?.processing, queryClient]);

  // Simulation de l'étape du pipeline en cours d'exécution
  const [currentStep, setCurrentStep] = useState(-1);
  useEffect(() => {
    if (upload.isPending) {
      setCurrentStep(0);
      const interval = setInterval(() => {
        setCurrentStep((prev) => {
          if (prev < PIPELINE_STEPS.length - 2) return prev + 1;
          return prev;
        });
      }, 700);
      return () => clearInterval(interval);
    } else if (upload.isSuccess) {
      setCurrentStep(PIPELINE_STEPS.length - 1);
    } else {
      setCurrentStep(-1);
    }
  }, [upload.isPending, upload.isSuccess]);

  const handleFiles = (fileList: FileList | File[]) => {
    const arr = Array.from(fileList);
    if (arr.length === 0) return;
    if (arr.length === 1) {
      upload.mutate(arr[0]);
    } else {
      upload.mutate(arr);
    }
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const droppedFiles = e.dataTransfer.files;
    if (droppedFiles && droppedFiles.length > 0) handleFiles(droppedFiles);
  };

  const filesArray = Array.isArray(files) ? files : [];

  return (
    <AppShell
      title="Import de résultats forensiques"
      subtitle="Glissez-déposez les fichiers générés par vos outils"
    >
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Zone de drop */}
        <div
          className={`lg:col-span-2 rounded-lg bg-card p-10 border-2 border-dashed transition-all duration-300 ${
            dragging
              ? "border-primary bg-primary/5 scale-[1.01]"
              : upload.isPending
                ? "border-[color:var(--medium)] bg-[color:var(--medium)]/5"
                : upload.isSuccess
                  ? "border-[color:var(--success)] bg-[color:var(--success)]/5"
                  : upload.isError
                    ? "border-destructive bg-destructive/5"
                    : "border-border"
          }`}
          onDragOver={(e: React.DragEvent) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
        >
          <div className="flex flex-col items-center text-center py-8">
            {/* Icône centrale animée */}
            <div
              className={`h-16 w-16 rounded-full grid place-items-center mb-4 border transition-all duration-300 ${
                upload.isPending
                  ? "bg-[color:var(--medium)]/10 border-[color:var(--medium)]/30"
                  : upload.isSuccess
                    ? "bg-[color:var(--success)]/10 border-[color:var(--success)]/30"
                    : upload.isError
                      ? "bg-destructive/10 border-destructive/30"
                      : "bg-primary/10 border-primary/20"
              }`}
            >
              {upload.isPending ? (
                <div className="relative">
                  <Loader2 className="h-8 w-8 text-[color:var(--medium)] animate-spin" />
                  <Activity className="h-4 w-4 text-[color:var(--medium)] absolute top-2 left-2" />
                </div>
              ) : upload.isSuccess ? (
                <CheckCircle2 className="h-8 w-8 text-[color:var(--success)]" />
              ) : upload.isError ? (
                <XCircle className="h-8 w-8 text-destructive" />
              ) : (
                <UploadCloud className="h-8 w-8 text-primary" />
              )}
            </div>

            <h3 className="text-xl font-semibold">
              {upload.isPending
                ? "Analyse en cours…"
                : upload.isSuccess
                  ? "Analyse terminée !"
                  : upload.isError
                    ? "Erreur d'analyse"
                    : "Déposez vos fichiers ici"}
            </h3>

            <p className="text-sm text-muted-foreground mt-2 max-w-md">
              {upload.isPending
                ? "Les fichiers sont en cours de traitement par le backend. Le dashboard se mettra à jour automatiquement."
                : upload.isSuccess
                  ? upload.data?.count
                    ? `${upload.data.count} fichier(s) envoyé(s) en analyse.`
                    : `Outil détecté : ${upload.data?.tool_detected ?? "—"} — ${upload.data?.alerts_extracted ?? 0} alertes extraites`
                  : upload.isError
                    ? "Échec de l'analyse. Vérifiez que le backend tourne sur localhost:8000."
                    : "Formats supportés : CSV, JSON, logs. Sélectionnez ou glissez un ou plusieurs fichiers à la fois."}
            </p>

            <input
              ref={fileInputRef}
              type="file"
              multiple
              accept=".json,.txt,.csv,.xlsx"
              className="hidden"
              onChange={(e) => e.target.files && e.target.files.length > 0 && handleFiles(e.target.files)}
            />

            {!upload.isPending && (
              <button
                onClick={() => fileInputRef.current?.click()}
                disabled={upload.isPending}
                className="mt-5 inline-flex items-center gap-2 rounded-md bg-primary text-primary-foreground px-4 py-2 text-sm font-medium hover:opacity-90 disabled:opacity-50 transition-opacity"
              >
                {upload.isSuccess ? "Analyser d'autres fichiers" : "Parcourir les fichiers"}
              </button>
            )}

            {/* Résultat et lien vers dashboard */}
            {upload.isSuccess && (
              <button
                onClick={() => navigate({ to: "/" })}
                className="mt-3 inline-flex items-center gap-1.5 text-sm text-primary hover:underline"
              >
                Voir le dashboard <ArrowRight className="h-3.5 w-3.5" />
              </button>
            )}

            <div className="mt-6 flex items-center gap-2 flex-wrap justify-center">
              <span className="text-xs text-muted-foreground">Compatible :</span>
              {(["Loki", "Hayabusa", "Kuiper", "ML-Network"] as const).map((t) => (
                <ToolBadge key={t} tool={t} />
              ))}
            </div>
          </div>
        </div>

        {/* Pipeline de traitement */}
        <Card className="p-5">
          <h3 className="text-sm font-semibold mb-1">Pipeline de traitement</h3>
          <p className="text-xs text-muted-foreground mb-4">Étapes appliquées à chaque fichier</p>
          <ol className="space-y-3 text-sm">
            {PIPELINE_STEPS.map((step, i) => {
              const done = upload.isSuccess || (upload.isPending && i < currentStep);
              const active = upload.isPending && i === currentStep;
              const pending = !upload.isPending && !upload.isSuccess;

              return (
                <li key={step.label} className="flex items-center gap-3">
                  <span
                    className={`h-6 w-6 rounded-full grid place-items-center text-[10px] font-semibold border transition-all duration-300 ${
                      done
                        ? "bg-[color:var(--success)]/15 border-[color:var(--success)]/30 text-[color:var(--success)]"
                        : active
                          ? "bg-[color:var(--medium)]/15 border-[color:var(--medium)]/30 text-[color:var(--medium)] animate-pulse"
                          : "bg-primary/15 border-primary/30 text-primary"
                    }`}
                  >
                    {done ? <CheckCircle2 className="h-3.5 w-3.5" /> : i + 1}
                  </span>
                  <span
                    className={
                      done
                        ? "text-[color:var(--success)]"
                        : active
                          ? "text-[color:var(--medium)] font-medium"
                          : pending
                            ? "text-foreground/50"
                            : "text-foreground"
                    }
                  >
                    {step.label}
                  </span>
                  {active && (
                    <Loader2 className="h-3.5 w-3.5 text-[color:var(--medium)] animate-spin ml-auto" />
                  )}
                  {done && i === PIPELINE_STEPS.length - 1 && (
                    <CheckCircle2 className="h-3.5 w-3.5 text-[color:var(--success)] ml-auto" />
                  )}
                </li>
              );
            })}
          </ol>

          {/* Stats live */}
          {stats && (
            <div className="mt-5 pt-4 border-t border-border space-y-2">
              <div className="text-xs text-muted-foreground uppercase tracking-wider mb-2">Stats actuelles</div>
              {[
                { label: "Fichiers", value: stats.files_analyzed ?? 0 },
                { label: "Alertes", value: stats.alerts ?? 0 },
                { label: "IOCs", value: stats.iocs ?? 0 },
              ].map((s) => (
                <div key={s.label} className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground">{s.label}</span>
                  <span className="font-semibold tabular-nums">{s.value}</span>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      {/* Fichiers importés */}
      <Card className="mt-4">
        <div className="p-5 border-b border-border flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold">Fichiers importés</h3>
            <p className="text-xs text-muted-foreground mt-0.5">
              {filesArray.length} fichier(s) pour ce dossier
            </p>
          </div>
          {filesArray.some((f: any) => f.status === "processing") && (
            <div className="flex items-center gap-2 text-xs text-[color:var(--medium)]">
              <Activity className="h-3.5 w-3.5 animate-pulse" />
              Traitement en cours…
            </div>
          )}
        </div>
        <div className="divide-y divide-border">
          {filesLoading && (
            <div className="px-5 py-6 text-sm text-muted-foreground flex items-center gap-2">
              <Loader2 className="h-4 w-4 animate-spin" /> Chargement…
            </div>
          )}
          {!filesLoading && filesArray.length === 0 && (
            <div className="px-5 py-6 text-sm text-muted-foreground">
              Aucun fichier importé pour ce dossier.
            </div>
          )}
          {filesArray.map((f: any, i: number) => (
            <div
              key={f.id ?? i}
              className="px-5 py-3 flex items-center gap-4 hover:bg-muted/30 transition-colors"
            >
              <FileText className="h-4 w-4 text-muted-foreground shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="text-sm font-medium truncate">{f.filename ?? f.name}</div>
                <div className="text-xs text-muted-foreground font-mono">
                  {f.uploaded_at ? String(f.uploaded_at).slice(0, 19) : "—"} · {f.alert_count ?? 0} alerte(s)
                </div>
              </div>
              <ToolBadge tool={f.tool ?? f.tool_detected ?? "unknown"} />
              <span
                className={`text-[10px] uppercase tracking-widest flex items-center gap-1 ${
                  f.status === "parsed"
                    ? "text-[color:var(--success)]"
                    : f.status === "processing"
                      ? "text-[color:var(--medium)] animate-pulse"
                      : f.status === "error"
                        ? "text-destructive"
                        : "text-muted-foreground"
                }`}
              >
                {f.status === "error" && <XCircle className="h-3 w-3" />}
                {f.status ?? "—"}
              </span>
              
              {/* Bouton de filtrage */}
              {f.status === "parsed" && (
                <button
                  onClick={() => {
                    setFileFilter(f.id, f.filename);
                    navigate({ to: "/" });
                  }}
                  className="ml-4 h-8 w-8 grid place-items-center rounded-md border border-border hover:bg-primary/10 hover:text-primary transition-colors"
                  title="Voir uniquement les résultats de ce fichier"
                >
                  <Filter className="h-4 w-4" />
                </button>
              )}
            </div>
          ))}
        </div>
      </Card>
    </AppShell>
  );
}
