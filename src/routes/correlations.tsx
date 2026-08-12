import { createFileRoute } from "@tanstack/react-router";
import { useState, useCallback } from "react";
import { AppShell, Card, SeverityBadge } from "@/components/app-shell";
import { useCorrelations } from "@/hooks/useCaseData";
import { useFileSelection } from "@/hooks/useFileSelection";
import { Network, Loader2, AlertTriangle, Link2, Hash, Globe, Target, Clock, FileText, Shield, Sparkles } from "lucide-react";

const API_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8000";
const explanationCache: Record<string, string> = {};

async function fetchAICorrelationExplanation(type: string, indicator: string, risk: string, tools: string[], files: string[], alert_count: number, events: string[]): Promise<string> {
  const cacheKey = `correl|${type}|${indicator}|${risk}`;
  if (explanationCache[cacheKey]) return explanationCache[cacheKey];

  const res = await fetch(`${API_URL}/explain-correlation`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ type, indicator, risk, tools, files, alert_count, events }),
  });
  if (!res.ok) throw new Error("Erreur API");
  const data = await res.json();
  explanationCache[cacheKey] = data.explanation;
  return data.explanation;
}

function AICorrelationExplainButton({ data }: { data: any }) {
  const [state, setState] = useState<"idle" | "loading" | "done" | "error">("idle");
  const [explanation, setExplanation] = useState<string>("");
  const [isModalOpen, setIsModalOpen] = useState(false);

  const handleExplain = useCallback(async (e: React.MouseEvent) => {
    e.stopPropagation();
    
    if (state === "done") {
      setIsModalOpen(true);
      return;
    }
    
    if (state === "loading") return;
    
    setState("loading");
    try {
      const type = data.type || "unknown";
      const indicator = data.indicator || "";
      const risk = data.risk || "medium";
      const tools = data.tools || [];
      const files = data.files || [];
      const alert_count = data.alert_count || 0;
      const events = data.network_events || [];

      const text = await fetchAICorrelationExplanation(type, indicator, risk, tools, files, alert_count, events);
      setExplanation(text);
      setState("done");
      setIsModalOpen(true);
    } catch {
      setState("error");
    }
  }, [data, state]);

  return (
    <>
      {state === "idle" || state === "done" ? (
        <button
          onClick={handleExplain}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium border border-primary/30 text-primary bg-primary/5 hover:bg-primary/15 transition-all duration-200 group"
        >
          <Sparkles className="h-3.5 w-3.5 group-hover:animate-pulse" />
          {state === "done" ? "Voir l'explication IA" : "Explication IA"}
        </button>
      ) : state === "loading" ? (
        <div className="inline-flex items-center gap-2 px-3 py-1.5 text-xs text-muted-foreground">
          <Loader2 className="h-3.5 w-3.5 animate-spin text-primary" />
          <span className="animate-pulse">Analyse IA en cours…</span>
        </div>
      ) : (
        <div className="flex items-center gap-2">
          <span className="text-xs text-destructive">Erreur IA</span>
          <button onClick={handleExplain} className="text-xs underline text-muted-foreground hover:text-foreground">
            Réessayer
          </button>
        </div>
      )}

      {isModalOpen && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div 
            className="bg-card text-card-foreground border border-border shadow-2xl rounded-xl w-full max-w-2xl overflow-hidden flex flex-col max-h-[90vh]"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-6 py-4 border-b border-border bg-muted/30 flex items-center gap-3 shrink-0">
              <Sparkles className="h-5 w-5 text-primary" />
              <h2 className="text-lg font-semibold">Explication IA de la corrélation</h2>
            </div>
            
            <div className="p-6 overflow-y-auto">
              <div className="mb-4 text-xs space-y-1 text-muted-foreground bg-muted/20 p-3 rounded-lg border border-border">
                <p><span className="font-semibold text-foreground">Indicateur partagé :</span> {data.indicator}</p>
                <p><span className="font-semibold text-foreground">Type :</span> {data.type} | <span className="font-semibold text-foreground">Risque :</span> <span className="uppercase">{data.risk}</span></p>
              </div>
              
              <div className="prose prose-sm dark:prose-invert max-w-none text-sm leading-relaxed whitespace-pre-wrap">
                {explanation}
              </div>
            </div>
            
            <div className="px-6 py-4 border-t border-border bg-muted/10 flex justify-end shrink-0">
              <button
                onClick={(e) => { e.stopPropagation(); setIsModalOpen(false); }}
                className="px-5 py-2 rounded-md bg-primary text-primary-foreground font-medium text-sm hover:opacity-90 transition-opacity"
              >
                Fermer
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
export const Route = createFileRoute("/correlations")({
  head: () => ({ meta: [{ title: "Corrélations — ForensiQ" }] }),
  component: CorrelationsPage,
});

const TYPE_CONFIG: Record<string, { label: string; icon: any; color: string; bg: string }> = {
  ip:       { label: "IP partagée",          icon: Globe,   color: "text-blue-400",   bg: "bg-blue-500/10 border-blue-500/20" },
  hash:     { label: "Hash partagé",         icon: Hash,    color: "text-red-400",    bg: "bg-red-500/10 border-red-500/20" },
  target:   { label: "Cible commune",        icon: Target,  color: "text-amber-400",  bg: "bg-amber-500/10 border-amber-500/20" },
  temporal: { label: "Corrélation temporelle", icon: Clock, color: "text-emerald-400", bg: "bg-emerald-500/10 border-emerald-500/20" },
};

function CorrelationsPage() {
  const { data: correlationsData, isLoading, isError } = useCorrelations();
  const { selectedFileId, selectedFileName } = useFileSelection();

  const correlated = Array.isArray(correlationsData?.correlated_events)
    ? correlationsData.correlated_events
    : [];
  const hostCount = correlationsData?.total_host_alerts ?? 0;
  const networkCount = correlationsData?.total_network_alerts ?? 0;
  const riskScore = correlationsData?.combined_risk_score ?? 0;
  const corrTypes = correlationsData?.correlation_types ?? [];

  return (
    <AppShell
      title="Corrélations intelligentes"
      subtitle={selectedFileId ? `Analyse multi-dimensionnelle : IPs, hashs, cibles et fenêtres temporelles croisés pour ${selectedFileName ?? "le fichier sélectionné"}` : "Analyse multi-dimensionnelle : IPs, hashs, cibles et fenêtres temporelles croisés entre tous les fichiers uploadés"}
    >
      {/* KPIs */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3 mb-6">
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="text-xs text-muted-foreground uppercase tracking-wider">Score de risque</div>
          <div className={`text-3xl font-semibold mt-2 tabular-nums ${riskScore > 100 ? "text-[color:var(--critical)]" : riskScore > 30 ? "text-[color:var(--high)]" : "text-[color:var(--medium)]"}`}>{riskScore}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="text-xs text-muted-foreground uppercase tracking-wider">Corrélations trouvées</div>
          <div className="text-3xl font-semibold mt-2 tabular-nums">{correlated.length}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="text-xs text-muted-foreground uppercase tracking-wider">Alertes host</div>
          <div className="text-3xl font-semibold mt-2 tabular-nums">{hostCount}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="text-xs text-muted-foreground uppercase tracking-wider">Alertes réseau</div>
          <div className="text-3xl font-semibold mt-2 tabular-nums">{networkCount}</div>
        </div>
      </div>

      {/* Type badges */}
      {corrTypes.length > 0 && (
        <div className="flex items-center gap-2 flex-wrap mb-4">
          <span className="text-xs text-muted-foreground">Types de corrélation :</span>
          {corrTypes.map((t: string) => {
            const cfg = TYPE_CONFIG[t] || TYPE_CONFIG.ip;
            const Icon = cfg.icon;
            return (
              <span key={t} className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold border ${cfg.bg} ${cfg.color}`}>
                <Icon className="h-3 w-3" />
                {cfg.label}
              </span>
            );
          })}
        </div>
      )}

      {/* Loading */}
      {isLoading && (
        <div className="flex items-center justify-center gap-2 py-12 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" /> Calcul des corrélations…
        </div>
      )}

      {isError && (
        <div className="flex items-center justify-center gap-2 py-12 text-sm text-destructive">
          <AlertTriangle className="h-4 w-4" /> Impossible de contacter le backend (localhost:8000).
        </div>
      )}

      {!isLoading && !isError && correlated.length === 0 && (
        <Card className="p-10 text-center">
          <Network className="h-10 w-10 mx-auto mb-3 text-muted-foreground opacity-30" />
          <div className="text-sm text-muted-foreground">
            {selectedFileId
              ? `Aucune corrélation détectée pour ${selectedFileName ?? "le fichier sélectionné"}. Les corrélations apparaissent automatiquement quand des indicateurs (IPs, hashs, cibles) sont partagés avec d'autres fichiers du même cas.`
              : "Aucune corrélation détectée. Les corrélations apparaissent automatiquement quand des indicateurs (IPs, hashs, cibles) sont partagés entre 2+ fichiers uploadés dans le même cas."}
          </div>
        </Card>
      )}

      {!isLoading && !isError && correlated.length > 0 && (
        <div className="space-y-4">
          {correlated.map((c: any, idx: number) => {
            const cfg = TYPE_CONFIG[c.type] || TYPE_CONFIG.ip;
            const Icon = cfg.icon;
            return (
              <Card key={idx} className="p-5">
                <div className="flex items-start justify-between gap-4 flex-wrap">
                  <div className="flex items-start gap-3 min-w-0 flex-1">
                    <div className={`h-10 w-10 rounded-md border grid place-items-center shrink-0 ${cfg.bg}`}>
                      <Icon className={`h-4 w-4 ${cfg.color}`} />
                    </div>
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs font-mono text-muted-foreground">CORR-{String(idx + 1).padStart(2, "0")}</span>
                        <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold border ${cfg.bg} ${cfg.color}`}>
                          {cfg.label}
                        </span>
                        <SeverityBadge severity={c.risk ?? "high"} />
                      </div>

                      {/* Indicateur */}
                      <h3 className="text-base font-semibold mt-1 font-mono break-all">
                        {c.indicator}
                      </h3>

                      {/* Fichiers & outils impliqués */}
                      <div className="mt-2 flex flex-wrap gap-2">
                        {(c.tools ?? []).map((tool: string, ti: number) => (
                          <span key={ti} className="inline-flex items-center gap-1 text-[10px] font-bold px-1.5 py-0.5 rounded bg-primary/10 text-primary border border-primary/20">
                            <Shield className="h-2.5 w-2.5" />
                            {tool.toUpperCase()}
                          </span>
                        ))}
                        {(c.files ?? []).map((file: string, fi: number) => (
                          <span key={fi} className="inline-flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded bg-muted border border-border">
                            <FileText className="h-2.5 w-2.5" />
                            {file}
                          </span>
                        ))}
                      </div>

                      {/* Fenêtre temporelle */}
                      {c.time_window && c.time_window !== "—" && (
                        <p className="text-sm text-muted-foreground mt-2">
                          <Clock className="h-3 w-3 inline mr-1" />
                          Fenêtre : <code className="font-mono text-xs">{c.time_window}</code>
                        </p>
                      )}

                      {/* Alertes liées */}
                      <div className="mt-3">
                        <div className="text-xs text-muted-foreground mb-1">{c.alert_count} alerte(s) liée(s) :</div>
                        <div className="flex flex-col gap-1">
                          {(c.network_events ?? []).map((ne: string, ni: number) => (
                            <span
                              key={ni}
                              className="flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded bg-muted border border-border w-fit max-w-full truncate"
                            >
                              <Link2 className="h-2.5 w-2.5 shrink-0" />
                              {ne}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                  <div className="text-right shrink-0 flex flex-col items-end gap-2">
                    <div>
                      <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Risque</div>
                      <div className={`text-lg font-semibold mt-1 uppercase ${c.risk === "critical" ? "text-[color:var(--critical)]" : c.risk === "high" ? "text-[color:var(--high)]" : "text-[color:var(--medium)]"}`}>{c.risk}</div>
                      <div className="text-xs text-muted-foreground mt-1 mb-2">{c.alert_count} alertes</div>
                    </div>
                    <AICorrelationExplainButton data={c} />
                  </div>
                </div>
              </Card>
            );
          })}
        </div>
      )}
    </AppShell>
  );
}
