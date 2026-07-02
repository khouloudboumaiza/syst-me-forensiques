import { createFileRoute } from "@tanstack/react-router";
import { AppShell, Card, SeverityBadge, ToolBadge } from "@/components/app-shell";
import { useCorrelations } from "@/hooks/useCaseData";
import { Network, Loader2, AlertTriangle, Link2 } from "lucide-react";

export const Route = createFileRoute("/correlations")({
  head: () => ({ meta: [{ title: "Corrélations — ForensiQ" }] }),
  component: CorrelationsPage,
});

function CorrelationsPage() {
  const { data: correlationsData, isLoading, isError } = useCorrelations();

  const correlated = Array.isArray(correlationsData?.correlated_events)
    ? correlationsData.correlated_events
    : [];
  const hostCount = correlationsData?.total_host_alerts ?? 0;
  const networkCount = correlationsData?.total_network_alerts ?? 0;
  const riskScore = correlationsData?.combined_risk_score ?? 0;

  return (
    <AppShell
      title="Corrélations intelligentes"
      subtitle="Événements host/réseau regroupés automatiquement en incidents cohérents"
    >
      {/* KPIs */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-6">
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="text-xs text-muted-foreground uppercase tracking-wider">Score de risque combiné</div>
          <div className="text-3xl font-semibold mt-2 text-[color:var(--high)] tabular-nums">{riskScore}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="text-xs text-muted-foreground uppercase tracking-wider">Alertes host (Hayabusa/Loki)</div>
          <div className="text-3xl font-semibold mt-2 tabular-nums">{hostCount}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="text-xs text-muted-foreground uppercase tracking-wider">Alertes réseau (ML)</div>
          <div className="text-3xl font-semibold mt-2 tabular-nums">{networkCount}</div>
        </div>
      </div>

      {/* Corrélations */}
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
            Aucune corrélation host/réseau détectée. Pour obtenir des corrélations, uploadez à la fois
            un fichier Hayabusa/Loki <strong>et</strong> un CSV réseau ML dans la même fenêtre temporelle.
          </div>
        </Card>
      )}

      {!isLoading && !isError && correlated.length > 0 && (
        <div className="space-y-4">
          {correlated.map((c: any, idx: number) => (
            <Card key={idx} className="p-5">
              <div className="flex items-start justify-between gap-4 flex-wrap">
                <div className="flex items-start gap-3 min-w-0 flex-1">
                  <div className="h-10 w-10 rounded-md bg-primary/10 border border-primary/20 grid place-items-center shrink-0">
                    <Network className="h-4 w-4 text-primary" />
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-mono text-muted-foreground">CORR-{String(idx + 1).padStart(2, "0")}</span>
                      <SeverityBadge severity={c.risk ?? "high"} />
                    </div>
                    <h3 className="text-base font-semibold mt-1">{c.host_event}</h3>
                    <p className="text-sm text-muted-foreground mt-2">
                      Fenêtre temporelle :{" "}
                      <code className="font-mono text-xs">{c.time_window}</code>
                    </p>
                    <div className="mt-3">
                      <div className="text-xs text-muted-foreground mb-1">Événements réseau corrélés :</div>
                      <div className="flex items-center gap-2 flex-wrap">
                        {(c.network_events ?? []).map((ne: string, ni: number) => (
                          <span
                            key={ni}
                            className="flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded bg-muted border border-border"
                          >
                            <Link2 className="h-2.5 w-2.5" />
                            {ne}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
                <div className="text-right shrink-0">
                  <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Risque</div>
                  <div className="text-lg font-semibold text-[color:var(--critical)] mt-1 uppercase">{c.risk}</div>
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}
    </AppShell>
  );
}
