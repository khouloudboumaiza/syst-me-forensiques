import { createFileRoute } from "@tanstack/react-router";
import { AppShell, Card, SeverityBadge, ToolBadge } from "@/components/app-shell";
import { useTimeline } from "@/hooks/useCaseData";
import { Loader2, AlertTriangle, Clock, Info, X } from "lucide-react";
import { useState } from "react";

export const Route = createFileRoute("/timeline")({
  head: () => ({ meta: [{ title: "Timeline — ForensiQ" }] }),
  component: TimelinePage,
});

function TimelinePage() {
  const { data: events, isLoading, isError } = useTimeline();
  const [showSummary, setShowSummary] = useState(false);
  const eventList = Array.isArray(events) ? events : [];
  
  // Calculs pour le résumé
  const criticalCount = eventList.filter(e => e.severity === "critical").length;
  const highCount = eventList.filter(e => e.severity === "high").length;
  const firstEvent = eventList[0];
  const lastEvent = eventList[eventList.length - 1];
  const dangerousEvents = eventList
    .filter(e => e.severity === "critical" || e.severity === "high")
    .slice(0, 5);

  return (
    <AppShell
      title="Timeline corrélée"
      subtitle={
        isLoading
          ? "Chargement…"
          : `${eventList.length} événement(s) ordonnés chronologiquement depuis le backend`
      }
    >
      <div className="flex justify-end mb-4">
        <button
          onClick={() => setShowSummary(true)}
          disabled={eventList.length === 0}
          className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground text-sm font-medium rounded-md hover:opacity-90 disabled:opacity-50 transition-opacity"
        >
          <Info className="h-4 w-4" />
          Résumé de la Timeline
        </button>
      </div>

      {/* Modal de résumé */}
      {showSummary && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg bg-card border border-border shadow-lg rounded-xl flex flex-col max-h-[90vh]">
            <div className="flex items-center justify-between p-4 border-b border-border sticky top-0 bg-card z-10 rounded-t-xl">
              <h2 className="text-xl font-semibold flex items-center gap-2">
                <Clock className="h-5 w-5 text-primary" /> Résumé de l'Investigation
              </h2>
              <button 
                onClick={() => setShowSummary(false)}
                className="p-1.5 rounded-md hover:bg-muted text-muted-foreground transition-colors"
                title="Fermer (Échap)"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            
            <div className="p-6 overflow-y-auto space-y-4 text-sm">
              <p>Cette timeline contient <strong>{eventList.length}</strong> événements horodatés.</p>
              <div className="bg-muted p-3 rounded border border-border space-y-2">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Premier événement :</span>
                  <span className="font-mono">{firstEvent?.time}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Dernier événement :</span>
                  <span className="font-mono">{lastEvent?.time}</span>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3 mt-4">
                <div className="p-3 border border-destructive/20 bg-destructive/5 rounded flex flex-col">
                  <span className="text-xs text-muted-foreground uppercase tracking-wider">Alertes Critiques</span>
                  <span className="text-2xl font-semibold text-destructive">{criticalCount}</span>
                </div>
                <div className="p-3 border border-[color:var(--high)]/20 bg-[color:var(--high)]/5 rounded flex flex-col">
                  <span className="text-xs text-muted-foreground uppercase tracking-wider">Alertes Hautes</span>
                  <span className="text-2xl font-semibold text-[color:var(--high)]">{highCount}</span>
                </div>
              </div>
              {criticalCount > 0 && (
                <div className="mt-4 p-3 bg-destructive/10 text-destructive text-xs rounded border border-destructive/20">
                  <AlertTriangle className="h-4 w-4 inline-block mr-1 mb-0.5" />
                  <strong>Attention :</strong> Des événements critiques ont été détectés, veuillez examiner la timeline de près.
                </div>
              )}
              {dangerousEvents.length > 0 && (
                <div className="mt-4 border-t border-border pt-4">
                  <h3 className="font-semibold mb-3 flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 text-destructive" /> 
                    Événements les plus dangereux
                  </h3>
                  <ul className="space-y-3">
                    {dangerousEvents.map((de, i) => (
                      <li key={i} className="bg-muted p-3 rounded-md border border-border text-xs">
                        <div className="flex justify-between items-start mb-1">
                          <span className="font-semibold">{de.title}</span>
                          <span className="font-mono text-muted-foreground">{de.time}</span>
                        </div>
                        <div className="flex items-center gap-2 mt-2">
                          <SeverityBadge severity={de.severity} />
                          <ToolBadge tool={de.source} />
                        </div>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      <Card className="p-6">
        {isLoading && (
          <div className="flex items-center justify-center gap-2 py-12 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" /> Chargement de la timeline…
          </div>
        )}

        {isError && (
          <div className="flex items-center justify-center gap-2 py-12 text-sm text-destructive">
            <AlertTriangle className="h-4 w-4" /> Impossible de contacter le backend (localhost:8000).
          </div>
        )}

        {!isLoading && !isError && eventList.length === 0 && (
          <div className="py-12 text-center text-sm text-muted-foreground">
            <Clock className="h-8 w-8 mx-auto mb-3 opacity-30" />
            Aucun événement horodaté pour l'instant. Uploadez un fichier depuis la page Import.
          </div>
        )}

        {!isLoading && !isError && eventList.length > 0 && (
          <div className="relative">
            <div className="absolute left-[92px] top-0 bottom-0 w-px bg-border" />
            <ul className="space-y-4">
              {eventList.map((e: any, idx: number) => (
                <li key={idx} className="relative flex gap-4 items-start group">
                  <div className="w-20 text-right pt-1 shrink-0">
                    <div className="text-xs font-mono tabular-nums text-muted-foreground">{e.time}</div>
                  </div>
                  <div className="relative shrink-0">
                    <div
                      className={`h-3 w-3 rounded-full ring-4 ring-background mt-1.5 transition-transform group-hover:scale-125 ${
                        e.severity === "critical"
                          ? "bg-[color:var(--critical)]"
                          : e.severity === "high"
                            ? "bg-[color:var(--high)]"
                            : e.severity === "medium"
                              ? "bg-[color:var(--medium)]"
                              : "bg-primary"
                      }`}
                    />
                  </div>
                  <div className="flex-1 pb-4">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-medium">{e.title}</span>
                      <SeverityBadge severity={e.severity} />
                      <ToolBadge tool={e.source} />
                    </div>
                    {e.target && (
                      <div className="text-xs font-mono text-muted-foreground mt-0.5 truncate max-w-lg">
                        {e.target}
                      </div>
                    )}
                    {e.detail && (
                      <p className="text-xs text-muted-foreground mt-1">{e.detail}</p>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          </div>
        )}
      </Card>
    </AppShell>
  );
}
