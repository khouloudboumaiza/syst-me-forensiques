import { createFileRoute } from "@tanstack/react-router";
import { AppShell, Card, SeverityBadge, ToolBadge } from "@/components/app-shell";
import { useTimeline } from "@/hooks/useCaseData";
import { Loader2, AlertTriangle, Clock } from "lucide-react";

export const Route = createFileRoute("/timeline")({
  head: () => ({ meta: [{ title: "Timeline — ForensiQ" }] }),
  component: TimelinePage,
});

function TimelinePage() {
  const { data: events, isLoading, isError } = useTimeline();
  const eventList = Array.isArray(events) ? events : [];

  return (
    <AppShell
      title="Timeline corrélée"
      subtitle={
        isLoading
          ? "Chargement…"
          : `${eventList.length} événement(s) ordonnés chronologiquement depuis le backend`
      }
    >
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
