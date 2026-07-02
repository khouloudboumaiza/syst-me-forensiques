import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { AppShell, Card, SeverityBadge, ToolBadge } from "@/components/app-shell";
import { Filter, Search, Loader2 } from "lucide-react";
import { useAlerts } from "@/hooks/useCaseData";

export const Route = createFileRoute("/alerts")({
  head: () => ({ meta: [{ title: "Alertes — ForensiQ" }] }),
  component: AlertsPage,
});

// Normalise les champs venant du backend (Hayabusa / Loki / ML réseau n'ont pas
// exactement les mêmes noms de colonnes) vers un format unique pour l'affichage.
function normalizeAlert(a: any, index: number) {
  return {
    id: a.id ?? index,
    timestamp: a.timestamp ?? "—",
    severity: (a.severity ?? "medium").toLowerCase(),
    source: a.tool ?? a.source ?? "unknown",
    rule: a.title ?? a.rule ?? a.RuleTitle ?? "Alerte",
    target: a.target ?? a.dst_ip ?? a.FilePath ?? a.Computer ?? "",
    description: a.details ?? a.description ?? "",
  };
}

function AlertsPage() {
  const [q, setQ] = useState("");
  const [sev, setSev] = useState<string>("all");

  const { data: rawAlerts, isLoading, isError } = useAlerts();

  const alerts = Array.isArray(rawAlerts) ? rawAlerts.map(normalizeAlert) : [];

  const filtered = alerts.filter(
    (a) =>
      (sev === "all" || a.severity === sev) &&
      (q === "" ||
        (a.rule + a.target + a.description).toLowerCase().includes(q.toLowerCase())),
  );

  return (
    <AppShell
      title="Alertes"
      subtitle={
        isLoading
          ? "Chargement…"
          : `${filtered.length} alertes filtrées sur ${alerts.length}`
      }
    >
      <Card className="p-4 mb-4 flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-muted border border-border flex-1 min-w-64">
          <Search className="h-3.5 w-3.5 text-muted-foreground" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Filtrer par règle, chemin, description…"
            className="bg-transparent text-sm outline-none flex-1"
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-muted-foreground" />
          {["all", "critical", "high", "medium", "low"].map((s) => (
            <button
              key={s}
              onClick={() => setSev(s)}
              className={`px-2.5 py-1 rounded text-xs capitalize border transition-colors ${
                sev === s
                  ? "bg-primary text-primary-foreground border-primary"
                  : "border-border hover:bg-muted"
              }`}
            >
              {s}
            </button>
          ))}
        </div>
      </Card>

      <Card>
        {isLoading && (
          <div className="flex items-center justify-center gap-2 py-12 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" /> Chargement des alertes…
          </div>
        )}

        {isError && (
          <div className="py-12 text-center text-sm text-destructive">
            Impossible de contacter le backend (localhost:8000). Vérifiez qu'uvicorn tourne.
          </div>
        )}

        {!isLoading && !isError && filtered.length === 0 && (
          <div className="py-12 text-center text-sm text-muted-foreground">
            Aucune alerte pour l'instant. Uploadez un fichier depuis la page Import.
          </div>
        )}

        {!isLoading && !isError && filtered.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-xs uppercase text-muted-foreground border-b border-border">
                <tr>
                  <th className="text-left px-4 py-3">ID</th>
                  <th className="text-left px-4 py-3">Horodatage</th>
                  <th className="text-left px-4 py-3">Sévérité</th>
                  <th className="text-left px-4 py-3">Source</th>
                  <th className="text-left px-4 py-3">Règle</th>
                  <th className="text-left px-4 py-3">Cible / Description</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {filtered.map((a) => (
                  <tr key={a.id} className="hover:bg-muted/30 transition-colors">
                    <td className="px-4 py-3 font-mono text-xs text-muted-foreground">{a.id}</td>
                    <td className="px-4 py-3 font-mono text-xs tabular-nums">{a.timestamp}</td>
                    <td className="px-4 py-3">
                      <SeverityBadge severity={a.severity} />
                    </td>
                    <td className="px-4 py-3">
                      <ToolBadge tool={a.source} />
                    </td>
                    <td className="px-4 py-3 font-medium">{a.rule}</td>
                    <td className="px-4 py-3">
                      <div className="font-mono text-xs text-muted-foreground truncate max-w-md">
                        {a.target}
                      </div>
                      <div className="text-xs mt-0.5">{a.description}</div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </AppShell>
  );
}
