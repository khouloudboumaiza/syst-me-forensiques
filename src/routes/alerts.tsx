import { createFileRoute } from "@tanstack/react-router";
import { useState, useCallback } from "react";
import { AppShell, Card, SeverityBadge, ToolBadge } from "@/components/app-shell";
import { Filter, Search, Loader2, Sparkles, ChevronDown, ChevronUp } from "lucide-react";
import { useAlerts } from "@/hooks/useCaseData";

export const Route = createFileRoute("/alerts")({
  head: () => ({ meta: [{ title: "Alertes — ForensiQ" }] }),
  component: AlertsPage,
});

const API_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

// Cache local pour éviter de ré-appeler l'IA pour la même alerte
const explanationCache: Record<string, string> = {};

async function fetchAIExplanation(rule: string, target: string, source: string, details: string): Promise<string> {
  const cacheKey = `${rule}|${target}|${source}`;
  if (explanationCache[cacheKey]) return explanationCache[cacheKey];

  const res = await fetch(`${API_URL}/explain-alert`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ rule, target, source, details }),
  });
  if (!res.ok) throw new Error("Erreur API");
  const data = await res.json();
  explanationCache[cacheKey] = data.explanation;
  return data.explanation;
}

function normalizeAlert(a: any, index: number) {
  const rule = a.title ?? a.rule ?? a.RuleTitle ?? "Alerte";
  const target = a.target ?? a.dst_ip ?? a.FilePath ?? a.Computer ?? "";
  const source = a.tool ?? a.source ?? "unknown";
  return {
    id: a.id ?? index,
    timestamp: a.timestamp ?? "—",
    severity: (a.severity ?? "medium").toLowerCase(),
    source,
    rule,
    target,
    description: a.details ?? a.description ?? "",
  };
}

// Composant de cellule IA pour chaque ligne du tableau
function AIExplainCell({ rule, target, source, details }: { rule: string; target: string; source: string; details: string }) {
  const [state, setState] = useState<"idle" | "loading" | "done" | "error">("idle");
  const [explanation, setExplanation] = useState<string>("");
  const [expanded, setExpanded] = useState(false);

  const handleExplain = useCallback(async (e: React.MouseEvent) => {
    e.stopPropagation();
    if (state === "loading") return;
    setState("loading");
    try {
      const text = await fetchAIExplanation(rule, target, source, details);
      setExplanation(text);
      setState("done");
      setExpanded(true);
    } catch {
      setState("error");
    }
  }, [rule, target, source, details, state]);

  if (state === "idle") {
    return (
      <button
        onClick={handleExplain}
        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium border border-primary/30 text-primary bg-primary/5 hover:bg-primary/15 transition-all duration-200 group"
      >
        <Sparkles className="h-3.5 w-3.5 group-hover:animate-pulse" />
        Expliquer via IA
      </button>
    );
  }

  if (state === "loading") {
    return (
      <div className="inline-flex items-center gap-2 px-3 py-1.5 text-xs text-muted-foreground">
        <Loader2 className="h-3.5 w-3.5 animate-spin text-primary" />
        <span className="animate-pulse">Analyse IA en cours…</span>
      </div>
    );
  }

  if (state === "error") {
    return (
      <div className="flex items-center gap-2">
        <span className="text-xs text-destructive">Erreur IA</span>
        <button onClick={handleExplain} className="text-xs underline text-muted-foreground hover:text-foreground">
          Réessayer
        </button>
      </div>
    );
  }

  // state === "done"
  const preview = explanation.slice(0, 120);
  const isLong = explanation.length > 120;

  return (
    <div className="text-xs bg-gradient-to-br from-primary/8 to-violet-500/5 border border-primary/20 rounded-lg p-3 leading-relaxed space-y-2 max-w-xs">
      <div className="flex items-center gap-1.5 text-primary font-semibold mb-1">
        <Sparkles className="h-3 w-3" />
        Analyse IA
      </div>
      <p className="text-foreground/80">
        {expanded || !isLong ? explanation : `${preview}…`}
      </p>
      {isLong && (
        <button
          onClick={(e) => { e.stopPropagation(); setExpanded(!expanded); }}
          className="inline-flex items-center gap-1 text-primary/70 hover:text-primary text-[11px] font-medium transition-colors"
        >
          {expanded ? <><ChevronUp className="h-3 w-3" /> Réduire</> : <><ChevronDown className="h-3 w-3" /> Voir plus</>}
        </button>
      )}
    </div>
  );
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
                  <th className="text-left px-4 py-3 min-w-[220px]">
                    <span className="inline-flex items-center gap-1.5">
                      <Sparkles className="h-3.5 w-3.5 text-primary" />
                      Explication (IA)
                    </span>
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {filtered.map((a) => (
                  <tr key={a.id} className="hover:bg-muted/30 transition-colors align-top">
                    <td className="px-4 py-3 font-mono text-xs text-muted-foreground">{a.id}</td>
                    <td className="px-4 py-3 font-mono text-xs tabular-nums">{a.timestamp}</td>
                    <td className="px-4 py-3">
                      <SeverityBadge severity={a.severity} />
                    </td>
                    <td className="px-4 py-3">
                      <ToolBadge tool={a.source} />
                    </td>
                    <td className="px-4 py-3 font-medium max-w-[200px]">
                      <div className="line-clamp-2" title={a.rule}>{a.rule}</div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="font-mono text-xs text-muted-foreground truncate max-w-[200px]" title={a.target}>
                        {a.target}
                      </div>
                      <div className="text-xs mt-0.5 line-clamp-2 text-muted-foreground" title={a.description}>{a.description}</div>
                    </td>
                    <td className="px-4 py-3">
                      <AIExplainCell
                        rule={a.rule}
                        target={a.target}
                        source={a.source}
                        details={a.description}
                      />
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
