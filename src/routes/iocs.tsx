import { createFileRoute } from "@tanstack/react-router";
import { AppShell, Card, ToolBadge } from "@/components/app-shell";
import { Copy, Fingerprint, Loader2, AlertTriangle } from "lucide-react";
import { useIOCs, useFilesList } from "@/hooks/useCaseData";
import { useState, useMemo } from "react";

export const Route = createFileRoute("/iocs")({
  head: () => ({ meta: [{ title: "IOCs — ForensiQ" }] }),
  component: IocsPage,
});

const IOC_TYPES = ["IP", "Hash", "Domain", "File", "Registry"] as const;
type IocType = (typeof IOC_TYPES)[number];

function IocsPage() {
  const { data: iocs, isLoading, isError } = useIOCs();
  const { data: files } = useFilesList();
  const [copied, setCopied] = useState<string | null>(null);
  const [filter, setFilter] = useState<string>("all");

  const iocList = Array.isArray(iocs) ? iocs : [];
  
  // Associe chaque IOC à son nom de fichier
  const enrichedIocs = useMemo(() => {
    const filesArray = Array.isArray(files) ? files : [];
    const filesMap = filesArray.reduce((acc: any, f: any) => ({ ...acc, [f.id]: f.filename }), {});
    
    return iocList.map(ioc => ({
      ...ioc,
      filename: ioc.file_id ? (filesMap[ioc.file_id] || "Inconnu") : "Inconnu"
    }));
  }, [iocList, files]);

  const filtered = filter === "all" ? enrichedIocs : enrichedIocs.filter((i) => i.type === filter);

  const handleCopy = (value: string) => {
    navigator.clipboard.writeText(value);
    setCopied(value);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <AppShell
      title="Indicateurs de compromission"
      subtitle={
        isLoading
          ? "Chargement depuis le backend…"
          : `${iocList.length} IOC(s) extraits et normalisés depuis les alertes`
      }
    >
      {/* Compteurs par type */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-3 mb-4">
        <button
          onClick={() => setFilter("all")}
          className={`col-span-1 rounded-lg border p-4 text-left transition-colors ${
            filter === "all" ? "border-primary bg-primary/10" : "border-border bg-card hover:border-primary/40"
          }`}
        >
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Fingerprint className="h-3.5 w-3.5" /> Tous
          </div>
          <div className="text-2xl font-semibold mt-2 tabular-nums">{iocList.length}</div>
        </button>
        {IOC_TYPES.map((t) => {
          const count = iocList.filter((i) => i.type === t).length;
          return (
            <button
              key={t}
              onClick={() => setFilter(t)}
              className={`rounded-lg border p-4 text-left transition-colors ${
                filter === t ? "border-primary bg-primary/10" : "border-border bg-card hover:border-primary/40"
              }`}
            >
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <Fingerprint className="h-3.5 w-3.5" /> {t}
              </div>
              <div className="text-2xl font-semibold mt-2 tabular-nums">{count}</div>
            </button>
          );
        })}
      </div>

      <Card>
        {isLoading && (
          <div className="flex items-center justify-center gap-2 py-12 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" /> Chargement des IOCs depuis le backend…
          </div>
        )}

        {isError && (
          <div className="flex items-center justify-center gap-2 py-12 text-sm text-destructive">
            <AlertTriangle className="h-4 w-4" /> Impossible de contacter le backend (localhost:8000).
          </div>
        )}

        {!isLoading && !isError && filtered.length === 0 && (
          <div className="py-12 text-center text-sm text-muted-foreground">
            Aucun IOC extrait pour l'instant. Uploadez un fichier Loki ou Hayabusa depuis la page Import.
          </div>
        )}

        {!isLoading && !isError && filtered.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-xs uppercase text-muted-foreground border-b border-border">
                <tr>
                  <th className="text-left px-4 py-3">Type</th>
                  <th className="text-left px-4 py-3">Valeur</th>
                  <th className="text-left px-4 py-3">Outil</th>
                  <th className="text-left px-4 py-3">Fichier analysé</th>
                  <th className="text-left px-4 py-3">Occurrences</th>
                  <th className="text-left px-4 py-3">Vu pour la 1ère fois</th>
                  <th className="px-4 py-3"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {filtered.map((i: any) => (
                  <tr key={i.value} className="hover:bg-muted/30 transition-colors">
                    <td className="px-4 py-3">
                      <span className="text-[10px] uppercase tracking-wider px-2 py-0.5 rounded border border-border bg-muted">
                        {i.type}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs max-w-xs truncate">{i.value}</td>
                    <td className="px-4 py-3">
                      <ToolBadge tool={i.source} />
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-muted-foreground max-w-xs truncate" title={i.filename}>
                      {i.filename}
                    </td>
                    <td className="px-4 py-3 tabular-nums">{i.hits}</td>
                    <td className="px-4 py-3 font-mono text-xs text-muted-foreground">
                      {String(i.firstSeen ?? "—").slice(0, 19)}
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => handleCopy(i.value)}
                        title="Copier la valeur"
                        className="h-7 w-7 grid place-items-center rounded border border-border hover:bg-muted transition-colors"
                      >
                        {copied === i.value ? (
                          <span className="text-[8px] text-[color:var(--success)] font-bold">OK</span>
                        ) : (
                          <Copy className="h-3 w-3" />
                        )}
                      </button>
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
