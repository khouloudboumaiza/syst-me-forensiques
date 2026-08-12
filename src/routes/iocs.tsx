import { createFileRoute } from "@tanstack/react-router";
import { AppShell, Card, ToolBadge } from "@/components/app-shell";
import { Copy, Fingerprint, Loader2, AlertTriangle, ShieldCheck, ShieldAlert, ShieldX, HelpCircle, Sparkles } from "lucide-react";
import { useIOCs, useFilesList } from "@/hooks/useCaseData";
import { useState, useMemo, useCallback } from "react";
import { useQuery } from "@tanstack/react-query";
import { API_URL } from "@/lib/api";

export const Route = createFileRoute("/iocs")({
  head: () => ({ meta: [{ title: "IOCs — ForensiQ" }] }),
  component: IocsPage,
});

const IOC_TYPES = ["IP", "Hash", "Domain", "File", "Registry"] as const;
type IocType = (typeof IOC_TYPES)[number];

// Cache pour les classifications IA
const classifyCache: Record<string, any> = {};

// Statut => style visuel
const STATUS_CONFIG: Record<string, { label: string; icon: any; cls: string }> = {
  true_positive:            { label: "Vrai Positif",           icon: ShieldX,      cls: "bg-destructive/15 text-destructive border-destructive/30" },
  likely_false_positive:    { label: "Faux Positif (Probable)", icon: ShieldCheck,  cls: "bg-[color:var(--success)]/15 text-[color:var(--success)] border-[color:var(--success)]/30" },
  potential_false_negative: { label: "Faux Négatif (Potentiel)",icon: ShieldAlert,  cls: "bg-orange-500/15 text-orange-500 border-orange-500/30" },
  suspicious_review:        { label: "Suspect (À revoir)",     icon: ShieldAlert,  cls: "bg-[color:var(--medium)]/15 text-[color:var(--medium)] border-[color:var(--medium)]/30" },
  clean:                    { label: "Sain",                   icon: ShieldCheck,  cls: "bg-[color:var(--success)]/15 text-[color:var(--success)] border-[color:var(--success)]/30" },
};

const isHashLike = (value?: string) => typeof value === "string" && /[a-f0-9]{8,64}/i.test(value);

function VirusTotalCell({ ioc }: { ioc: any }) {
  const lookupHash = ioc.linkedHash || (ioc.type === "Hash" ? ioc.value : "");
  const isHash = ioc.type === "Hash" || ioc.type === "IP" || Boolean(lookupHash);
  if (ioc.vtScore && ioc.vtScore !== "—") {
    return (
      <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold border ${ioc.vtVerdict === "malicious" ? "bg-destructive/15 text-destructive border-destructive/30" : ioc.vtVerdict === "clean" ? "bg-success/15 text-success border-success/30" : "bg-medium/15 text-medium border-medium/30"}`}>
        {ioc.vtScore}
      </span>
    );
  }
  const { data, isLoading } = useQuery({
    queryKey: ["vt", ioc.type, lookupHash || ioc.value],
    queryFn: () => fetch(`${API_URL}/vt/hash/${encodeURIComponent(lookupHash || ioc.value)}`).then((r) => r.json()),
    enabled: isHash && isHashLike(lookupHash || ioc.value) && !ioc.vtScore,
    staleTime: Infinity,
  });
  if (!isHash || !isHashLike(lookupHash || ioc.value)) return <span className="text-xs text-muted-foreground">—</span>;
  if (isLoading) return <Loader2 className="h-3 w-3 animate-spin text-muted-foreground" />;
  if (data && data.found) {
    const total = (data.malicious || 0) + (data.suspicious || 0) + (data.harmless || 0);
    const scoreStr = `${data.malicious}/${total}`;
    return (
      <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold border ${data.verdict === "malicious" ? "bg-destructive/15 text-destructive border-destructive/30" : data.verdict === "clean" ? "bg-success/15 text-success border-success/30" : "bg-medium/15 text-medium border-medium/30"}`}>
        {scoreStr}
      </span>
    );
  }
  return <span className="text-[10px] text-muted-foreground">0/0</span>;
}

// Cellule de classification IA avec bouton, chargement et résultat
function AIClassifyCell({ ioc }: { ioc: any }) {
  const [state, setState] = useState<"idle" | "loading" | "done" | "error">("idle");
  const [result, setResult] = useState<any>(null);

  const lookupHash = ioc.linkedHash || (ioc.type === "Hash" ? ioc.value : "");
  const { data: vtData } = useQuery({
    queryKey: ["vt", ioc.type, lookupHash || ioc.value],
    queryFn: () => fetch(`${API_URL}/vt/hash/${encodeURIComponent(lookupHash || ioc.value)}`).then((r) => r.json()),
    enabled: isHashLike(lookupHash || ioc.value),
    staleTime: Infinity,
  });

  const handleClassify = useCallback(async (e: React.MouseEvent) => {
    e.stopPropagation();
    if (state === "loading") return;

    const cacheKey = `${ioc.value}|${ioc.type}|${lookupHash || ""}`;
    if (classifyCache[cacheKey]) {
      setResult(classifyCache[cacheKey]);
      setState("done");
      return;
    }

    setState("loading");
    try {
      const body: any = {
        hash_value: lookupHash || (ioc.type === "Hash" ? ioc.value : ""),
        file_path: ioc.filename || ioc.value || "",
        tool: ioc.source || "",
        vt_malicious: 0,
        vt_total: 0,
        vt_verdict: "unknown",
      };

      // Utiliser les données VT si disponibles
      if (vtData && vtData.found) {
        const total = (vtData.malicious || 0) + (vtData.suspicious || 0) + (vtData.harmless || 0);
        body.vt_malicious = vtData.malicious || 0;
        body.vt_total = total;
        body.vt_verdict = vtData.verdict || "unknown";
      }

      const res = await fetch(`${API_URL}/classify-ioc`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error("Erreur API");
      const data = await res.json();
      classifyCache[cacheKey] = data;
      setResult(data);
      setState("done");
    } catch {
      setState("error");
    }
  }, [ioc, vtData, state]);

  if (state === "idle") {
    return (
      <button
        onClick={handleClassify}
        className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-[11px] font-medium border border-violet-500/30 text-violet-400 bg-violet-500/5 hover:bg-violet-500/15 transition-all group"
      >
        <Sparkles className="h-3 w-3 group-hover:animate-pulse" />
        Classer via IA
      </button>
    );
  }

  if (state === "loading") {
    return (
      <div className="inline-flex items-center gap-1.5 text-[11px] text-muted-foreground">
        <Loader2 className="h-3 w-3 animate-spin text-violet-400" />
        <span className="animate-pulse">Analyse IA…</span>
      </div>
    );
  }

  if (state === "error") {
    return (
      <button onClick={handleClassify} className="text-[11px] text-destructive underline">
        Erreur — Réessayer
      </button>
    );
  }

  // state === "done"
  const cfg = STATUS_CONFIG[result?.status] || STATUS_CONFIG["suspicious_review"];
  const Icon = cfg.icon;
  const confValue = result?.confidence !== undefined ? Math.round(result.confidence) : 0;

  return (
    <div className="space-y-2 max-w-xs">
      <div className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-bold border ${cfg.cls}`}>
        <Icon className="h-3 w-3" />
        {cfg.label}
        <span className="opacity-60 text-[9px]">({confValue}%)</span>
      </div>
      <p className="text-[11px] text-muted-foreground leading-relaxed line-clamp-3" title={result?.explanation}>
        {result?.explanation}
      </p>
      {result?.recommendation && (
        <p className="text-[10px] text-primary/70 bg-primary/5 rounded p-1.5 border border-primary/10 leading-snug">
          💡 {result.recommendation}
        </p>
      )}
    </div>
  );
}

function IocsPage() {
  const { data: iocs, isLoading, isError } = useIOCs();
  const { data: files } = useFilesList();
  const [copied, setCopied] = useState<string | null>(null);
  const [filter, setFilter] = useState<string>("all");

  const iocList = Array.isArray(iocs) ? iocs : [];

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

  // Compteurs de statuts pour le résumé global
  const hashIocs = enrichedIocs.filter(i => i.type === "Hash");

  return (
    <AppShell
      title="Indicateurs de compromission"
      subtitle={isLoading ? "Chargement depuis le backend…" : `${iocList.length} IOC(s) extraits et normalisés depuis les alertes`}
    >
      {/* Compteurs par type */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-3 mb-4">
        <button
          onClick={() => setFilter("all")}
          className={`col-span-1 rounded-lg border p-4 text-left transition-colors ${filter === "all" ? "border-primary bg-primary/10" : "border-border bg-card hover:border-primary/40"}`}
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
              className={`rounded-lg border p-4 text-left transition-colors ${filter === t ? "border-primary bg-primary/10" : "border-border bg-card hover:border-primary/40"}`}
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
            Aucun IOC extrait. Uploadez un fichier depuis la page Import.
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
                  <th className="text-left px-4 py-3">VirusTotal</th>
                  <th className="text-left px-4 py-3">Occurrences</th>
                  <th className="text-left px-4 py-3">1ère détection</th>
                  <th className="text-left px-4 py-3 min-w-55">
                    <span className="inline-flex items-center gap-1">
                      <Sparkles className="h-3 w-3 text-violet-400" /> Classification IA
                    </span>
                  </th>
                  <th className="px-4 py-3"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {filtered.map((i: any) => (
                  <tr key={i.value} className="hover:bg-muted/30 transition-colors align-top">
                    <td className="px-4 py-3">
                      <span className="text-[10px] uppercase tracking-wider px-2 py-0.5 rounded border border-border bg-muted">
                        {i.type}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs max-w-xs truncate" title={i.value}>{i.value}</td>
                    <td className="px-4 py-3"><ToolBadge tool={i.source} /></td>
                    <td className="px-4 py-3 font-mono text-xs text-muted-foreground max-w-xs truncate" title={i.filename}>
                      {i.filename}
                    </td>
                    <td className="px-4 py-3"><VirusTotalCell ioc={i} /></td>
                    <td className="px-4 py-3 tabular-nums">{i.hits}</td>
                    <td className="px-4 py-3 font-mono text-xs text-muted-foreground">
                      {String(i.firstSeen ?? "—").slice(0, 19)}
                    </td>
                    <td className="px-4 py-3">
                      {i.type === "Hash" || i.type === "File" ? (
                        <AIClassifyCell ioc={i} />
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => handleCopy(i.value)}
                        title="Copier la valeur"
                        className="h-7 w-7 grid place-items-center rounded border border-border hover:bg-muted transition-colors"
                      >
                        {copied === i.value ? (
                          <span className="text-[8px] text-success font-bold">OK</span>
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
