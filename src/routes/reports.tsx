import { createFileRoute } from "@tanstack/react-router";
import { AppShell, Card, SeverityBadge } from "@/components/app-shell";
import { useStats, useCorrelations, useAlerts, useReport } from "@/hooks/useCaseData";
import { FileText, Download, FileJson, FileCode, Loader2, AlertTriangle, ArrowUpRight } from "lucide-react";
import { API_URL } from "@/lib/api";

export const Route = createFileRoute("/reports")({
  head: () => ({ meta: [{ title: "Rapports — ForensiQ" }] }),
  component: ReportsPage,
});

function ReportsPage() {
  const { data: stats, isLoading: statsLoading } = useStats();
  const { data: correlationsData, isLoading: corrLoading } = useCorrelations();
  const { data: rawAlerts, isLoading: alertsLoading } = useAlerts();
  const { data: report } = useReport();

  const isLoading = statsLoading || corrLoading || alertsLoading;
  const alerts = Array.isArray(rawAlerts) ? rawAlerts : [];
  const correlated = Array.isArray(correlationsData?.correlated_events)
    ? correlationsData.correlated_events
    : [];

  // Résumé dynamique
  const topSeverity = alerts.some((a: any) => a.severity === "critical")
    ? "critique"
    : alerts.some((a: any) => a.severity === "high")
      ? "élevé"
      : "modéré";

  const tools = [...new Set(alerts.map((a: any) => a.tool).filter(Boolean))];

  return (
    <AppShell title="Rapports d'investigation" subtitle="Génération automatique aux formats PDF, HTML, JSON">
      {/* Boutons d'export */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
        {[
          {
            icon: FileText,
            label: "PDF exécutif",
            desc: "Rapport formaté pour direction et audit.",
            href: `${API_URL}/cases/demo/report/pdf`,
            external: true,
          },
          {
            icon: FileCode,
            label: "HTML interactif",
            desc: "Rapport navigable avec liens et filtres.",
            href: null,
            external: false,
          },
          {
            icon: FileJson,
            label: "Export JSON",
            desc: "Données normalisées pour SIEM / SOAR.",
            href: `${API_URL}/cases/demo/report`,
            external: true,
          },
        ].map((f) => (
          <Card key={f.label} className="p-5 hover:border-primary/40 transition-colors cursor-pointer group">
            <div className="flex items-start justify-between">
              <div className="h-10 w-10 rounded-md bg-primary/10 border border-primary/20 grid place-items-center">
                <f.icon className="h-5 w-5 text-primary" />
              </div>
              {f.href ? (
                <a
                  href={f.href}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center gap-1 text-xs text-primary hover:underline"
                >
                  Télécharger <ArrowUpRight className="h-3 w-3" />
                </a>
              ) : (
                <Download className="h-4 w-4 text-muted-foreground group-hover:text-primary" />
              )}
            </div>
            <div className="mt-4">
              <div className="font-semibold text-sm">{f.label}</div>
              <p className="text-xs text-muted-foreground mt-1">{f.desc}</p>
            </div>
          </Card>
        ))}
      </div>

      {/* Aperçu dynamique du rapport */}
      <Card className="p-8 max-w-4xl mx-auto">
        {isLoading ? (
          <div className="flex items-center justify-center gap-2 py-12 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" /> Chargement du rapport…
          </div>
        ) : (
          <>
            <div className="border-b border-border pb-4 mb-6">
              <div className="text-[10px] uppercase tracking-widest text-muted-foreground">
                Rapport forensique · CASE-demo
              </div>
              <h2 className="text-2xl font-semibold mt-2">Investigation ForensiQ — Dossier demo</h2>
              <div className="flex flex-wrap gap-4 mt-3 text-xs text-muted-foreground">
                <span>
                  Outils :{" "}
                  <span className="text-foreground font-medium">
                    {tools.length > 0 ? tools.join(", ") : "—"}
                  </span>
                </span>
                <span>
                  Niveau de menace :{" "}
                  <span className="text-[color:var(--high)] font-medium capitalize">{topSeverity}</span>
                </span>
              </div>
            </div>

            {/* Résumé exécutif dynamique */}
            <section className="mb-6">
              <h3 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-2">
                Résumé exécutif
              </h3>
              {alerts.length === 0 ? (
                <p className="text-sm text-muted-foreground italic">
                  Aucune alerte disponible. Uploadez un fichier forensique pour générer un résumé.
                </p>
              ) : (
                <p className="text-sm leading-relaxed">
                  L'analyse du dossier <strong>demo</strong> a généré{" "}
                  <strong>{stats?.alerts ?? alerts.length} alertes</strong> issues de{" "}
                  <strong>{tools.length || 1} source(s)</strong> forensique(s) (
                  {tools.join(", ") || "inconnues"}). Le niveau de menace est jugé{" "}
                  <strong>{topSeverity}</strong>.
                  {stats?.iocs && stats.iocs > 0
                    ? ` ${stats.iocs} indicateur(s) de compromission (IOCs) ont été identifiés.`
                    : ""}
                  {correlated.length > 0
                    ? ` ${correlated.length} corrélation(s) host/réseau ont été détectées.`
                    : ""}
                </p>
              )}
            </section>

            {/* Statistiques */}
            <section className="mb-6 grid grid-cols-2 md:grid-cols-4 gap-3">
              {[
                { l: "Fichiers analysés", v: stats?.files_analyzed ?? 0 },
                { l: "Alertes", v: stats?.alerts ?? alerts.length },
                { l: "IOCs", v: stats?.iocs ?? 0 },
                { l: "Corrélations", v: correlated.length },
              ].map((k) => (
                <div key={k.l} className="rounded-md border border-border p-3">
                  <div className="text-[10px] uppercase tracking-widest text-muted-foreground">{k.l}</div>
                  <div className="text-xl font-semibold tabular-nums mt-1">{k.v}</div>
                </div>
              ))}
            </section>

            {/* Top 5 alertes critiques */}
            {alerts.length > 0 && (
              <section className="mb-6">
                <h3 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-3">
                  Alertes les plus critiques
                </h3>
                <div className="space-y-2">
                  {alerts
                    .filter((a: any) => ["critical", "high"].includes(a.severity))
                    .slice(0, 5)
                    .map((a: any, i: number) => (
                      <div key={i} className="border border-border rounded-md p-3 flex items-center gap-3">
                        <SeverityBadge severity={a.severity} />
                        <div className="min-w-0 flex-1">
                          <div className="text-sm font-medium truncate">{a.title ?? "Alerte"}</div>
                          <div className="text-xs text-muted-foreground truncate">{a.target ?? ""}</div>
                        </div>
                        <div className="text-xs text-muted-foreground font-mono shrink-0">
                          {String(a.timestamp ?? "").slice(0, 19)}
                        </div>
                      </div>
                    ))}
                </div>
              </section>
            )}

            {/* Corrélations */}
            {correlated.length > 0 && (
              <section className="mb-6">
                <h3 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-3">
                  Incidents corrélés
                </h3>
                <div className="space-y-3">
                  {correlated.map((c: any, i: number) => (
                    <div key={i} className="border border-border rounded-md p-4">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-mono text-muted-foreground">
                            CORR-{String(i + 1).padStart(2, "0")}
                          </span>
                          <SeverityBadge severity={c.risk ?? "high"} />
                        </div>
                        <span className="text-xs text-muted-foreground font-mono">{c.time_window}</span>
                      </div>
                      <div className="font-medium text-sm mt-1">{c.host_event}</div>
                      <p className="text-xs text-muted-foreground mt-1">
                        {(c.network_events ?? []).join(", ")}
                      </p>
                    </div>
                  ))}
                </div>
              </section>
            )}

            {/* Recommandations dynamiques */}
            <section>
              <h3 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-2">
                Recommandations
              </h3>
              <ul className="text-sm space-y-1.5 list-disc pl-5 text-foreground/90">
                {alerts.some((a: any) => a.severity === "critical") && (
                  <li>Isoler immédiatement le(s) poste(s) concerné(s) du réseau.</li>
                )}
                {(stats?.iocs ?? 0) > 0 && (
                  <li>Bloquer les IOCs identifiés (IPs, domaines) sur le pare-feu.</li>
                )}
                {correlated.length > 0 && (
                  <li>Investiguer les corrélations host/réseau pour retracer la chaîne d'attaque complète.</li>
                )}
                <li>Réinitialiser les identifiants des comptes potentiellement compromis.</li>
                <li>Analyser les autres postes du même segment réseau pour propagation latérale.</li>
                <li>Restaurer à partir de la dernière sauvegarde saine et re-imager les machines touchées.</li>
              </ul>
            </section>
          </>
        )}
      </Card>
    </AppShell>
  );
}
