import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { AppShell } from "@/components/app-shell";
import { useStats, useCorrelations, useAlerts, useIOCs, useFilesList, useReport, useAnalysisStatus } from "@/hooks/useCaseData";
import { useFileSelection } from "@/hooks/useFileSelection";
import { API_URL } from "@/lib/api";
import {
  FileText, Download, Printer, Shield, AlertTriangle,
  Clock, CheckCircle2, XCircle, ChevronRight, Globe,
  Cpu, ArrowUpRight, Fingerprint, Network, FileWarning, Filter,
} from "lucide-react";

export const Route = createFileRoute("/reports")({
  head: () => ({ meta: [{ title: "Rapport d'Investigation — ForensiQ" }] }),
  component: ReportsPage,
});

// ─── Helpers ──────────────────────────────────────────────────────────────────
const SEV_COLOR: Record<string, string> = {
  critical: "#dc2626",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#22c55e",
  info:     "#3b82f6",
};

const SEV_BG: Record<string, string> = {
  critical: "rgba(220,38,38,0.12)",
  high:     "rgba(249,115,22,0.12)",
  medium:   "rgba(234,179,8,0.12)",
  low:      "rgba(34,197,94,0.12)",
  info:     "rgba(59,130,246,0.12)",
};

function sevLabel(s: string) {
  return { critical: "CRITIQUE", high: "ÉLEVÉ", medium: "MOYEN", low: "FAIBLE", info: "INFO" }[s] ?? s.toUpperCase();
}

function now() {
  return new Date().toLocaleString("fr-FR", {
    day: "2-digit", month: "long", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

function threatLevel(alerts: any[]): { label: string; color: string } {
  if (alerts.some((a) => a.severity === "critical")) return { label: "CRITIQUE",  color: "#dc2626" };
  if (alerts.some((a) => a.severity === "high"))     return { label: "ÉLEVÉ",     color: "#f97316" };
  if (alerts.some((a) => a.severity === "medium"))   return { label: "MODÉRÉ",    color: "#eab308" };
  return { label: "FAIBLE", color: "#22c55e" };
}

function generateExplanation(rule: string, target: string, source: string) {
  const r = (rule || "").toLowerCase();
  if (r.includes("logon") || r.includes("login") || r.includes("connexion")) {
    return `Tentative de connexion identifiée sur la machine / l'IP ${target || "cible"}.`;
  }
  if (r.includes("process") || r.includes("execution") || r.includes("cmd") || r.includes("shell")) {
    return `Exécution d'une commande ou d'un processus potentiellement malveillant (${target}).`;
  }
  if (r.includes("malware") || r.includes("virus") || r.includes("trojan") || r.includes("backdoor")) {
    return `Un logiciel malveillant potentiel a été détecté dans ${target || "le système"}.`;
  }
  if (r.includes("network") || r.includes("connection") || r.includes("traffic") || r.includes("port")) {
    return `Trafic réseau anormal impliquant l'adresse ${target}.`;
  }
  if (r.includes("privilege") || r.includes("admin") || r.includes("credential")) {
    return `Activité liée à des droits d'administration ou un vol d'identifiants.`;
  }
  if (r.includes("file") || r.includes("registry")) {
    return `Modification suspecte d'un fichier ou du registre (${target}).`;
  }
  return `L'outil ${source} a signalé ce comportement comme suspect.`;
}

// ─── Composants internes ───────────────────────────────────────────────────────
function Section({ title, icon: Icon, children }: {
  title: string; icon: React.ElementType; children: React.ReactNode;
}) {
  return (
    <section className="mb-10 print-section">
      <div className="flex items-center gap-3 mb-4 pb-2 border-b-2 border-primary/30">
        <div className="h-8 w-8 rounded-lg bg-primary/15 border border-primary/30 grid place-items-center shrink-0">
          <Icon className="h-4 w-4 text-primary" />
        </div>
        <h2 className="text-base font-bold uppercase tracking-widest text-primary">{title}</h2>
      </div>
      {children}
    </section>
  );
}

function StatBox({ label, value, color }: { label: string; value: string | number; color?: string }) {
  return (
    <div className="rounded-xl border border-border bg-card p-4 text-center">
      <div className="text-2xl font-bold tabular-nums" style={color ? { color } : {}}>{value}</div>
      <div className="text-[11px] uppercase tracking-wider text-muted-foreground mt-1">{label}</div>
    </div>
  );
}

function SevBadge({ severity }: { severity: string }) {
  const sev = (severity ?? "info").toLowerCase();
  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider"
      style={{ color: SEV_COLOR[sev] ?? "#888", background: SEV_BG[sev] ?? "transparent", border: `1px solid ${SEV_COLOR[sev] ?? "#888"}44` }}
    >
      {sevLabel(sev)}
    </span>
  );
}

// ─── Page principale ───────────────────────────────────────────────────────────
function ReportsPage() {
  const { data: stats }        = useStats();
  const { data: correlationsData } = useCorrelations();
  const { data: rawAlerts }    = useAlerts();
  const { data: report } = useReport();
  const { data: iocData }      = useIOCs();
  const { data: files }        = useFilesList();
  const { data: statusData } = useAnalysisStatus();
  const { setFileFilter } = useFileSelection();
  const navigate = useNavigate();

  const alerts     = Array.isArray(rawAlerts) ? rawAlerts : [];
  const iocs       = Array.isArray(iocData)   ? iocData   : [];
  const filesList  = Array.isArray(files)     ? files     : [];
  const correlated = Array.isArray(correlationsData?.correlated_events)
    ? correlationsData.correlated_events : [];

  const tools      = [...new Set(alerts.map((a: any) => a.tool).filter(Boolean))];
  const threat     = threatLevel(alerts);
  const reportDate = now();

  // Top alertes critiques/high
  const topAlerts = alerts
    .filter((a: any) => ["critical", "high"].includes(a.severity))
    .slice(0, 20);

  // Toutes les alertes (limité à 50 pour affichage)
  const allAlerts  = alerts.slice(0, 50);

  // Compteurs par sévérité
  const sevCounts = alerts.reduce((acc: any, a: any) => {
    acc[a.severity] = (acc[a.severity] ?? 0) + 1;
    return acc;
  }, {});

  const handlePrint = () => window.print();

  return (
    <AppShell title="Rapport d'investigation" subtitle="Rapport professionnel à destination du management">
      {/* ── Barre d'actions ── */}
      <div className="flex items-center justify-between mb-6 gap-3 flex-wrap no-print">
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Shield className="h-4 w-4 text-primary" />
          <span>Rapport généré automatiquement depuis les données forensiques du dossier <strong className="text-foreground">demo</strong></span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handlePrint}
            className="inline-flex items-center gap-2 rounded-lg border border-border bg-card px-4 py-2 text-sm font-medium hover:bg-muted transition-colors"
          >
            <Printer className="h-4 w-4" /> Imprimer
          </button>
          <a
            href={`${API_URL}/cases/demo/report/pdf`}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-2 rounded-lg bg-primary text-primary-foreground px-4 py-2 text-sm font-medium hover:opacity-90 transition-opacity"
          >
            <Download className="h-4 w-4" /> Télécharger PDF <ArrowUpRight className="h-3.5 w-3.5" />
          </a>
          <a
            href={`${API_URL}/cases/demo/report`}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-2 rounded-lg border border-border bg-card px-4 py-2 text-sm font-medium hover:bg-muted transition-colors"
          >
            <FileText className="h-4 w-4" /> Export JSON
          </a>
        </div>
      </div>

      {/* ════════════════════════════════════════════════════════
          CORPS DU RAPPORT (imprimable)
          ════════════════════════════════════════════════════════ */}
      <div className="max-w-5xl mx-auto" id="report-body">

        {/* ── En-tête officiel ── */}
        <div className="rounded-2xl border border-border bg-card overflow-hidden mb-8">
          {/* Bandeau coloré */}
          <div
            className="px-8 py-5"
            style={{ background: "linear-gradient(135deg, oklch(0.20 0.04 250), oklch(0.16 0.06 220))" }}
          >
            <div className="flex items-start justify-between flex-wrap gap-4">
              <div>
                <div className="flex items-center gap-3 mb-2">
                  <div className="h-10 w-10 rounded-xl bg-primary/20 border border-primary/30 grid place-items-center">
                    <Shield className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <div className="text-xs uppercase tracking-widest text-primary font-semibold">ForensiQ</div>
                    <div className="text-[10px] text-muted-foreground">Plateforme d'analyse forensique</div>
                  </div>
                </div>
                <h1 className="text-2xl font-bold mt-3">Rapport d'Investigation Forensique</h1>
                <p className="text-sm text-muted-foreground mt-1">Dossier : <span className="text-foreground font-mono font-medium">CASE-demo</span></p>
              </div>
              <div className="text-right">
                <div
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-xl font-bold text-sm"
                  style={{ color: threat.color, background: `${threat.color}22`, border: `1px solid ${threat.color}44` }}
                >
                  <AlertTriangle className="h-4 w-4" />
                  MENACE {threat.label}
                </div>
                <div className="text-xs text-muted-foreground mt-3 space-y-1">
                  <div>Date : <span className="text-foreground font-mono">{reportDate}</span></div>
                  <div>Classification : <span className="text-[color:var(--high)] font-semibold">CONFIDENTIEL</span></div>
                </div>
              </div>
            </div>
          </div>

          {/* Méta-informations */}
          <div className="grid grid-cols-2 md:grid-cols-4 divide-x divide-y divide-border border-t border-border">
            {[
              { label: "Référence", value: "CASE-demo" },
              { label: "Outils utilisés", value: tools.length > 0 ? tools.join(", ") : "—" },
              { label: "Période d'analyse", value: alerts.length > 0 ? (String(alerts[alerts.length-1]?.timestamp ?? "").slice(0,10) || "—") : "—" },
              { label: "Niveau de confidentialité", value: "Confidentiel" },
            ].map((m) => (
              <div key={m.label} className="px-5 py-3">
                <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{m.label}</div>
                <div className="text-sm font-medium mt-0.5 truncate">{m.value}</div>
              </div>
            ))}
          </div>
        </div>

        {/* ── 1. RÉSUMÉ EXÉCUTIF ── */}
        <Section title="Résumé exécutif" icon={FileText}>
          <div className="rounded-xl border border-border bg-card/60 p-6">
            {alerts.length === 0 ? (
              <p className="text-sm text-muted-foreground italic">
                Aucune donnée disponible. Uploadez un fichier forensique pour générer ce rapport.
              </p>
            ) : (
              <div className="space-y-4 text-sm leading-relaxed">
                <p>
                  Dans le cadre de l'investigation forensique du dossier <strong>CASE-demo</strong>, une analyse
                  approfondie a été conduite à l'aide de la plateforme ForensiQ. L'analyse a porté sur{" "}
                  <strong>{filesList.length} fichier(s)</strong> soumis par l'équipe technique, générant au total{" "}
                  <strong>{stats?.alerts ?? alerts.length} alertes</strong> issues de{" "}
                  <strong>{tools.length || 1} source(s)</strong> forensique(s) différente(s)
                  {tools.length > 0 && <> ({tools.join(", ")})</>}.
                </p>
                <p>
                  L'évaluation du niveau de risque est jugée{" "}
                  <strong style={{ color: threat.color }}>{threat.label}</strong>.{" "}
                  {sevCounts["critical"] > 0 && (
                    <>
                      On dénombre <strong>{sevCounts["critical"]} alerte(s) de niveau critique</strong> nécessitant
                      une action immédiate.{" "}
                    </>
                  )}
                  {sevCounts["high"] > 0 && (
                    <>
                      <strong>{sevCounts["high"]} alerte(s) de niveau élevé</strong> ont également été identifiées.{" "}
                    </>
                  )}
                  {(stats?.iocs ?? 0) > 0 && (
                    <>
                      Au total, <strong>{stats?.iocs} indicateur(s) de compromission (IOC)</strong> ont été extraits
                      et documentés.{" "}
                    </>
                  )}
                  {correlated.length > 0 && (
                    <>
                      <strong>{correlated.length} corrélation(s) host/réseau</strong> ont été détectées, suggérant
                      une chaîne d'attaque coordonnée.
                    </>
                  )}
                </p>
                <p className="border-l-2 border-primary/50 pl-4 text-muted-foreground italic">
                  Ce rapport est destiné à la direction et aux équipes de sécurité. Les conclusions présentées
                  reposent exclusivement sur les artefacts forensiques analysés et les règles de détection appliquées.
                </p>
              </div>
            )}
          </div>
        </Section>

        {/* ── 2. INDICATEURS CLÉS ── */}
        <Section title="Indicateurs clés" icon={Cpu}>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
            <StatBox label="Fichiers analysés"  value={stats?.files_analyzed ?? filesList.length} />
            <StatBox label="Alertes totales"    value={stats?.alerts ?? alerts.length} color={threat.color} />
            <StatBox label="IOCs détectés"      value={stats?.iocs ?? iocs.length}     color="#f97316" />
            <StatBox label="Corrélations"       value={correlated.length}              color="#a78bfa" />
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { label: "Critique", key: "critical", color: "#dc2626" },
              { label: "Élevé",    key: "high",     color: "#f97316" },
              { label: "Moyen",    key: "medium",   color: "#eab308" },
              { label: "Faible",   key: "low",      color: "#22c55e" },
            ].map((s) => (
              <div
                key={s.key}
                className="rounded-xl border p-4 flex items-center gap-3"
                style={{ borderColor: `${s.color}33`, background: `${s.color}0d` }}
              >
                <div className="h-3 w-3 rounded-full shrink-0" style={{ background: s.color }} />
                <div>
                  <div className="text-lg font-bold tabular-nums" style={{ color: s.color }}>
                    {sevCounts[s.key] ?? 0}
                  </div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">{s.label}</div>
                </div>
              </div>
            ))}
          </div>
        </Section>

        {/* ── 3. FICHIERS ANALYSÉS ── */}
        {filesList.length > 0 && (
          <Section title="Fichiers analysés" icon={FileWarning}>
            <div className="rounded-xl border border-border overflow-hidden">
              <table className="w-full text-sm">
                <thead className="bg-muted/40 text-xs uppercase text-muted-foreground">
                  <tr>
                    <th className="text-left px-4 py-3">Nom du fichier</th>
                    <th className="text-left px-4 py-3">Outil détecté</th>
                    <th className="text-left px-4 py-3">Alertes extraites</th>
                    <th className="text-left px-4 py-3">Statut</th>
                    <th className="text-left px-4 py-3">Date d'import</th>
                    <th className="text-right px-4 py-3 no-print">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {filesList.map((f: any, i: number) => (
                    <tr key={i} className="hover:bg-muted/20">
                      <td className="px-4 py-3 font-mono text-xs font-medium">{f.filename}</td>
                      <td className="px-4 py-3">
                        <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-primary/10 text-primary border border-primary/20">
                          {(f.tool ?? "unknown").toUpperCase()}
                        </span>
                      </td>
                      <td className="px-4 py-3 tabular-nums font-semibold">{f.alert_count ?? 0}</td>
                      <td className="px-4 py-3">
                        {f.status === "parsed" ? (
                          <span className="flex items-center gap-1 text-[color:var(--success)] text-xs">
                            <CheckCircle2 className="h-3 w-3" /> Analysé
                          </span>
                        ) : f.status === "error" ? (
                          <span className="flex items-center gap-1 text-destructive text-xs">
                            <XCircle className="h-3 w-3" /> Erreur
                          </span>
                        ) : (
                          <span className="text-xs text-muted-foreground">{f.status}</span>
                        )}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-muted-foreground">
                        {String(f.uploaded_at ?? "").slice(0, 19)}
                      </td>
                      <td className="px-4 py-3 text-right no-print flex items-center justify-end gap-2">
                        {f.status === "parsed" && (
                          <button
                            onClick={() => {
                              setFileFilter(f.id, f.filename);
                              navigate({ to: "/" });
                            }}
                            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 border border-primary/20 hover:bg-primary/10 text-primary text-xs font-medium rounded transition-colors"
                            title="Filtrer le dashboard pour ce fichier"
                          >
                            <Filter className="h-3.5 w-3.5" />
                          </button>
                        )}
                        <a
                          href={`${API_URL}/cases/demo/files/${f.id}/report/pdf`}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-primary/10 hover:bg-primary/20 text-primary text-xs font-medium rounded transition-colors"
                          title="Télécharger le rapport détaillé de ce fichier"
                        >
                          <Download className="h-3.5 w-3.5" /> PDF
                        </a>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Section>
        )}

        {/* ── 4. ALERTES CRITIQUES ET ÉLEVÉES ── */}
        {topAlerts.length > 0 && (
          <Section title="Alertes critiques et élevées" icon={AlertTriangle}>
            <div className="rounded-xl border border-border overflow-hidden">
              <table className="w-full text-sm">
                <thead className="bg-muted/40 text-xs uppercase text-muted-foreground">
                  <tr>
                    <th className="text-left px-4 py-3 w-8">#</th>
                    <th className="text-left px-4 py-3">Sévérité</th>
                    <th className="text-left px-4 py-3">Source</th>
                    <th className="text-left px-4 py-3">Règle & Cible</th>
                    
                    <th className="text-left px-4 py-3">Horodatage</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {topAlerts.map((a: any, i: number) => (
                    <tr key={i} className="hover:bg-muted/20 transition-colors">
                      <td className="px-4 py-3 text-xs text-muted-foreground tabular-nums">{i + 1}</td>
                      <td className="px-4 py-3"><SevBadge severity={a.severity} /></td>
                      <td className="px-4 py-3">
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-muted border border-border">
                          {(a.tool ?? "?").toUpperCase()}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-medium max-w-xs">
                        <div className="truncate">{a.title ?? "—"}</div>
                        {a.mitre_attack && (
                          <div className="text-[10px] text-muted-foreground font-mono mt-0.5">{a.mitre_attack}</div>
                        )}
                        <div className="text-xs text-muted-foreground font-mono mt-1 truncate max-w-xs" title={a.target ?? a.dst_ip}>
                          Cible: {a.target ?? a.dst_ip ?? "—"}
                        </div>
                      </td>
                      
                      <td className="px-4 py-3 font-mono text-xs text-muted-foreground tabular-nums">
                        {String(a.timestamp ?? "—").slice(0, 19)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {alerts.filter((a: any) => ["critical","high"].includes(a.severity)).length > 20 && (
              <p className="text-xs text-muted-foreground mt-2 text-center">
                … et {alerts.filter((a: any) => ["critical","high"].includes(a.severity)).length - 20} alerte(s) supplémentaire(s). Consultez la page Alertes pour la liste complète.
              </p>
            )}
          </Section>
        )}

        {/* ── 5. TOUTES LES ALERTES ── */}
        {allAlerts.length > 0 && (
          <Section title="Journal complet des alertes" icon={Shield}>
            <div className="rounded-xl border border-border overflow-hidden">
              <table className="w-full text-sm">
                <thead className="bg-muted/40 text-xs uppercase text-muted-foreground">
                  <tr>
                    <th className="text-left px-4 py-3">Sévérité</th>
                    <th className="text-left px-4 py-3">Source</th>
                    <th className="text-left px-4 py-3">Titre</th>
                    <th className="text-left px-4 py-3">Cible</th>
                    <th className="text-left px-4 py-3">Horodatage</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {allAlerts.map((a: any, i: number) => (
                    <tr key={i} className="hover:bg-muted/20 transition-colors">
                      <td className="px-4 py-2"><SevBadge severity={a.severity} /></td>
                      <td className="px-4 py-2">
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-muted border border-border">
                          {(a.tool ?? "?").toUpperCase()}
                        </span>
                      </td>
                      <td className="px-4 py-2 font-medium text-xs max-w-xs">
                        <div className="truncate">{a.title ?? "—"}</div>
                      </td>
                      <td className="px-4 py-2 font-mono text-xs text-muted-foreground max-w-xs">
                        <div className="truncate">{a.target ?? a.dst_ip ?? "—"}</div>
                      </td>
                      <td className="px-4 py-2 font-mono text-xs text-muted-foreground">
                        {String(a.timestamp ?? "—").slice(0, 19)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {alerts.length > 50 && (
              <p className="text-xs text-muted-foreground mt-2 text-center">
                Affichage des 50 premières alertes sur {alerts.length} au total.
              </p>
            )}
          </Section>
        )}

        {/* ── 6. INDICATEURS DE COMPROMISSION (IOCs) ── */}
        {iocs.length > 0 && (
          <Section title="Indicateurs de compromission (IOCs)" icon={Fingerprint}>
            <div className="rounded-xl border border-border overflow-hidden">
              <table className="w-full text-sm">
                <thead className="bg-muted/40 text-xs uppercase text-muted-foreground">
                  <tr>
                    <th className="text-left px-4 py-3">Type</th>
                    <th className="text-left px-4 py-3">Valeur</th>
                    <th className="text-left px-4 py-3">Source</th>
                    <th className="text-left px-4 py-3">Occurrences</th>
                    <th className="text-left px-4 py-3">1ère détection</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {iocs.slice(0, 30).map((ioc: any, i: number) => (
                    <tr key={i} className="hover:bg-muted/20 transition-colors">
                      <td className="px-4 py-3">
                        <span className="text-[10px] uppercase tracking-wider px-2 py-0.5 rounded border border-border bg-muted">
                          {ioc.type}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs max-w-xs truncate">{ioc.value}</td>
                      <td className="px-4 py-3">
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-muted border border-border">
                          {(ioc.source ?? "?").toUpperCase()}
                        </span>
                      </td>
                      <td className="px-4 py-3 tabular-nums font-semibold">{ioc.hits}</td>
                      <td className="px-4 py-3 font-mono text-xs text-muted-foreground">
                        {String(ioc.firstSeen ?? "—").slice(0, 19)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Section>
        )}

        {/* ── 7. CORRÉLATIONS HOST / RÉSEAU ── */}
        {correlated.length > 0 && (
          <Section title="Corrélations host / réseau" icon={Network}>
            <div className="space-y-3">
              {correlated.map((c: any, i: number) => (
                <div key={i} className="rounded-xl border border-[#dc262633] bg-[#dc26260a] p-5">
                  <div className="flex items-start gap-3">
                    <div className="h-8 w-8 rounded-lg bg-[#dc2626]/15 border border-[#dc2626]/30 grid place-items-center shrink-0 mt-0.5">
                      <Network className="h-4 w-4 text-[#dc2626]" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap mb-1">
                        <span className="text-xs font-mono text-muted-foreground">
                          CORR-{String(i + 1).padStart(2, "0")}
                        </span>
                        <SevBadge severity={c.risk ?? "critical"} />
                      </div>
                      <div className="font-semibold text-sm mb-1">{c.host_event}</div>
                      <div className="text-xs text-muted-foreground">
                        <span className="mr-2">Fenêtre temporelle :</span>
                        <code className="font-mono bg-muted px-1 rounded">{c.time_window}</code>
                      </div>
                      {c.network_events?.length > 0 && (
                        <div className="mt-2 flex items-center gap-1 flex-wrap">
                          <span className="text-[10px] text-muted-foreground mr-1">Événements réseau corrélés :</span>
                          {c.network_events.slice(0, 3).map((ne: string, ni: number) => (
                            <span key={ni} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-muted border border-border">
                              {ne}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </Section>
        )}

        {/* ── 8. RECOMMANDATIONS ── */}
        <Section title="Recommandations" icon={CheckCircle2}>
          <div className="space-y-3">
            {[
              {
                priority: "IMMÉDIAT",
                color: "#dc2626",
                show: alerts.some((a: any) => a.severity === "critical"),
                items: [
                  "Isoler immédiatement le(s) système(s) compromis du réseau de production.",
                  "Révoquer et réinitialiser tous les comptes d'utilisateurs potentiellement compromis.",
                  "Activer le plan de réponse aux incidents et notifier l'équipe CSIRT.",
                ],
              },
              {
                priority: "COURT TERME (< 48h)",
                color: "#f97316",
                show: true,
                items: [
                  iocs.filter((i: any) => i.type === "IP").length > 0
                    ? `Bloquer les ${iocs.filter((i: any) => i.type === "IP").length} adresse(s) IP malveillante(s) identifiées sur le pare-feu et les équipements réseau.`
                    : "Mettre à jour les règles de filtrage réseau.",
                  "Effectuer une analyse approfondie des autres postes du même segment réseau pour détecter une éventuelle propagation latérale.",
                  "Collecter et conserver toutes les preuves numériques (images disque, logs) pour l'investigation judiciaire.",
                ],
              },
              {
                priority: "MOYEN TERME (< 2 semaines)",
                color: "#eab308",
                show: true,
                items: [
                  "Restaurer les systèmes compromis à partir de sauvegardes vérifiées et saines.",
                  "Mettre à jour et renforcer les politiques de sécurité (MFA, privilèges minimaux).",
                  "Déployer des règles de détection supplémentaires basées sur les IOCs identifiés dans ce rapport.",
                  "Planifier une revue complète des journaux d'accès pour la période concernée.",
                ],
              },
              {
                priority: "LONG TERME",
                color: "#22c55e",
                show: true,
                items: [
                  "Renforcer la formation des équipes aux bonnes pratiques de sécurité.",
                  "Implémenter une solution SIEM/SOAR pour une détection continue des menaces.",
                  "Effectuer des tests d'intrusion réguliers pour identifier les faiblesses résiduelles.",
                ],
              },
            ]
              .filter((r) => r.show)
              .map((r) => (
                <div
                  key={r.priority}
                  className="rounded-xl border p-5"
                  style={{ borderColor: `${r.color}33`, background: `${r.color}08` }}
                >
                  <div
                    className="text-[11px] font-bold uppercase tracking-widest mb-3 flex items-center gap-2"
                    style={{ color: r.color }}
                  >
                    <div className="h-1.5 w-1.5 rounded-full" style={{ background: r.color }} />
                    {r.priority}
                  </div>
                  <ul className="space-y-2">
                    {r.items.map((item, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm">
                        <ChevronRight className="h-4 w-4 shrink-0 mt-0.5" style={{ color: r.color }} />
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
          </div>
        </Section>

        {/* ── 9. CONCLUSION ── */}
        <Section title="Conclusion" icon={Globe}>
          <div className="rounded-xl border border-border bg-card/60 p-6 text-sm leading-relaxed space-y-3">
            <p>
              Cette investigation forensique a permis d'identifier et de documenter les menaces présentes
              dans le système analysé. Le niveau de risque global est évalué à{" "}
              <strong style={{ color: threat.color }}>{threat.label}</strong> sur la base des{" "}
              {stats?.alerts ?? alerts.length} alertes générées.
            </p>
            <p>
              Les recommandations formulées dans ce rapport doivent être mises en œuvre dans les délais indiqués
              afin de contenir la menace et de rétablir la sécurité opérationnelle. Une surveillance continue
              est préconisée dans les semaines suivant cet incident.
            </p>
            <p className="text-muted-foreground text-xs border-t border-border pt-3 mt-3">
              Ce rapport a été généré automatiquement par la plateforme ForensiQ le {reportDate}.
              Les résultats présentés sont basés sur l'analyse des artefacts fournis et ne constituent pas
              un avis juridique. Pour toute question, contactez l'équipe de cybersécurité.
            </p>
          </div>
        </Section>

        {/* ── Pied de page ── */}
        <div className="border-t border-border pt-6 pb-4 flex items-center justify-between text-xs text-muted-foreground">
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-primary" />
            <span>ForensiQ — Plateforme d'analyse forensique</span>
          </div>
          <div>Rapport généré le {reportDate} · CASE-demo · CONFIDENTIEL</div>
        </div>
      </div>

      {/* ── Styles d'impression ── */}
      <style>{`
        @media print {
          .no-print { display: none !important; }
          aside, header { display: none !important; }
          main { padding: 0 !important; }
          body { background: white !important; color: black !important; }
          .print-section { break-inside: avoid; }
          #report-body { max-width: 100% !important; }
        }
      `}</style>
    </AppShell>
  );
}
