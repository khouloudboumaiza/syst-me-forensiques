import { createFileRoute } from "@tanstack/react-router";
import { AppShell, Card, SeverityBadge, ToolBadge } from "@/components/app-shell";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  AreaChart,
  Area,
  CartesianGrid,
} from "recharts";
import { Files, ShieldAlert, Fingerprint, Boxes, TrendingUp, ArrowUpRight, Loader2 } from "lucide-react";
import {
  useStats,
  useAlerts,
  useSeverityDistribution,
  useToolDistribution,
  useCorrelations,
} from "@/hooks/useCaseData";
import { API_URL } from "@/lib/api";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "ForensiQ — Dashboard d'analyse forensique" },
      {
        name: "description",
        content:
          "Plateforme de post-traitement forensique : parsing, corrélation et rapports pour Loki, Hayabusa et analyse réseau ML.",
      },
    ],
  }),
  component: Overview,
});

const SEVERITY_COLORS: Record<string, string> = {
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
  low: "var(--success)",
};

function Kpi({
  label,
  value,
  icon: Icon,
  trend,
  tone = "primary",
}: {
  label: string;
  value: string | number;
  icon: React.ElementType;
  trend?: string;
  tone?: "primary" | "critical" | "high" | "medium";
}) {
  const toneMap: Record<string, string> = {
    primary: "text-primary bg-primary/10 border-primary/20",
    critical: "text-[color:var(--critical)] bg-[color:var(--critical)]/10 border-[color:var(--critical)]/20",
    high: "text-[color:var(--high)] bg-[color:var(--high)]/10 border-[color:var(--high)]/20",
    medium: "text-[color:var(--medium)] bg-[color:var(--medium)]/10 border-[color:var(--medium)]/20",
  };
  return (
    <Card className="p-4">
      <div className="flex items-start justify-between">
        <div>
          <div className="text-xs text-muted-foreground uppercase tracking-wider">{label}</div>
          <div className="text-2xl font-semibold mt-2 tabular-nums">{value}</div>
          {trend && (
            <div className="flex items-center gap-1 mt-1 text-xs text-[color:var(--success)]">
              <TrendingUp className="h-3 w-3" /> {trend}
            </div>
          )}
        </div>
        <div className={`h-9 w-9 rounded-md grid place-items-center border ${toneMap[tone]}`}>
          <Icon className="h-4 w-4" />
        </div>
      </div>
    </Card>
  );
}

// Regroupe les alertes par heure pour construire le graphique d'activité,
// faute d'endpoint /timeline dédié côté backend pour l'instant.
function buildTimeline(rawAlerts: any[]) {
  const buckets: Record<string, number> = {};
  for (const a of rawAlerts) {
    const ts = a.timestamp ?? "";
    const hour = String(ts).slice(11, 16) || "??:??"; // "HH:MM"
    buckets[hour] = (buckets[hour] || 0) + 1;
  }
  return Object.entries(buckets)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([time, events]) => ({ time, events }));
}

function Overview() {
  const { data: stats, isLoading: statsLoading } = useStats();
  const { data: rawAlerts, isLoading: alertsLoading } = useAlerts();
  const { data: severityDistribution } = useSeverityDistribution();
  const { data: toolDistribution } = useToolDistribution();
  const { data: correlations } = useCorrelations();

  const alerts = Array.isArray(rawAlerts) ? rawAlerts : [];
  const timelineActivity = buildTimeline(alerts);

  const isLoading = statsLoading || alertsLoading;

  return (
    <AppShell title="Vue d'ensemble" subtitle={`Dossier : demo`}>
      {/* Case header banner */}
      <Card className="p-5 mb-6 relative overflow-hidden">
        <div
          className="absolute inset-0 opacity-40 pointer-events-none"
          style={{
            background:
              "radial-gradient(600px 200px at 10% 0%, color-mix(in oklab, var(--primary) 25%, transparent), transparent)",
          }}
        />
        <div className="relative flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <span className="h-1.5 w-1.5 rounded-full bg-[color:var(--high)] animate-pulse" />
              {isLoading ? "Chargement…" : "Investigation en cours"}
            </div>
            <h2 className="text-xl font-semibold mt-1">Dossier demo</h2>
            <p className="text-sm text-muted-foreground mt-1 max-w-2xl">
              {correlations?.correlated_events?.length
                ? `${correlations.correlated_events.length} corrélation(s) host/réseau détectée(s).`
                : "En attente de corrélations entre événements host et réseau."}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <div className="text-right">
              <div className="text-[10px] uppercase tracking-widest text-muted-foreground">
                Score de risque combiné
              </div>
              <div className="text-lg font-semibold text-[color:var(--high)]">
                {correlations?.combined_risk_score ?? "—"}
              </div>
            </div>
            <a
              href={`${API_URL}/cases/demo/report`}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 rounded-md bg-primary text-primary-foreground px-3 py-2 text-sm font-medium hover:opacity-90"
            >
              Générer rapport <ArrowUpRight className="h-3.5 w-3.5" />
            </a>
          </div>
        </div>
      </Card>

      {/* KPIs */}
      {isLoading ? (
        <div className="flex items-center gap-2 text-sm text-muted-foreground mb-6">
          <Loader2 className="h-4 w-4 animate-spin" /> Chargement des statistiques…
        </div>
      ) : (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 mb-6">
          <Kpi label="Fichiers analysés" value={stats?.files_analyzed ?? 0} icon={Files} />
          <Kpi label="Alertes" value={stats?.alerts ?? alerts.length} icon={ShieldAlert} tone="high" />
          <Kpi label="IOCs" value={stats?.iocs ?? 0} icon={Fingerprint} tone="critical" />
          <Kpi label="Artefacts" value={stats?.artifacts ?? 0} icon={Boxes} />
          <Kpi
            label="Corrélations"
            value={correlations?.correlated_events?.length ?? 0}
            icon={TrendingUp}
            tone="medium"
          />
          <Kpi label="Sources" value={stats?.sources ?? 0} icon={Boxes} />
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
        {/* Activity chart */}
        <Card className="lg:col-span-2 p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold">Activité d'événements</h3>
              <p className="text-xs text-muted-foreground">Volume d'alertes par horodatage</p>
            </div>
          </div>
          <div className="h-64">
            {timelineActivity.length === 0 ? (
              <div className="h-full grid place-items-center text-sm text-muted-foreground">
                Pas encore de données — uploadez un fichier.
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timelineActivity}>
                  <defs>
                    <linearGradient id="g1" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="var(--primary)" stopOpacity={0.5} />
                      <stop offset="100%" stopColor="var(--primary)" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                  <XAxis dataKey="time" stroke="var(--muted-foreground)" fontSize={11} />
                  <YAxis stroke="var(--muted-foreground)" fontSize={11} />
                  <Tooltip
                    contentStyle={{
                      background: "var(--popover)",
                      border: "1px solid var(--border)",
                      borderRadius: 8,
                      fontSize: 12,
                    }}
                  />
                  <Area type="monotone" dataKey="events" stroke="var(--primary)" strokeWidth={2} fill="url(#g1)" />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>

        {/* Severity pie */}
        <Card className="p-5">
          <h3 className="text-sm font-semibold mb-1">Répartition par sévérité</h3>
          <p className="text-xs text-muted-foreground mb-3">Toutes sources confondues</p>
          <div className="h-48">
            {!severityDistribution || severityDistribution.length === 0 ? (
              <div className="h-full grid place-items-center text-sm text-muted-foreground">Aucune donnée</div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityDistribution}
                    dataKey="count"
                    nameKey="level"
                    innerRadius={45}
                    outerRadius={75}
                    paddingAngle={2}
                  >
                    {severityDistribution.map((e: any, i: number) => (
                      <Cell key={i} fill={e.color ?? SEVERITY_COLORS[e.level] ?? "var(--primary)"} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      background: "var(--popover)",
                      border: "1px solid var(--border)",
                      borderRadius: 8,
                      fontSize: 12,
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
          <div className="grid grid-cols-2 gap-2 mt-3">
            {(severityDistribution ?? []).map((s: any) => (
              <div key={s.level} className="flex items-center gap-2 text-xs">
                <span
                  className="h-2 w-2 rounded-sm"
                  style={{ background: s.color ?? SEVERITY_COLORS[s.level] }}
                />
                <span className="text-muted-foreground">{s.level}</span>
                <span className="ml-auto font-medium tabular-nums">{s.count}</span>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Tool distribution */}
        <Card className="lg:col-span-1 p-5">
          <h3 className="text-sm font-semibold mb-1">Par outil forensique</h3>
          <p className="text-xs text-muted-foreground mb-3">Alertes générées par source</p>
          <div className="h-56">
            {!toolDistribution || toolDistribution.length === 0 ? (
              <div className="h-full grid place-items-center text-sm text-muted-foreground">Aucune donnée</div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={toolDistribution} layout="vertical" margin={{ left: 10 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" horizontal={false} />
                  <XAxis type="number" stroke="var(--muted-foreground)" fontSize={11} />
                  <YAxis dataKey="tool" type="category" stroke="var(--muted-foreground)" fontSize={11} width={70} />
                  <Tooltip
                    contentStyle={{
                      background: "var(--popover)",
                      border: "1px solid var(--border)",
                      borderRadius: 8,
                      fontSize: 12,
                    }}
                  />
                  <Bar dataKey="alerts" fill="var(--primary)" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>

        {/* Recent alerts */}
        <Card className="lg:col-span-2">
          <div className="p-5 border-b border-border flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold">Alertes récentes</h3>
              <p className="text-xs text-muted-foreground">Dernières détections</p>
            </div>
            <a href="/alerts" className="text-xs text-primary hover:underline">
              Tout voir →
            </a>
          </div>
          <div className="divide-y divide-border">
            {alerts.length === 0 && (
              <div className="px-5 py-6 text-sm text-muted-foreground">Aucune alerte pour l'instant.</div>
            )}
            {alerts.slice(0, 5).map((a: any, i: number) => (
              <div key={a.id ?? i} className="px-5 py-3 hover:bg-muted/30 transition-colors flex items-center gap-4">
                <SeverityBadge severity={(a.severity ?? "medium").toLowerCase()} />
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-medium truncate">{a.title ?? a.rule ?? "Alerte"}</div>
                  <div className="text-xs text-muted-foreground truncate font-mono">
                    {a.target ?? a.dst_ip ?? ""}
                  </div>
                </div>
                <ToolBadge tool={a.tool ?? a.source ?? "unknown"} />
                <div className="text-xs text-muted-foreground tabular-nums hidden md:block">
                  {String(a.timestamp ?? "").split(" ")[1] ?? ""}
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </AppShell>
  );
}
