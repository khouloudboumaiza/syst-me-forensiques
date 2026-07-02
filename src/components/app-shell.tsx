import { Link, useRouterState } from "@tanstack/react-router";
import type { ReactNode } from "react";
import {
  LayoutDashboard,
  ShieldAlert,
  Fingerprint,
  Clock3,
  Files,
  Network,
  FileText,
  Upload,
  Search,
  Bell,
  CircleUser,
  Wifi,
  WifiOff,
  Activity,
} from "lucide-react";
import { useBackendStatus, useFilesList } from "@/hooks/useCaseData";

const nav = [
  { to: "/", label: "Overview", icon: LayoutDashboard },
  { to: "/alerts", label: "Alertes", icon: ShieldAlert },
  { to: "/iocs", label: "IOCs", icon: Fingerprint },
  { to: "/timeline", label: "Timeline", icon: Clock3 },
  { to: "/artifacts", label: "Artefacts", icon: Files },
  { to: "/correlations", label: "Corrélations", icon: Network },
  { to: "/reports", label: "Rapports", icon: FileText },
  { to: "/upload", label: "Import", icon: Upload },
] as const;

export function AppShell({ children, title, subtitle }: { children: ReactNode; title: string; subtitle?: string }) {
  const pathname = useRouterState({ select: (s) => s.location.pathname });

  const { data: backendData, isError: backendDown } = useBackendStatus();
  const { data: files } = useFilesList();

  // Vrai si au moins un fichier est en cours d'analyse
  const filesArray = Array.isArray(files) ? files : [];
  const analysisInProgress = filesArray.some((f: any) => f.status === "processing");

  const backendOnline = !backendDown && backendData;

  return (
    <div className="flex min-h-screen bg-background text-foreground">
      {/* Sidebar */}
      <aside className="hidden md:flex w-64 flex-col border-r border-sidebar-border bg-sidebar">
        <div className="px-5 py-5 border-b border-sidebar-border">
          <div className="flex items-center gap-2">
            <div className="h-8 w-8 rounded-md bg-primary/15 border border-primary/30 grid place-items-center">
              <ShieldAlert className="h-4 w-4 text-primary" />
            </div>
            <div>
              <div className="text-sm font-semibold tracking-tight text-sidebar-foreground">ForensiQ</div>
              <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Post-Analysis</div>
            </div>
          </div>
        </div>

        <nav className="flex-1 px-3 py-4 space-y-1">
          {nav.map(({ to, label, icon: Icon }) => {
            const active = pathname === to;
            return (
              <Link
                key={to}
                to={to}
                className={`flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
                  active
                    ? "bg-sidebar-accent text-sidebar-accent-foreground border-l-2 border-primary"
                    : "text-sidebar-foreground/80 hover:bg-sidebar-accent/50 hover:text-sidebar-foreground"
                }`}
              >
                <Icon className="h-4 w-4" />
                <span>{label}</span>
              </Link>
            );
          })}
        </nav>

        {/* Backend status + case info */}
        <div className="p-4 border-t border-sidebar-border space-y-3">
          {/* Indicateur backend */}
          <div className="flex items-center gap-2 text-xs">
            {backendOnline ? (
              <>
                <Wifi className="h-3.5 w-3.5 text-[color:var(--success)]" />
                <span className="text-[color:var(--success)]">Backend connecté</span>
              </>
            ) : (
              <>
                <WifiOff className="h-3.5 w-3.5 text-destructive" />
                <span className="text-destructive">Backend hors-ligne</span>
              </>
            )}
          </div>

          {/* Analyse en cours */}
          {analysisInProgress && (
            <div className="flex items-center gap-2 text-xs text-[color:var(--medium)] animate-pulse">
              <Activity className="h-3.5 w-3.5" />
              <span>Analyse en cours…</span>
            </div>
          )}

          <div className="rounded-md bg-sidebar-accent/60 p-3">
            <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Dossier actif</div>
            <div className="text-sm font-medium mt-1 text-sidebar-foreground">CASE-demo</div>
            <div className="text-xs text-muted-foreground mt-0.5 truncate">Investigation active</div>
          </div>
        </div>
      </aside>

      {/* Main */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Bandeau d'analyse en cours */}
        {analysisInProgress && (
          <div className="bg-[color:var(--medium)]/10 border-b border-[color:var(--medium)]/30 px-6 py-2 flex items-center gap-3">
            <Activity className="h-4 w-4 text-[color:var(--medium)] animate-pulse shrink-0" />
            <span className="text-sm text-[color:var(--medium)] font-medium">
              Analyse en cours — le dashboard se met à jour automatiquement dès que les résultats arrivent
            </span>
            <span className="ml-auto flex gap-1">
              {[0, 1, 2].map((i) => (
                <span
                  key={i}
                  className="h-1.5 w-1.5 rounded-full bg-[color:var(--medium)] animate-bounce"
                  style={{ animationDelay: `${i * 0.15}s` }}
                />
              ))}
            </span>
          </div>
        )}

        {/* Backend hors-ligne */}
        {!backendOnline && !analysisInProgress && (
          <div className="bg-destructive/10 border-b border-destructive/30 px-6 py-2 flex items-center gap-3">
            <WifiOff className="h-4 w-4 text-destructive shrink-0" />
            <span className="text-sm text-destructive">
              Backend non joignable sur <code className="font-mono text-xs">localhost:8000</code> — lancez{" "}
              <code className="font-mono text-xs">uvicorn main:app --reload --port 8000</code> dans le dossier{" "}
              <code className="font-mono text-xs">backend/</code>
            </span>
          </div>
        )}

        <header className="h-16 border-b border-border bg-card/40 backdrop-blur flex items-center justify-between px-6">
          <div>
            <h1 className="text-lg font-semibold tracking-tight">{title}</h1>
            {subtitle && <p className="text-xs text-muted-foreground mt-0.5">{subtitle}</p>}
          </div>
          <div className="flex items-center gap-3">
            <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-md bg-muted border border-border w-72">
              <Search className="h-3.5 w-3.5 text-muted-foreground" />
              <input
                placeholder="Rechercher IOC, hash, fichier…"
                className="bg-transparent text-sm outline-none flex-1 placeholder:text-muted-foreground"
              />
            </div>
            <button className="relative h-9 w-9 grid place-items-center rounded-md border border-border hover:bg-muted">
              <Bell className="h-4 w-4" />
              <span className="absolute top-1.5 right-1.5 h-2 w-2 rounded-full bg-destructive" />
            </button>
            <div className="flex items-center gap-2 pl-3 border-l border-border">
              <CircleUser className="h-6 w-6 text-muted-foreground" />
              <div className="text-xs">
                <div className="font-medium">Analyste</div>
                <div className="text-muted-foreground">Forensique</div>
              </div>
            </div>
          </div>
        </header>
        <main className="flex-1 p-6 overflow-x-hidden">{children}</main>
      </div>
    </div>
  );
}

export function SeverityBadge({ severity }: { severity: "critical" | "high" | "medium" | "low" | "info" }) {
  const map: Record<string, string> = {
    critical: "bg-[color:var(--critical)]/15 text-[color:var(--critical)] border-[color:var(--critical)]/30",
    high: "bg-[color:var(--high)]/15 text-[color:var(--high)] border-[color:var(--high)]/30",
    medium: "bg-[color:var(--medium)]/15 text-[color:var(--medium)] border-[color:var(--medium)]/30",
    low: "bg-[color:var(--low)]/15 text-[color:var(--low)] border-[color:var(--low)]/30",
    info: "bg-[color:var(--info)]/15 text-[color:var(--info)] border-[color:var(--info)]/30",
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider border ${map[severity] ?? map.info}`}>
      {severity}
    </span>
  );
}

export function ToolBadge({ tool }: { tool: string }) {
  const normalizedTool = (tool ?? "").toLowerCase();
  const map: Record<string, string> = {
    loki: "bg-purple-500/15 text-purple-300 border-purple-500/30",
    hayabusa: "bg-sky-500/15 text-sky-300 border-sky-500/30",
    autopsy: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
    kuiper: "bg-amber-500/15 text-amber-300 border-amber-500/30",
    "ml-network": "bg-rose-500/15 text-rose-300 border-rose-500/30",
    "ml network": "bg-rose-500/15 text-rose-300 border-rose-500/30",
    unknown: "bg-muted text-muted-foreground border-border",
  };
  const style = map[normalizedTool] ?? "bg-muted text-muted-foreground border-border";
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium border ${style}`}>
      {tool}
    </span>
  );
}

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div className={`rounded-lg border border-border bg-card ${className}`}>
      {children}
    </div>
  );
}
