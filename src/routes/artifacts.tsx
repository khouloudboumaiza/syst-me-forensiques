import { createFileRoute } from "@tanstack/react-router";
import { AppShell, Card, ToolBadge } from "@/components/app-shell";
import { FileIcon, Loader2, AlertTriangle } from "lucide-react";
import { useArtifacts } from "@/hooks/useCaseData";

export const Route = createFileRoute("/artifacts")({
  head: () => ({ meta: [{ title: "Artefacts — ForensiQ" }] }),
  component: ArtifactsPage,
});

const tagColor: Record<string, string> = {
  malware: "bg-[color:var(--critical)]/15 text-[color:var(--critical)] border-[color:var(--critical)]/30",
  suspicious: "bg-[color:var(--high)]/15 text-[color:var(--high)] border-[color:var(--high)]/30",
  "ransom-note": "bg-[color:var(--critical)]/15 text-[color:var(--critical)] border-[color:var(--critical)]/30",
  log: "bg-[color:var(--info)]/15 text-[color:var(--info)] border-[color:var(--info)]/30",
  image: "bg-muted text-muted-foreground border-border",
};

function ArtifactsPage() {
  const { data: artifacts, isLoading, isError } = useArtifacts();
  const artifactList = Array.isArray(artifacts) ? artifacts : [];

  return (
    <AppShell
      title="Artefacts"
      subtitle={
        isLoading
          ? "Chargement…"
          : `${artifactList.length} artefact(s) extrait(s) des sources forensiques`
      }
    >
      <Card>
        {isLoading && (
          <div className="flex items-center justify-center gap-2 py-12 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" /> Chargement des artefacts…
          </div>
        )}

        {isError && (
          <div className="flex items-center justify-center gap-2 py-12 text-sm text-destructive">
            <AlertTriangle className="h-4 w-4" /> Impossible de contacter le backend (localhost:8000).
          </div>
        )}

        {!isLoading && !isError && artifactList.length === 0 && (
          <div className="py-12 text-center text-sm text-muted-foreground">
            Aucun artefact pour l'instant. Uploadez un fichier Loki ou Hayabusa depuis la page Import.
          </div>
        )}

        {!isLoading && !isError && artifactList.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-xs uppercase text-muted-foreground border-b border-border">
                <tr>
                  <th className="text-left px-4 py-3">Nom</th>
                  <th className="text-left px-4 py-3">Chemin</th>
                  <th className="text-left px-4 py-3">Hash / MITRE</th>
                  <th className="text-left px-4 py-3">Source</th>
                  <th className="text-left px-4 py-3">Horodatage</th>
                  <th className="text-left px-4 py-3">Tag</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {artifactList.map((a: any, i: number) => (
                  <tr key={i} className="hover:bg-muted/30 transition-colors">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <FileIcon className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                        <span className="font-medium truncate max-w-xs">{a.name}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-muted-foreground truncate max-w-xs">{a.path}</td>
                    <td className="px-4 py-3 font-mono text-xs text-muted-foreground truncate max-w-xs">{a.hash}</td>
                    <td className="px-4 py-3">
                      <ToolBadge tool={a.source} />
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-muted-foreground">
                      {String(a.timestamp ?? "—").slice(0, 19)}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`text-[10px] uppercase tracking-wider px-2 py-0.5 rounded border ${tagColor[a.tag] ?? "bg-muted text-muted-foreground border-border"}`}
                      >
                        {a.tag}
                      </span>
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
