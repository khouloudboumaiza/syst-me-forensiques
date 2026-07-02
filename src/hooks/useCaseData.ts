// src/hooks/useCaseData.ts
//
// Centralise les appels API du dashboard et gère le rafraîchissement
// automatique après un upload, sans reload manuel de la page.

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { API_URL } from "@/lib/api";

const CASE_ID = "demo"; // remplacez par votre case_id dynamique si multi-dossiers

// Intervalle de polling pendant qu'une analyse est en cours (2 s),
// sinon on revient à 10 s pour ne pas surcharger le backend.
const POLL_INTERVAL_ACTIVE = 2000;
const POLL_INTERVAL_IDLE = 10000;

// --- Lecture des données (se rafraîchissent automatiquement) ---
export function useStats() {
  return useQuery({
    queryKey: ["stats", CASE_ID],
    queryFn: () =>
      fetch(`${API_URL}/cases/${CASE_ID}/stats`).then((r) => r.json()),
    refetchInterval: POLL_INTERVAL_ACTIVE,
  });
}

export function useAlerts() {
  return useQuery({
    queryKey: ["alerts", CASE_ID],
    queryFn: () =>
      fetch(`${API_URL}/cases/${CASE_ID}/alerts`).then((r) => r.json()),
    refetchInterval: POLL_INTERVAL_ACTIVE,
  });
}

export function useSeverityDistribution() {
  return useQuery({
    queryKey: ["severity-distribution", CASE_ID],
    queryFn: () =>
      fetch(`${API_URL}/cases/${CASE_ID}/severity-distribution`).then((r) =>
        r.json()
      ),
    refetchInterval: POLL_INTERVAL_ACTIVE,
  });
}

export function useToolDistribution() {
  return useQuery({
    queryKey: ["tool-distribution", CASE_ID],
    queryFn: () =>
      fetch(`${API_URL}/cases/${CASE_ID}/tool-distribution`).then((r) =>
        r.json()
      ),
    refetchInterval: POLL_INTERVAL_ACTIVE,
  });
}

export function useFilesList() {
  return useQuery({
    queryKey: ["files", CASE_ID],
    queryFn: () =>
      fetch(`${API_URL}/cases/${CASE_ID}/files`).then((r) => r.json()),
    refetchInterval: POLL_INTERVAL_ACTIVE,
  });
}

export function useNetworkAlerts() {
  return useQuery({
    queryKey: ["network-alerts", CASE_ID],
    queryFn: () =>
      fetch(`${API_URL}/cases/${CASE_ID}/network-alerts`).then((r) => r.json()),
    refetchInterval: POLL_INTERVAL_IDLE,
  });
}

export function useCorrelations() {
  return useQuery({
    queryKey: ["correlations", CASE_ID],
    queryFn: () =>
      fetch(`${API_URL}/cases/${CASE_ID}/correlations`).then((r) => r.json()),
    refetchInterval: POLL_INTERVAL_ACTIVE,
  });
}

// --- IOCs dérivés des alertes avec threat_intel ---
export function useIOCs() {
  return useQuery({
    queryKey: ["iocs", CASE_ID],
    queryFn: async () => {
      const alerts = await fetch(
        `${API_URL}/cases/${CASE_ID}/alerts`
      ).then((r) => r.json());
      if (!Array.isArray(alerts)) return [];

      // Construit une liste d'IOCs à partir des alertes enrichies
      const iocMap = new Map<string, any>();

      for (const a of alerts) {
        // IOCs de type IP
        const ips = [a.dst_ip, a.src_ip].filter(Boolean);
        for (const ip of ips) {
          if (!iocMap.has(ip)) {
            iocMap.set(ip, {
              value: ip,
              type: "IP",
              source: a.tool ?? "unknown",
              hits: 0,
              firstSeen: a.timestamp ?? "—",
              severity: a.severity ?? "info",
              threat_intel: a.threat_intel,
            });
          }
          iocMap.get(ip)!.hits += 1;
        }

        // IOCs de type File (cibles Loki)
        if (a.tool === "loki" && a.target) {
          const key = `file:${a.target}`;
          if (!iocMap.has(key)) {
            iocMap.set(key, {
              value: a.target,
              type: "File",
              source: a.tool,
              hits: 0,
              firstSeen: a.timestamp ?? "—",
              severity: a.severity ?? "info",
              threat_intel: a.threat_intel,
            });
          }
          iocMap.get(key)!.hits += 1;
        }

        // IOCs de type Hash depuis threat_intel
        if (a.threat_intel) {
          const ti =
            typeof a.threat_intel === "string"
              ? JSON.parse(a.threat_intel)
              : a.threat_intel;
          const hashes = ti?.hashes ?? [];
          for (const h of hashes) {
            if (!iocMap.has(h)) {
              iocMap.set(h, {
                value: h,
                type: "Hash",
                source: a.tool ?? "unknown",
                hits: 1,
                firstSeen: a.timestamp ?? "—",
                severity: a.severity ?? "info",
                threat_intel: a.threat_intel,
              });
            }
          }
        }
      }

      return Array.from(iocMap.values());
    },
    refetchInterval: POLL_INTERVAL_ACTIVE,
  });
}

// --- Timeline construite depuis les alertes triées par timestamp ---
export function useTimeline() {
  return useQuery({
    queryKey: ["timeline", CASE_ID],
    queryFn: async () => {
      const alerts = await fetch(
        `${API_URL}/cases/${CASE_ID}/alerts`
      ).then((r) => r.json());
      if (!Array.isArray(alerts)) return [];

      return [...alerts]
        .filter((a) => a.timestamp)
        .sort((a, b) => String(a.timestamp).localeCompare(String(b.timestamp)))
        .map((a) => ({
          time: String(a.timestamp ?? "").slice(11, 19) || "—",
          fullTimestamp: a.timestamp,
          source: a.tool ?? "unknown",
          severity: (a.severity ?? "info").toLowerCase(),
          title: a.title ?? a.rule ?? "Événement",
          detail: a.details ?? a.description ?? "",
          target: a.target ?? a.dst_ip ?? "",
        }));
    },
    refetchInterval: POLL_INTERVAL_ACTIVE,
  });
}

// --- Artefacts construits depuis les alertes (fichiers/binaires suspects) ---
export function useArtifacts() {
  return useQuery({
    queryKey: ["artifacts", CASE_ID],
    queryFn: async () => {
      const alerts = await fetch(
        `${API_URL}/cases/${CASE_ID}/alerts`
      ).then((r) => r.json());
      if (!Array.isArray(alerts)) return [];

      // On filtre les alertes ayant un chemin de fichier ou une cible fichier
      const seen = new Set<string>();
      const result: any[] = [];

      for (const a of alerts) {
        const path = a.file_path ?? a.target ?? "";
        if (!path || seen.has(path)) continue;
        seen.add(path);

        const parts = path.replace(/\\/g, "/").split("/");
        const name = parts[parts.length - 1] || path;
        const dir = parts.slice(0, -1).join("/") || "/";

        result.push({
          name,
          path: dir,
          hash: a.mitre_attack ? `MITRE: ${a.mitre_attack}` : "—",
          source: a.tool ?? "unknown",
          tag: tagFromSeverity(a.severity),
          severity: a.severity ?? "info",
          timestamp: a.timestamp ?? "—",
        });
      }

      return result;
    },
    refetchInterval: POLL_INTERVAL_ACTIVE,
  });
}

function tagFromSeverity(severity: string) {
  switch ((severity ?? "").toLowerCase()) {
    case "critical":
      return "malware";
    case "high":
      return "suspicious";
    case "medium":
      return "suspicious";
    default:
      return "log";
  }
}

// --- Rapport complet depuis le backend ---
export function useReport() {
  return useQuery({
    queryKey: ["report", CASE_ID],
    queryFn: () =>
      fetch(`${API_URL}/cases/${CASE_ID}/report`).then((r) => r.json()),
    refetchInterval: POLL_INTERVAL_IDLE,
  });
}

// --- Upload : dès que ça réussit, on force le refetch de TOUT le dashboard ---
export function useUploadFile() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (file: File) => {
      const formData = new FormData();
      formData.append("file", file);
      const res = await fetch(`${API_URL}/cases/${CASE_ID}/upload`, {
        method: "POST",
        body: formData,
      });
      if (!res.ok) throw new Error("Échec de l'upload");
      return res.json();
    },
    onSuccess: () => {
      // Invalide toutes les queries pour forcer un rechargement complet
      queryClient.invalidateQueries({ queryKey: ["stats", CASE_ID] });
      queryClient.invalidateQueries({ queryKey: ["alerts", CASE_ID] });
      queryClient.invalidateQueries({ queryKey: ["network-alerts", CASE_ID] });
      queryClient.invalidateQueries({ queryKey: ["correlations", CASE_ID] });
      queryClient.invalidateQueries({ queryKey: ["iocs", CASE_ID] });
      queryClient.invalidateQueries({ queryKey: ["timeline", CASE_ID] });
      queryClient.invalidateQueries({ queryKey: ["artifacts", CASE_ID] });
      queryClient.invalidateQueries({ queryKey: ["files", CASE_ID] });
      queryClient.invalidateQueries({ queryKey: ["report", CASE_ID] });
      queryClient.invalidateQueries({
        queryKey: ["severity-distribution", CASE_ID],
      });
      queryClient.invalidateQueries({
        queryKey: ["tool-distribution", CASE_ID],
      });
    },
  });
}

// --- Hook utilitaire : est-ce que le backend est joignable ? ---
export function useBackendStatus() {
  return useQuery({
    queryKey: ["backend-status"],
    queryFn: () =>
      fetch(`${API_URL}/`).then((r) => {
        if (!r.ok) throw new Error("Backend down");
        return r.json();
      }),
    refetchInterval: 5000,
    retry: 1,
  });
}