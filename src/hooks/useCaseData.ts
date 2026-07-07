// src/hooks/useCaseData.ts
//
// Centralise les appels API du dashboard.
// ─ Polling adaptatif : rapide (1.5 s) juste après un upload, lent (8 s) au repos.
// ─ Les hooks dérivés (IOCs, Timeline, Artefacts) partagent le MÊME cache
//   d'alertes via `select` — un seul vrai appel réseau pour tous.
// ─ useAnalysisStatus surveille /status (très léger) pendant le traitement.

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { API_URL } from "@/lib/api";
import { useFileSelection } from "./useFileSelection";

const CASE_ID = "demo";

// Durée pendant laquelle on garde les données en cache avant re-fetch
const STALE_TIME   = 4_000;   // 4 s  – données considérées « fraîches »
const IDLE_POLL    = 8_000;   // 8 s  – intervalle de polling au repos
const ACTIVE_POLL  = 1_500;   // 1.5 s – intervalle juste après un upload

// ─────────────────────────────────────────────────────────────────────────────
// Helpers de transformation (pur JS, pas d'appel réseau)
// ─────────────────────────────────────────────────────────────────────────────
function buildIOCsFromAlerts(alerts: any[], filesMap?: Record<number, string>): any[] {
  if (!Array.isArray(alerts)) return [];
  const iocMap = new Map<string, any>();

  for (const a of alerts) {
    const addIoc = (value: string, type: string, extra: object = {}) => {
      if (!value || value.length < 4) return;
      const key = `${type}:${value}`;
      if (!iocMap.has(key)) {
        iocMap.set(key, {
          value,
          type,
          source: a.tool ?? "unknown",
          file_id: a.file_id,
          filename: filesMap?.[a.file_id] || "Inconnu",
          hits: 0,
          firstSeen: a.timestamp ?? "—",
          severity: a.severity ?? "info",
          ...extra,
        });
      }
      iocMap.get(key)!.hits += 1;
    };

    addIoc(a.dst_ip, "IP");
    addIoc(a.src_ip, "IP");

    if (a.tool === "loki" && a.target) addIoc(a.target, "File");

    if (a.threat_intel) {
      try {
        const tiList = typeof a.threat_intel === "string" ? JSON.parse(a.threat_intel) : a.threat_intel;
        if (Array.isArray(tiList)) {
          for (const ti of tiList) {
            if (ti.type === "hash" || ti.type === "ip") {
              const vtScore = ti.found ? `${ti.malicious}/${(ti.malicious || 0) + (ti.suspicious || 0) + (ti.harmless || 0)}` : "—";
              const typeLabel = ti.type === "hash" ? "Hash" : "IP";
              addIoc(ti.value, typeLabel, { vtScore, vtVerdict: ti.verdict });
            }
          }
        }
      } catch (e) {
        console.error("Error parsing threat_intel", e);
      }
    }

    // Extraction magique (Regex) depuis le texte des alertes
    const textToSearch = `${a.title} ${a.details} ${a.target}`.toLowerCase();
    
    // Extraction des IPs
    const ips = textToSearch.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g);
    if (ips) ips.forEach(ip => addIoc(ip, "IP"));

    // Extraction des Hashes (MD5, SHA1, SHA256)
    const hashes = textToSearch.match(/\b[a-f0-9]{32,64}\b/g);
    if (hashes) hashes.forEach(hash => addIoc(hash, "Hash"));

    // Extraction des noms de fichiers suspects
    const files = textToSearch.match(/\b[a-z0-9_.-]+\.(exe|dll|ps1|bat|sh|bin|vbs)\b/g);
    if (files) files.forEach(f => addIoc(f, "File"));
  }

  return Array.from(iocMap.values());
}

function buildTimelineFromAlerts(alerts: any[]): any[] {
  if (!Array.isArray(alerts)) return [];
  return [...alerts]
    .filter((a) => a.timestamp)
    .sort((a, b) => String(a.timestamp).localeCompare(String(b.timestamp)))
    .map((a) => ({
      time:          String(a.timestamp ?? "").slice(11, 19) || "—",
      fullTimestamp: a.timestamp,
      source:        a.tool ?? "unknown",
      severity:      (a.severity ?? "info").toLowerCase(),
      title:         a.title ?? a.rule ?? "Événement",
      detail:        a.details ?? a.description ?? "",
      target:        a.target ?? a.dst_ip ?? "",
    }));
}

function buildArtifactsFromAlerts(alerts: any[]): any[] {
  if (!Array.isArray(alerts)) return [];
  const seen = new Set<string>();
  const result: any[] = [];

  for (const a of alerts) {
    const path = a.file_path ?? a.target ?? "";
    if (!path || seen.has(path)) continue;
    seen.add(path);

    const parts = path.replace(/\\/g, "/").split("/");
    const name  = parts[parts.length - 1] || path;
    const dir   = parts.slice(0, -1).join("/") || "/";

    const sev = (a.severity ?? "").toLowerCase();
    result.push({
      name,
      path:      dir,
      hash:      a.mitre_attack ? `MITRE: ${a.mitre_attack}` : "—",
      source:    a.tool ?? "unknown",
      tag:       sev === "critical" ? "malware" : sev === "high" ? "suspicious" : "log",
      severity:  a.severity ?? "info",
      timestamp: a.timestamp ?? "—",
    });
  }
  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// État partagé : timestamp du dernier upload (pour le polling adaptatif)
// ─────────────────────────────────────────────────────────────────────────────
let _lastUploadAt = 0;
const ACTIVE_WINDOW_MS = 30_000; // polling rapide pendant 30 s après upload

function getRefetchInterval() {
  const sinceUpload = Date.now() - _lastUploadAt;
  return sinceUpload < ACTIVE_WINDOW_MS ? ACTIVE_POLL : IDLE_POLL;
}

// ─────────────────────────────────────────────────────────────────────────────
// Hooks de lecture — données primaires
// ─────────────────────────────────────────────────────────────────────────────
export function useStats() {
  const { selectedFileId } = useFileSelection();
  return useQuery({
    queryKey:       ["stats", CASE_ID, selectedFileId],
    queryFn:        () => fetch(`${API_URL}/cases/${CASE_ID}/stats${selectedFileId ? `?file_id=${selectedFileId}` : ""}`).then((r) => r.json()),
    staleTime:      STALE_TIME,
    refetchInterval: getRefetchInterval,
  });
}

/** Requête principale : partagée avec les hooks dérivés via `select`. */
export function useAlerts() {
  const { selectedFileId } = useFileSelection();
  return useQuery({
    queryKey:        ["alerts", CASE_ID, selectedFileId],
    queryFn:         () =>
      fetch(`${API_URL}/cases/${CASE_ID}/alerts?limit=500${selectedFileId ? `&file_id=${selectedFileId}` : ""}`).then((r) => r.json()),
    staleTime:       STALE_TIME,
    refetchInterval: getRefetchInterval,
  });
}

export function useSeverityDistribution() {
  const { selectedFileId } = useFileSelection();
  return useQuery({
    queryKey:        ["severity-distribution", CASE_ID, selectedFileId],
    queryFn:         () =>
      fetch(`${API_URL}/cases/${CASE_ID}/severity-distribution${selectedFileId ? `?file_id=${selectedFileId}` : ""}`).then((r) => r.json()),
    staleTime:       STALE_TIME,
    refetchInterval: getRefetchInterval,
  });
}

export function useToolDistribution() {
  const { selectedFileId } = useFileSelection();
  return useQuery({
    queryKey:        ["tool-distribution", CASE_ID, selectedFileId],
    queryFn:         () =>
      fetch(`${API_URL}/cases/${CASE_ID}/tool-distribution${selectedFileId ? `?file_id=${selectedFileId}` : ""}`).then((r) => r.json()),
    staleTime:       STALE_TIME,
    refetchInterval: getRefetchInterval,
  });
}

export function useFilesList() {
  return useQuery({
    queryKey:        ["files", CASE_ID],
    queryFn:         () =>
      fetch(`${API_URL}/cases/${CASE_ID}/files`).then((r) => r.json()),
    staleTime:       STALE_TIME,
    refetchInterval: getRefetchInterval,
  });
}

export function useCorrelations() {
  const { selectedFileId } = useFileSelection();
  return useQuery({
    queryKey:        ["correlations", CASE_ID, selectedFileId],
    queryFn:         () =>
      fetch(`${API_URL}/cases/${CASE_ID}/correlations${selectedFileId ? `?file_id=${selectedFileId}` : ""}`).then((r) => r.json()),
    staleTime:       STALE_TIME,
    refetchInterval: getRefetchInterval,
  });
}

export function useReport() {
  const { selectedFileId } = useFileSelection();
  return useQuery({
    queryKey:        ["report", CASE_ID, selectedFileId],
    queryFn:         () =>
      fetch(`${API_URL}/cases/${CASE_ID}/report${selectedFileId ? `?file_id=${selectedFileId}` : ""}`).then((r) => r.json()),
    staleTime:       10_000,
    refetchInterval: IDLE_POLL,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Hooks dérivés — partagent le cache d'alertes via `select` (0 appel réseau sup.)
// ─────────────────────────────────────────────────────────────────────────────
export function useIOCs() {
  const { selectedFileId } = useFileSelection();
  return useQuery({
    queryKey:        ["alerts", CASE_ID, selectedFileId],
    queryFn:         () =>
      fetch(`${API_URL}/cases/${CASE_ID}/alerts?limit=500${selectedFileId ? `&file_id=${selectedFileId}` : ""}`).then((r) => r.json()),
    select:          buildIOCsFromAlerts,
    staleTime:       STALE_TIME,
    refetchInterval: getRefetchInterval,
  });
}

export function useTimeline() {
  const { selectedFileId } = useFileSelection();
  return useQuery({
    queryKey:        ["alerts", CASE_ID, selectedFileId],
    queryFn:         () =>
      fetch(`${API_URL}/cases/${CASE_ID}/alerts?limit=500${selectedFileId ? `&file_id=${selectedFileId}` : ""}`).then((r) => r.json()),
    select:          buildTimelineFromAlerts,
    staleTime:       STALE_TIME,
    refetchInterval: getRefetchInterval,
  });
}

export function useArtifacts() {
  const { selectedFileId } = useFileSelection();
  return useQuery({
    queryKey:        ["alerts", CASE_ID, selectedFileId],
    queryFn:         () =>
      fetch(`${API_URL}/cases/${CASE_ID}/alerts?limit=500${selectedFileId ? `&file_id=${selectedFileId}` : ""}`).then((r) => r.json()),
    select:          buildArtifactsFromAlerts,
    staleTime:       STALE_TIME,
    refetchInterval: getRefetchInterval,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Statut backend
// ─────────────────────────────────────────────────────────────────────────────
export function useBackendStatus() {
  return useQuery({
    queryKey:        ["backend-status"],
    queryFn:         () =>
      fetch(`${API_URL}/`).then((r) => {
        if (!r.ok) throw new Error("Backend down");
        return r.json();
      }),
    staleTime:       4_000,
    refetchInterval: 6_000,
    retry:           1,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Statut d'analyse — endpoint ultra-léger (polling agressif pendant traitement)
// ─────────────────────────────────────────────────────────────────────────────
export function useAnalysisStatus() {
  return useQuery({
    queryKey:        ["status", CASE_ID],
    queryFn:         () =>
      fetch(`${API_URL}/cases/${CASE_ID}/status`).then((r) => r.json()),
    staleTime:       500,
    refetchInterval: (data: any) => {
      // Si traitement en cours : poll toutes les 1.5 s, sinon 8 s
      return data?.processing ? 1_500 : 8_000;
    },
    retry: 1,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Upload : supporte un ou plusieurs fichiers. Invalide le cache et passe en
// mode polling rapide 30 s.
// ─────────────────────────────────────────────────────────────────────────────
export function useUploadFile() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (files: File | File[]) => {
      const fileArray = Array.isArray(files) ? files : [files];
      const formData = new FormData();

      if (fileArray.length === 1) {
        // Single file → utilise l'endpoint existant
        formData.append("file", fileArray[0]);
        const res = await fetch(`${API_URL}/cases/${CASE_ID}/upload`, {
          method: "POST",
          body: formData,
        });
        if (!res.ok) throw new Error("Échec de l'upload");
        return res.json();
      } else {
        // Multiple files → utilise le nouvel endpoint multi
        for (const f of fileArray) {
          formData.append("files", f);
        }
        const res = await fetch(`${API_URL}/cases/${CASE_ID}/upload-multi`, {
          method: "POST",
          body: formData,
        });
        if (!res.ok) throw new Error("Échec de l'upload");
        return res.json();
      }
    },
    onMutate: () => {
      _lastUploadAt = Date.now();
    },
    onSuccess: () => {
      _lastUploadAt = Date.now();

      queryClient.invalidateQueries({ queryKey: ["stats",                CASE_ID] });
      queryClient.invalidateQueries({ queryKey: ["alerts",               CASE_ID] });
      queryClient.invalidateQueries({ queryKey: ["correlations",         CASE_ID] });
      queryClient.invalidateQueries({ queryKey: ["files",                CASE_ID] });
      queryClient.invalidateQueries({ queryKey: ["report",               CASE_ID] });
      queryClient.invalidateQueries({ queryKey: ["severity-distribution", CASE_ID] });
      queryClient.invalidateQueries({ queryKey: ["tool-distribution",    CASE_ID] });
    },
  });
}