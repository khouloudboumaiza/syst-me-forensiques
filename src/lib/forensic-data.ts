// Mock forensic data for the dashboard demo
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type SourceTool = "Loki" | "Hayabusa" | "Autopsy" | "Kuiper";

export const caseInfo = {
  id: "CASE-2026-0142",
  name: "Incident PowerShell suspect - Poste RH-04",
  analyst: "Stagiaire Forensique",
  createdAt: "2026-06-28 09:14",
  status: "In Progress",
  threatLevel: "High" as const,
};

export const stats = {
  filesAnalyzed: 12847,
  alerts: 143,
  iocs: 27,
  artifacts: 3421,
  sources: 4,
  correlations: 18,
};

export const severityDistribution = [
  { level: "Critical", count: 6, color: "var(--critical)" },
  { level: "High", count: 19, color: "var(--high)" },
  { level: "Medium", count: 42, color: "var(--medium)" },
  { level: "Low", count: 76, color: "var(--low)" },
];

export const toolDistribution: { tool: SourceTool; files: number; alerts: number }[] = [
  { tool: "Loki", files: 1240, alerts: 32 },
  { tool: "Hayabusa", files: 8420, alerts: 87 },
  { tool: "Autopsy", files: 2890, alerts: 14 },
  { tool: "Kuiper", files: 297, alerts: 10 },
];

export const timelineActivity = [
  { time: "00:00", events: 4 },
  { time: "02:00", events: 2 },
  { time: "04:00", events: 1 },
  { time: "06:00", events: 3 },
  { time: "08:00", events: 12 },
  { time: "10:00", events: 28 },
  { time: "12:00", events: 34 },
  { time: "14:00", events: 41 },
  { time: "16:00", events: 22 },
  { time: "18:00", events: 9 },
  { time: "20:00", events: 5 },
  { time: "22:00", events: 3 },
];

export type Alert = {
  id: string;
  timestamp: string;
  source: SourceTool;
  severity: Severity;
  rule: string;
  target: string;
  description: string;
};

export const alerts: Alert[] = [
  { id: "ALT-0001", timestamp: "2026-06-28 14:22:11", source: "Loki", severity: "critical", rule: "MAL_Mimikatz_Gen", target: "C:\\Users\\rh04\\Downloads\\update.exe", description: "Signature YARA Mimikatz détectée dans un binaire téléchargé." },
  { id: "ALT-0002", timestamp: "2026-06-28 14:20:04", source: "Hayabusa", severity: "high", rule: "Suspicious PowerShell EncodedCommand", target: "EventID 4104 - powershell.exe", description: "Exécution PowerShell avec commande encodée base64 (obfuscation)." },
  { id: "ALT-0003", timestamp: "2026-06-28 14:19:58", source: "Hayabusa", severity: "high", rule: "New Service Installed", target: "EventID 7045 - WinDefendUpd", description: "Installation d'un service Windows avec nom trompeur." },
  { id: "ALT-0004", timestamp: "2026-06-28 14:25:33", source: "Autopsy", severity: "medium", rule: "Recent File - Suspicious Path", target: "C:\\ProgramData\\.cache\\svchost.exe", description: "Binaire trouvé dans un chemin inhabituel." },
  { id: "ALT-0005", timestamp: "2026-06-28 14:32:12", source: "Kuiper", severity: "medium", rule: "USB Device Connected", target: "USBSTOR\\Disk&Ven_Kingston", description: "Périphérique USB inconnu connecté avant l'incident." },
  { id: "ALT-0006", timestamp: "2026-06-28 14:41:07", source: "Loki", severity: "high", rule: "IOC_C2_Beacon", target: "185.220.101.42:443", description: "Connexion vers IP identifiée comme serveur C2 connu." },
  { id: "ALT-0007", timestamp: "2026-06-28 14:12:44", source: "Hayabusa", severity: "low", rule: "Failed Login Burst", target: "EventID 4625 - rh04", description: "5 échecs de connexion consécutifs." },
  { id: "ALT-0008", timestamp: "2026-06-28 14:44:29", source: "Autopsy", severity: "critical", rule: "Deleted File Recovered - Ransom Note", target: "C:\\Users\\rh04\\Desktop\\README_DECRYPT.txt", description: "Note de rançon récupérée du secteur non alloué." },
];

export type IOC = {
  value: string;
  type: "IP" | "Hash" | "Domain" | "File" | "Registry";
  source: SourceTool;
  hits: number;
  firstSeen: string;
};

export const iocs: IOC[] = [
  { value: "185.220.101.42", type: "IP", source: "Loki", hits: 12, firstSeen: "2026-06-28 14:41" },
  { value: "a1b2c3d4e5f6789012345678901234567890abcd", type: "Hash", source: "Loki", hits: 3, firstSeen: "2026-06-28 14:22" },
  { value: "malicious-domain.tk", type: "Domain", source: "Hayabusa", hits: 8, firstSeen: "2026-06-28 14:19" },
  { value: "C:\\ProgramData\\.cache\\svchost.exe", type: "File", source: "Autopsy", hits: 1, firstSeen: "2026-06-28 14:25" },
  { value: "HKCU\\...\\Run\\WinDefendUpd", type: "Registry", source: "Kuiper", hits: 1, firstSeen: "2026-06-28 14:20" },
  { value: "f9e8d7c6b5a4938271605948372615049382abcd", type: "Hash", source: "Loki", hits: 2, firstSeen: "2026-06-28 14:22" },
];

export type TimelineEvent = {
  time: string;
  source: SourceTool;
  severity: Severity;
  title: string;
  detail: string;
};

export const correlatedTimeline: TimelineEvent[] = [
  { time: "14:12:44", source: "Hayabusa", severity: "low", title: "Échecs de connexion", detail: "5 tentatives échouées sur compte rh04." },
  { time: "14:19:58", source: "Hayabusa", severity: "high", title: "PowerShell obfusqué", detail: "EncodedCommand base64 exécutée depuis session utilisateur." },
  { time: "14:20:04", source: "Hayabusa", severity: "high", title: "Service Windows installé", detail: "Service WinDefendUpd créé avec binaire non signé." },
  { time: "14:22:11", source: "Loki", severity: "critical", title: "Malware détecté", detail: "update.exe correspond à la règle YARA Mimikatz." },
  { time: "14:25:33", source: "Autopsy", severity: "medium", title: "Binaire suspect sur disque", detail: "svchost.exe trouvé dans C:\\ProgramData\\.cache\\." },
  { time: "14:32:12", source: "Kuiper", severity: "medium", title: "Clé USB connectée", detail: "Kingston DataTraveler branchée après l'exécution." },
  { time: "14:41:07", source: "Loki", severity: "high", title: "Beacon C2", detail: "Connexion sortante vers 185.220.101.42:443." },
  { time: "14:44:29", source: "Autopsy", severity: "critical", title: "Note de rançon", detail: "README_DECRYPT.txt récupéré (fichier supprimé)." },
];

export const correlations = [
  {
    id: "CORR-01",
    title: "Chaîne d'infection PowerShell → Mimikatz → C2",
    confidence: 92,
    severity: "critical" as Severity,
    sources: ["Hayabusa", "Loki"] as SourceTool[],
    summary:
      "Une commande PowerShell obfusquée a téléchargé update.exe, identifié comme Mimikatz par Loki. Peu après, une connexion sortante vers un C2 connu a été observée.",
    evidences: ["ALT-0002", "ALT-0001", "ALT-0006"],
  },
  {
    id: "CORR-02",
    title: "Persistance via service Windows malveillant",
    confidence: 84,
    severity: "high" as Severity,
    sources: ["Hayabusa", "Autopsy"] as SourceTool[],
    summary:
      "Le service WinDefendUpd pointe vers svchost.exe dans un chemin non standard découvert par Autopsy — technique de persistance.",
    evidences: ["ALT-0003", "ALT-0004"],
  },
  {
    id: "CORR-03",
    title: "Exfiltration probable via USB",
    confidence: 61,
    severity: "medium" as Severity,
    sources: ["Kuiper", "Autopsy"] as SourceTool[],
    summary:
      "Une clé USB inconnue a été connectée pendant l'incident, corrélée avec des accès récents à des dossiers sensibles.",
    evidences: ["ALT-0005"],
  },
];

export const artifacts = [
  { name: "update.exe", path: "C:\\Users\\rh04\\Downloads\\", size: "412 KB", hash: "a1b2c3d4…abcd", source: "Autopsy" as SourceTool, tag: "malware" },
  { name: "svchost.exe", path: "C:\\ProgramData\\.cache\\", size: "289 KB", hash: "f9e8d7c6…abcd", source: "Autopsy" as SourceTool, tag: "suspicious" },
  { name: "README_DECRYPT.txt", path: "C:\\Users\\rh04\\Desktop\\", size: "2 KB", hash: "-", source: "Autopsy" as SourceTool, tag: "ransom-note" },
  { name: "powershell.evtx", path: "C:\\Windows\\System32\\winevt\\", size: "18 MB", hash: "-", source: "Hayabusa" as SourceTool, tag: "log" },
  { name: "Kingston-USB.img", path: "Evidence/USB01/", size: "16 GB", hash: "b2c3d4e5…9876", source: "Kuiper" as SourceTool, tag: "image" },
];
