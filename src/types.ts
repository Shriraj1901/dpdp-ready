export type Severity = "high" | "medium" | "low" | "info";
export type Confidence = "high" | "medium" | "low";

export const SEVERITY_ORDER: Record<Severity, number> = { high: 3, medium: 2, low: 1, info: 0 };

export interface Location {
  /** Path relative to the scan root, always with forward slashes. */
  file: string;
  line: number;
  /** Short excerpt of the line. Secrets and personal data are masked. */
  snippet: string;
}

export type RuleId =
  | "secret-in-code"
  | "personal-data-in-logs"
  | "hardcoded-personal-data"
  | "sensitive-personal-data"
  | "third-party-processor"
  | "web-no-https"
  | "web-no-privacy-notice"
  | "web-notice-gaps"
  | "web-trackers"
  | "web-cookies-on-load";

export interface Finding {
  /** Stable id: rule + location, so results can be compared between scans. */
  id: string;
  rule: RuleId;
  title: string;
  severity: Severity;
  confidence: Confidence;
  location?: Location;
  url?: string;
  /** What was actually seen. Masked. */
  evidence: string;
  why: string;
  recommendation: string;
  /** Relevant DPDP provisions, for review by a qualified professional. */
  dpdp: string[];
}

export interface InventoryItem {
  type: string;
  label: string;
  sensitive: boolean;
  /** Number of distinct code locations. */
  count: number;
  files: number;
  locations: Location[];
}

export interface Processor {
  id: string;
  vendor: string;
  category: string;
  dataTypically: string;
  /** Where it was detected: dependency manifests or code references. */
  evidence: { kind: "dependency" | "code-reference"; detail: string; file: string; line?: number }[];
}

export interface WebsiteResult {
  url: string;
  finalUrl: string;
  status: number;
  pagesRead: string[];
  thirdParties: { domain: string; vendor?: string; category?: string; kinds: string[] }[];
  cookiesOnLoad: string[];
  consentTool: string | null;
  privacyNoticeUrl: string | null;
  noticeSignals: { id: string; label: string; found: boolean }[];
  formsCollecting: string[];
  notes: string[];
}

export interface ScanResult {
  tool: { name: string; version: string };
  scannedAt: string;
  root: string;
  filesScanned: number;
  filesSkipped: number;
  inventory: InventoryItem[];
  processors: Processor[];
  findings: Finding[];
  website?: WebsiteResult;
  limitations: string[];
}
