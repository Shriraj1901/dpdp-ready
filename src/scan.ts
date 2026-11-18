import path from "node:path";
import type { Finding, ScanResult } from "./types.ts";
import { SEVERITY_ORDER } from "./types.ts";
import { walk } from "./walk.ts";
import { buildInventory, findPiiDefinitions, sensitiveFindings, type PiiHit } from "./detectors/pii.ts";
import { findSecrets } from "./detectors/secrets.ts";
import { findPiiInLogs } from "./detectors/logs.ts";
import { findHardcodedPersonalData } from "./detectors/hardcoded.ts";
import { findProcessors, processorFindings } from "./detectors/processors.ts";
import { scanWebsite } from "./website.ts";
import { DISCLAIMER } from "./dpdp.ts";

export const VERSION = "0.2.0";

export interface ScanOptions {
  root: string;
  website?: string;
  fetchImpl?: typeof fetch;
}

const CODE_LIMITATIONS = [
  "Static analysis of source files only: databases, logs, cloud configuration, backups and vendor contracts were not inspected.",
  "Personal data is detected from field names and code patterns; fields with unusual names may be missed, and some matches may not be personal data.",
  "Secret detection uses high-precision patterns; use a dedicated secret scanner (e.g. gitleaks) for full coverage, including git history.",
  "Vendors are detected from dependency manifests and URLs in code; services called without an SDK or URL in the code may be missed.",
];

const WEB_LIMITATIONS = [
  "Website check reads HTML without running JavaScript: scripts and cookies added at runtime are not seen. Verify in a browser with a fresh profile.",
  "Privacy-notice checks are keyword searches and cannot judge whether the notice is legally adequate.",
];

export async function scan(opts: ScanOptions): Promise<ScanResult> {
  const root = path.resolve(opts.root);
  const { files, skipped } = walk(root);

  const piiHits: PiiHit[] = [];
  const findings: Finding[] = [];
  for (const f of files) {
    if (!f.isTest) piiHits.push(...findPiiDefinitions(f));
    findings.push(...findSecrets(f));
    findings.push(...findPiiInLogs(f));
    findings.push(...findHardcodedPersonalData(f));
  }
  const inventory = buildInventory(piiHits);
  findings.push(...sensitiveFindings(inventory));
  const processors = findProcessors(files);
  findings.push(...processorFindings(processors));

  const result: ScanResult = {
    tool: { name: "DPDP Ready", version: VERSION },
    scannedAt: new Date().toISOString(),
    // Folder name only: full paths can reveal usernames when reports are shared.
    root: path.basename(root),
    filesScanned: files.length,
    filesSkipped: skipped,
    inventory,
    processors,
    findings,
    limitations: [...CODE_LIMITATIONS],
  };

  if (opts.website) {
    try {
      const w = await scanWebsite(opts.website, opts.fetchImpl);
      result.website = w.result;
      result.findings.push(...w.findings);
    } catch (e) {
      result.limitations.push(`Website scan failed: ${(e as Error).message}`);
    }
    result.limitations.push(...WEB_LIMITATIONS);
  }
  result.limitations.push(DISCLAIMER);

  result.findings.sort(
    (a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || (a.location?.file ?? "").localeCompare(b.location?.file ?? "") || (a.location?.line ?? 0) - (b.location?.line ?? 0),
  );
  return result;
}
