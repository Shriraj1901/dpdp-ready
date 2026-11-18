import { createHash } from "node:crypto";
import type { RuleId, ScanResult, Severity } from "../types.ts";

const LEVEL: Record<Severity, "error" | "warning" | "note"> = { high: "error", medium: "warning", low: "note", info: "note" };

const RULE_HELP: Record<RuleId, string> = {
  "secret-in-code": "A credential is stored in the repository. Rotate it and load it from a secret store.",
  "personal-data-in-logs": "Personal data appears to be written to logs. Log IDs or masked values instead.",
  "hardcoded-personal-data": "Real-looking personal data is written into source code.",
  "sensitive-personal-data": "The code defines fields for higher-risk personal data.",
  "third-party-processor": "A third-party service that usually receives personal data is used.",
  "web-no-https": "The website is not served over HTTPS.",
  "web-no-privacy-notice": "No privacy notice link was found on the homepage.",
  "web-notice-gaps": "The privacy notice may be missing required elements.",
  "web-trackers": "Tracking or analytics scripts are referenced by the homepage.",
  "web-cookies-on-load": "Tracking cookies are set on the first page load.",
};

/** SARIF 2.1.0 for GitHub code scanning. Only findings with a code location are included. */
export function toSarif(r: ScanResult): object {
  const withLoc = r.findings.filter((f) => f.location);
  const ruleIds = [...new Set(withLoc.map((f) => f.rule))];
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "DPDP Ready",
            version: r.tool.version,
            rules: ruleIds.map((id) => {
              const sample = withLoc.find((f) => f.rule === id)!;
              return {
                id,
                name: id.replace(/(^|-)(\w)/g, (_, __, c: string) => c.toUpperCase()),
                shortDescription: { text: RULE_HELP[id] },
                fullDescription: { text: `${RULE_HELP[id]} ${sample.why}` },
                help: { text: `${sample.recommendation}\n\nRelevant provisions (for review): ${sample.dpdp.join("; ")}` },
                defaultConfiguration: { level: LEVEL[sample.severity] },
                properties: { tags: ["privacy", "dpdp"] },
              };
            }),
          },
        },
        results: withLoc.map((f) => ({
          ruleId: f.rule,
          level: LEVEL[f.severity],
          message: { text: `${f.title}. ${f.evidence}. ${f.recommendation}` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.location!.file },
                region: { startLine: Math.max(1, f.location!.line) },
              },
            },
          ],
          partialFingerprints: { dpdpReadyId: createHash("sha256").update(f.id).digest("hex").slice(0, 32) },
          properties: { confidence: f.confidence, severity: f.severity },
        })),
      },
    ],
  };
}
