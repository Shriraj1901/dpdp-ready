import type { Confidence, Finding } from "../types.ts";
import type { SourceFile } from "../walk.ts";
import { DPDP } from "../dpdp.ts";

interface SecretPattern {
  id: string;
  label: string;
  re: RegExp;
  /** Capture group holding the secret value (0 = whole match). */
  group?: number;
  confidence: Confidence;
}

// High-precision patterns only. For full coverage, also run a dedicated tool such as gitleaks.
const PATTERNS: SecretPattern[] = [
  { id: "aws-access-key", label: "AWS access key ID", re: /\b((?:AKIA|ASIA)[0-9A-Z]{16})\b/g, group: 1, confidence: "high" },
  { id: "google-api-key", label: "Google API key", re: /\b(AIza[0-9A-Za-z_-]{35})\b/g, group: 1, confidence: "high" },
  { id: "stripe-live", label: "Stripe live secret key", re: /\b((?:sk|rk)_live_[0-9a-zA-Z]{20,})\b/g, group: 1, confidence: "high" },
  { id: "github-token", label: "GitHub token", re: /\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/g, group: 1, confidence: "high" },
  { id: "slack-token", label: "Slack token", re: /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/g, group: 1, confidence: "high" },
  { id: "anthropic-key", label: "Anthropic API key", re: /\b(sk-ant-[A-Za-z0-9_-]{30,})\b/g, group: 1, confidence: "high" },
  { id: "openai-key", label: "OpenAI-style API key", re: /\b(sk-(?:proj-)?[A-Za-z0-9_-]{32,})\b/g, group: 1, confidence: "medium" },
  { id: "sendgrid-key", label: "SendGrid API key", re: /\b(SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{30,})\b/g, group: 1, confidence: "high" },
  { id: "private-key", label: "Private key", re: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----)/g, group: 1, confidence: "high" },
  {
    id: "generic-assignment",
    label: "Hardcoded password or secret",
    re: /\b(?:[A-Za-z_]*?(?:password|passwd|secret|api_?key|apikey|access_?token|auth_?token|client_?secret|private_?key))["']?\s*[:=]\s*["']([^"'\s]{8,})["']/gi,
    group: 1,
    confidence: "medium",
  },
];

const PLACEHOLDER = /^(?:x+|\*+|\.+|<.*>|\{.*\}|\$\{.*\}|%.*%)$|your|example|changeme|change_me|placeholder|dummy|sample|redacted|xxxx|todo|insert|replace|process\.env|os\.environ|getenv|config\.|import\.meta|test|fake|mock|invalid|demo/i;

export function mask(value: string): string {
  if (value.startsWith("-----BEGIN")) return value;
  const head = value.slice(0, 4);
  return `${head}${"*".repeat(Math.min(8, Math.max(4, value.length - 4)))} (${value.length} chars)`;
}

/** Shannon entropy in bits per character. Real secrets are random; words like "secret-key" are not. */
export function entropy(s: string): number {
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Generic "password = '...'" values must look machine-generated, not like a constant name, route or icon id. */
export function looksRandom(v: string): boolean {
  if (v.length < 12 || !/[A-Za-z]/.test(v) || !/\d/.test(v)) return false;
  if (/^[A-Z][A-Z0-9_]*$/.test(v)) return false; // CONSTANT_NAME
  if (/^[a-z0-9]+([-_.][a-z0-9]+)+$/.test(v)) return false; // kebab-case or dotted words
  if (/^\/|^[\w-]+(\/[\w:.-]+)+\/?$/.test(v)) return false; // paths and routes
  return entropy(v) >= 3.0;
}

/** Cheap check so most lines skip the full pattern list. */
const PREFILTER = /AKIA|ASIA|AIza|_live_|gh[pousr]_|github_pat_|xox[baprs]-|sk-|SG\.|PRIVATE KEY|passw|secret|api_?key|apikey|token|private_?key/i;

function isEnvFile(rel: string) {
  const name = rel.split("/").pop() ?? "";
  return /^\.env(\..+)?$/.test(name) && !/\.(example|sample|template|dist|defaults)$/i.test(name);
}

export function findSecrets(file: SourceFile): Finding[] {
  const out: Finding[] = [];
  if (!PREFILTER.test(file.text)) return out;
  const lines = file.text.split(/\r?\n/);
  const env = isEnvFile(file.rel);
  lines.forEach((line, i) => {
    if (line.length > 4000 || !PREFILTER.test(line)) return;
    const seenOnLine = new Set<string>();
    for (const pat of PATTERNS) {
      // Tests use made-up "apiKey: 'test-key'" values all the time; only provider-format keys count there.
      if (file.isTest && pat.id === "generic-assignment") continue;
      pat.re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = pat.re.exec(line))) {
        const value = m[pat.group ?? 0];
        if (!value || seenOnLine.has(value)) continue;
        if (pat.id !== "private-key" && (PLACEHOLDER.test(value) || /EXAMPLE/.test(value))) continue;
        if (pat.id === "generic-assignment" && !looksRandom(value)) continue;
        seenOnLine.add(value);
        out.push({
          id: `secret-in-code:${file.rel}:${i + 1}:${pat.id}`,
          rule: "secret-in-code",
          title: `${pat.label} in ${env ? "an environment file inside the repository" : file.isTest ? "a test file" : "source code"}`,
          // A provider-format key in a test may still be real, but is more often a dummy.
          severity: file.isTest ? "medium" : "high",
          confidence: file.isTest ? "low" : pat.confidence,
          location: { file: file.rel, line: i + 1, snippet: line.replace(value, mask(value)).trim().slice(0, 160) },
          evidence: mask(value),
          why: "Anyone with access to the repository (or a leaked copy) can use this credential to reach systems that may hold personal data.",
          recommendation:
            "Revoke and rotate this credential now, then load it from an environment variable or secret manager. Removing it from the latest commit is not enough: it stays in git history.",
          dpdp: [DPDP.security, DPDP.securityRule, DPDP.breach],
        });
      }
    }
  });
  return out;
}
