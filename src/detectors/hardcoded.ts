import type { Finding } from "../types.ts";
import type { SourceFile } from "../walk.ts";
import { DPDP } from "../dpdp.ts";

const EMAIL = /\b([A-Za-z0-9._%+-]{1,64})@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/g;
const PHONE_IN = /(?<![\d.])(\+91[\s-]?[6-9]\d{4}[\s-]?\d{5}|(?<!\+)\b[6-9]\d{9})\b/g;
const AADHAAR = /\b([2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4})\b/g;

const ROLE_ACCOUNTS = /^(no-?reply|do-?not-?reply|support|help|hello|hi|info|contact|admin|sales|team|careers|jobs|hr|privacy|dpo|grievance|legal|security|billing|accounts|notifications?|alerts?|feedback|press|media|marketing|webmaster|postmaster|abuse|founders?|ops|dev|developers?|api|bot|mailer|newsletter|git|user|username|name|someone|test|foo|bar|me|you|john\.?doe|jane\.?doe)$/i;
const SAFE_DOMAINS = /(^|\.)(example\.(com|org|net|in)|test|localhost|invalid|local|internal|svc|lan|home|corp|domain\.com|email\.com|company\.com|yourdomain\.com|acme\.(com|in)|users\.noreply\.github\.com|gserviceaccount\.com|sentry\.io|w3\.org|schema\.org)$/i;
/** Automation identities (CI bots, service accounts) are not people. */
const BOT_LOCAL = /bot|github|actions|^ci$|deploy|service|system|automation|release|renovate|dependabot/i;
const ASSET = /\.(png|jpe?g|gif|svg|webp|css|js)$/i;

function maskEmail(local: string, domain: string) {
  return `${local[0]}***@${domain}`;
}
function maskDigits(s: string) {
  const d = s.replace(/\D/g, "");
  return `${d.slice(0, 2)}******${d.slice(-2)}`;
}

/** Flags real-looking personal emails, Indian mobile numbers and Aadhaar numbers written into source (outside tests). */
export function findHardcodedPersonalData(file: SourceFile): Finding[] {
  if (file.isTest || /\.(md|txt|lock|example|sample|template)$/i.test(file.rel) || /(^|\/)(LICENSE|CHANGELOG|AUTHORS|CODEOWNERS)/i.test(file.rel)) return [];
  const out: Finding[] = [];
  file.text.split(/\r?\n/).forEach((line, i) => {
    if (line.length > 2000) return;
    const push = (kind: string, masked: string, severity: "low" | "medium") =>
      out.push({
        id: `hardcoded-personal-data:${file.rel}:${i + 1}:${kind}`,
        rule: "hardcoded-personal-data",
        title: `Personal data written into source code (${kind})`,
        severity,
        confidence: "low",
        location: { file: file.rel, line: i + 1, snippet: `… ${masked} …` },
        evidence: masked,
        why: "Personal data in source code is copied to every clone, fork and backup, and cannot be erased on request.",
        recommendation: "Move real people's data out of the code (to the database or config). Use fake values such as name@example.com in code and tests.",
        dpdp: [DPDP.erasure, DPDP.security],
      });

    EMAIL.lastIndex = 0;
    let m: RegExpExecArray | null;
    while (line.includes("@") && (m = EMAIL.exec(line))) {
      const [, local, domain] = m;
      if (ROLE_ACCOUNTS.test(local) || BOT_LOCAL.test(local) || SAFE_DOMAINS.test(domain) || ASSET.test(domain) || /^\d+(\.\d+)*$/.test(local) || local.includes("{")) continue;
      // user:password@host in connection strings is not an email address.
      if (/:\/\/[^\s"'@]*$/.test(line.slice(0, m.index + local.length))) continue;
      // Version strings like name@1.2.3 and package refs like @scope/pkg are not emails.
      if (/^\d/.test(domain)) continue;
      push("email address", maskEmail(local, domain), "low");
    }
    const lower = line.toLowerCase();
    if (/(phone|mobile|tel|contact|whatsapp|\+91)/.test(lower)) {
      PHONE_IN.lastIndex = 0;
      while ((m = PHONE_IN.exec(line))) {
        const digits = m[1].replace(/\D/g, "").slice(-10);
        if (/^(\d)\1{9}$/.test(digits) || digits === "9876543210" || digits === "9123456789") continue; // obvious placeholders
        push("phone number", maskDigits(m[1]), "low");
      }
    }
    if (/(aadhaar|aadhar|uid)/.test(lower)) {
      AADHAAR.lastIndex = 0;
      while ((m = AADHAAR.exec(line))) {
        const digits = m[1].replace(/\D/g, "");
        if (/^(\d)\1+$/.test(digits) || digits === "123412341234") continue;
        push("Aadhaar-like number", maskDigits(m[1]), "medium");
      }
    }
  });
  return out;
}
