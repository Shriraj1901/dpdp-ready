import type { Finding, InventoryItem, Location } from "../types.ts";
import type { SourceFile } from "../walk.ts";
import { snippetOf } from "../walk.ts";
import { DPDP } from "../dpdp.ts";

export interface PiiType {
  id: string;
  label: string;
  sensitive: boolean;
  /** Each phrase is a token sequence that must appear contiguously in the identifier. */
  phrases: string[][];
  /** Identifier is ignored if it contains any of these tokens. */
  exclude?: string[];
}

const p = (...xs: string[]) => xs.map((x) => x.split("_"));

/** Order matters: the first matching type wins (email_address is email, not postal address). */
export const PII_TYPES: PiiType[] = [
  { id: "email", label: "Email address", sensitive: false, phrases: p("email", "e_mail"), exclude: ["template", "verified", "sent", "enabled", "provider", "service", "smtp", "subject", "body"] },
  { id: "phone", label: "Phone number", sensitive: false, phrases: p("phone", "mobile", "msisdn", "whatsapp", "contact_number", "tel"), exclude: ["breakpoint", "layout", "view", "app", "menu", "nav", "verified"] },
  { id: "aadhaar", label: "Aadhaar number", sensitive: true, phrases: p("aadhaar", "aadhar", "uidai") },
  { id: "pan", label: "PAN", sensitive: true, phrases: p("pan_number", "pan_no", "pan_card", "pan_id") },
  { id: "government_id", label: "Government ID (passport, voter ID, licence)", sensitive: true, phrases: p("passport", "voter_id", "driving_licence", "driving_license", "national_id"), exclude: ["js", "strategy", "strategies", "jwt", "local", "oauth", "google", "microsoft", "auth", "module", "service"] },
  { id: "date_of_birth", label: "Date of birth / age", sensitive: false, phrases: p("dob", "date_of_birth", "birth_date", "birthdate", "birthday", "age"), exclude: ["max", "min", "cache", "stale", "cookie", "session", "token", "page", "storage"] },
  { id: "gender", label: "Gender", sensitive: false, phrases: p("gender", "sex") },
  { id: "name", label: "Person's name", sensitive: false, phrases: p("first_name", "last_name", "full_name", "middle_name", "firstname", "lastname", "fullname", "surname", "father_name", "mother_name", "customer_name", "contact_name") },
  { id: "postal_address", label: "Postal address", sensitive: false, phrases: p("address", "street", "pincode", "pin_code", "zip_code", "zipcode", "postal_code", "postcode"), exclude: ["ip", "mac", "wallet", "contract", "server", "web", "url", "host", "bind", "listen", "memory", "base", "node", "remote", "email", "e", "mail", "bar"] },
  { id: "location", label: "Precise location", sensitive: false, phrases: p("latitude", "longitude", "lat", "lng", "geolocation", "geo_location", "gps", "coordinates") },
  { id: "ip_address", label: "IP address", sensitive: false, phrases: p("ip", "ip_address", "ipaddress", "remote_addr", "client_ip") },
  { id: "device_id", label: "Device / advertising identifier", sensitive: false, phrases: p("device_id", "imei", "advertising_id", "idfa", "gaid", "fcm_token", "push_token", "device_token") },
  { id: "credentials", label: "Credentials (password / OTP)", sensitive: false, phrases: p("password", "passwd", "pwd", "otp", "security_answer"), exclude: ["reset", "forgot", "show", "toggle", "visible", "label", "placeholder", "policy", "strength", "min", "max", "length"] },
  { id: "financial", label: "Financial data (card, bank, UPI, income)", sensitive: true, phrases: p("card_number", "cardnumber", "cvv", "cvc", "bank_account", "account_number", "ifsc", "upi", "upi_id", "vpa", "salary", "income", "credit_score", "cibil") },
  { id: "health", label: "Health data", sensitive: true, phrases: p("health", "medical", "diagnosis", "blood_group", "prescription", "allergies", "allergy", "disability", "medication"), exclude: ["check", "checks", "status", "endpoint", "probe", "url", "path", "monitor", "wellness", "fitness", "industry", "category", "sector"] },
  { id: "biometric", label: "Biometric data", sensitive: true, phrases: p("biometric", "fingerprint", "face_id", "face_embedding", "face_template", "selfie"), exclude: ["api", "key", "ssh", "cert", "certificate", "hash", "sha", "gpg", "pgp", "tls", "browser", "device", "file", "content", "build"] },
  // Not "child"/"children": React's children prop and DOM childNodes would flood results.
  { id: "children", label: "Children's data / parental consent", sensitive: true, phrases: p("is_minor", "guardian", "parental", "parent_consent", "is_child", "child_name", "child_dob", "child_age", "under_18", "under18"), exclude: ["folder", "node", "element", "component", "item", "route", "process", "page", "menu", "row", "task", "category", "comment", "entity", "workspace", "record", "object", "view", "tab"] },
  { id: "religion_caste", label: "Religion / caste", sensitive: true, phrases: p("religion", "caste") },
  { id: "photo", label: "Photo of a person", sensitive: false, phrases: p("photo", "avatar", "profile_picture", "profile_image", "profile_photo") },
];

/** "userEmailAddress" → ["user","email","address"]; "DATE_OF_BIRTH" → ["date","of","birth"]. */
export function tokenize(identifier: string): string[] {
  return identifier
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

function hasPhrase(tokens: string[], phrase: string[]): boolean {
  outer: for (let i = 0; i + phrase.length <= tokens.length; i++) {
    for (let j = 0; j < phrase.length; j++) if (tokens[i + j] !== phrase[j]) continue outer;
    return true;
  }
  return false;
}

const classifyCache = new Map<string, PiiType | null>();

/** Identifiers repeat heavily across a codebase, so results are cached. */
export function classifyIdentifier(identifier: string): PiiType | null {
  let r = classifyCache.get(identifier);
  if (r === undefined) {
    r = classifyUncached(identifier);
    if (classifyCache.size < 500_000) classifyCache.set(identifier, r);
  }
  return r;
}

const IDENT = /[A-Za-z_$][\w$]*/g;

/** True if any identifier on the line could be personal data. Lets most lines skip the definition patterns. */
export function lineMentionsPii(line: string): boolean {
  IDENT.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = IDENT.exec(line))) if (classifyIdentifier(m[0])) return true;
  return /type\s*=\s*\{?["'](email|tel)["']/.test(line);
}

function classifyUncached(identifier: string): PiiType | null {
  const tokens = tokenize(identifier);
  if (tokens.length === 0 || tokens.length > 6) return null;
  for (const t of PII_TYPES) {
    if (t.phrases.some((ph) => hasPhrase(tokens, ph))) {
      // Excluded here (e.g. "ip_address" is not a postal address): let a later type claim it.
      if (t.exclude?.some((x) => tokens.includes(x))) continue;
      return t;
    }
  }
  return null;
}

/**
 * Lines where an identifier is *defined* (schema column, model field, object key, form field).
 * Matching only definitions keeps noise low compared with matching every mention.
 */
const DEFINITION_PATTERNS: RegExp[] = [
  // Object keys, TS/Python typed fields, YAML/JSON keys: email: / "email": / email?:
  /(?:^|[\s{,(])["']?([A-Za-z_$][\w$]*)["']?\s*\??\s*:(?!:)/g,
  // Prisma / GraphQL fields: email String
  /^\s*([A-Za-z_]\w*)\s+(?:String|Int|BigInt|DateTime|Boolean|Json|Float|Decimal|Bytes|ID)\b/g,
  // SQL columns: email varchar(255)
  /^\s*["`]?([A-Za-z_]\w*)["`]?\s+(?:varchar|character varying|text|char|int|integer|bigint|smallint|date|timestamp|timestamptz|boolean|bool|uuid|jsonb?|numeric|decimal|bytea|blob|nvarchar)\b/gi,
  // ORM model assignments: email = models.EmailField(...) / Column(...) / Field(...) / z.string()
  /^\s*([A-Za-z_]\w*)\s*[:=]\s*(?:models\.|Column\(|mapped_column|db\.Column|fields\.|Field\(|serializers\.|sa\.Column|z\.|DataTypes\.|Sequelize\.)/g,
  // HTML / JSX form fields
  /\bname\s*=\s*\{?["']([\w.[\]-]+)["']/g,
  // Java / C# fields: private String email;
  /\b(?:private|public|protected|internal)\s+(?:static\s+|final\s+|readonly\s+)*[\w<>[\],.?]+\s+([a-zA-Z_]\w*)\s*[;={]/g,
  // Kotlin / Swift / Dart: val email: / var email: / final String email;
  /\b(?:val|var|let)\s+([a-zA-Z_]\w*)\s*:/g,
];

const INPUT_TYPE = /\btype\s*=\s*\{?["'](email|tel)["']/g;

export interface PiiHit {
  type: PiiType;
  identifier: string;
  location: Location;
}

// Dependency manifests list package names ("passport", "react-phone-input"), not data fields.
const MANIFEST = /(^|\/)(package\.json|composer\.json|requirements[^/]*\.txt|pyproject\.toml|Pipfile|Gemfile|go\.mod|pom\.xml|build\.gradle(\.kts)?|pubspec\.yaml|tsconfig[^/]*\.json)$/;

export function findPiiDefinitions(file: SourceFile): PiiHit[] {
  if (/\.(md|txt)$/i.test(file.rel) || MANIFEST.test(file.rel)) return [];
  const hits: PiiHit[] = [];
  const lines = file.text.split(/\r?\n/);
  lines.forEach((line, i) => {
    if (line.length > 2000 || !lineMentionsPii(line)) return;
    const seen = new Set<string>();
    const add = (type: PiiType, identifier: string) => {
      if (seen.has(type.id)) return;
      seen.add(type.id);
      hits.push({ type, identifier, location: { file: file.rel, line: i + 1, snippet: snippetOf(line) } });
    };
    for (const re of DEFINITION_PATTERNS) {
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(line))) {
        // "medicalDevices: '5d6a3933-…'" maps a name to an ID constant; it is not a data field.
        if (/^\s*\??\s*:\s*["'`][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["'`]/i.test(line.slice(m.index + m[0].length - 1))) continue;
        const t = classifyIdentifier(m[1]);
        if (t) add(t, m[1]);
      }
    }
    INPUT_TYPE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = INPUT_TYPE.exec(line))) {
      const t = PII_TYPES.find((x) => x.id === (m![1] === "email" ? "email" : "phone"))!;
      add(t, `type="${m[1]}"`);
    }
  });
  return hits;
}

export function buildInventory(hits: PiiHit[], maxLocations = 25): InventoryItem[] {
  const byType = new Map<string, PiiHit[]>();
  for (const h of hits) byType.set(h.type.id, [...(byType.get(h.type.id) ?? []), h]);
  return PII_TYPES.filter((t) => byType.has(t.id)).map((t) => {
    const hs = byType.get(t.id)!;
    return {
      type: t.id,
      label: t.label,
      sensitive: t.sensitive,
      count: hs.length,
      files: new Set(hs.map((h) => h.location.file)).size,
      locations: hs.slice(0, maxLocations).map((h) => h.location),
    };
  });
}

const SENSITIVE_ADVICE: Record<string, string> = {
  aadhaar: "Store Aadhaar only if a law allows you to; prefer masked or tokenised references (e.g. last 4 digits).",
  pan: "Collect PAN only where needed (e.g. tax, KYC); mask it in UIs and logs.",
  government_id: "Keep ID documents and numbers in restricted, encrypted storage with a defined retention period.",
  financial: "Never store card numbers or CVV yourself; use your payment gateway's tokens. Encrypt bank and UPI details.",
  health: "Limit access to health data to people who need it and encrypt it at rest.",
  biometric: "Check that biometric data is truly necessary; store templates encrypted and separately from identity data.",
  children: "If users may be under 18, you need verifiable parental consent and must avoid tracking or targeted ads for them.",
  religion_caste: "Collect only if essential to the service; restrict access and encrypt.",
};

/** One finding per sensitive data type, pointing at its first location. */
export function sensitiveFindings(inventory: InventoryItem[]): Finding[] {
  return inventory
    .filter((i) => i.sensitive)
    .map((i) => ({
      id: `sensitive-personal-data:${i.type}`,
      rule: "sensitive-personal-data" as const,
      title: `Sensitive personal data in code: ${i.label}`,
      severity: "low" as const,
      confidence: "medium" as const,
      location: i.locations[0],
      evidence: `${i.count} field definition(s) in ${i.files} file(s), e.g. ${i.locations[0].file}:${i.locations[0].line}`,
      why: "Higher-risk personal data increases the impact of a breach and usually needs stronger safeguards and a clear purpose.",
      recommendation: `${SENSITIVE_ADVICE[i.type] ?? "Confirm the purpose, restrict access and encrypt."} Document why it is collected and how long it is kept.`,
      dpdp: i.type === "children" ? [DPDP.children, DPDP.security] : [DPDP.minimisation, DPDP.security, DPDP.erasure],
    }));
}
