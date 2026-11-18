import type { Finding, Processor } from "../types.ts";
import type { SourceFile } from "../walk.ts";
import { vendorForPackage, vendorForUrl, type Vendor } from "../vendors.ts";
import { DPDP } from "../dpdp.ts";

interface Dep {
  name: string;
  file: string;
  line?: number;
}

const lineOf = (text: string, needle: string) => {
  const idx = text.indexOf(needle);
  return idx < 0 ? undefined : text.slice(0, idx).split("\n").length;
};

/** Reads dependency names from common manifest formats. Best effort: no full TOML/XML/Gradle parsing. */
export function parseManifest(file: SourceFile): Dep[] {
  const name = file.rel.split("/").pop() ?? "";
  const deps: Dep[] = [];
  const add = (n: string) => n && deps.push({ name: n, file: file.rel, line: lineOf(file.text, n) });
  try {
    if (name === "package.json") {
      const j = JSON.parse(file.text) as Record<string, Record<string, string> | undefined>;
      for (const k of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]) Object.keys(j[k] ?? {}).forEach(add);
    } else if (name === "composer.json") {
      const j = JSON.parse(file.text) as { require?: Record<string, string> };
      Object.keys(j.require ?? {}).forEach(add);
    } else if (/^requirements.*\.txt$/.test(name)) {
      for (const l of file.text.split(/\r?\n/)) {
        const m = l.trim().match(/^([A-Za-z0-9_.-]+)(\[[^\]]*\])?\s*([<>=!~;].*)?$/);
        if (m && !l.trim().startsWith("#") && !l.trim().startsWith("-")) add(m[1]);
      }
    } else if (name === "pyproject.toml" || name === "Pipfile") {
      for (const m of file.text.matchAll(/^\s*["']?([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*(?:[<>=!~^]|["']\s*[,\]]|\s*=\s*["{])/gm)) add(m[1]);
    } else if (name === "Gemfile") {
      for (const m of file.text.matchAll(/^\s*gem\s+["']([^"']+)["']/gm)) add(m[1]);
    } else if (name === "go.mod") {
      for (const m of file.text.matchAll(/^\s*(?:require\s+)?([a-z0-9.-]+\.[a-z]+\/[^\s]+)\s+v\d/gm)) add(m[1]);
    } else if (/^build\.gradle(\.kts)?$/.test(name)) {
      for (const m of file.text.matchAll(/(?:implementation|api|compile)\s*\(?\s*["']([^:"']+):([^:"']+)/g)) add(`${m[1]}:${m[2]}`);
    } else if (name === "pom.xml") {
      for (const m of file.text.matchAll(/<artifactId>([^<]+)<\/artifactId>/g)) add(m[1]);
    } else if (name === "pubspec.yaml") {
      const block = file.text.split(/^dependencies:\s*$/m)[1]?.split(/^\S/m)[0] ?? "";
      for (const m of block.matchAll(/^\s{2}([a-z0-9_]+):/gm)) add(m[1]);
    }
  } catch {
    // Malformed manifest: skip it rather than fail the scan.
  }
  return deps;
}

const MANIFESTS = /(^|\/)(package\.json|composer\.json|requirements[^/]*\.txt|pyproject\.toml|Pipfile|Gemfile|go\.mod|build\.gradle(\.kts)?|pom\.xml|pubspec\.yaml)$/;
// Path stops at template placeholders (${...}) so reported URLs stay readable.
const URL_IN_CODE = /(?:https?:)?\/\/[a-z0-9.-]+\.[a-z]{2,}(?:\/[^\s"'`<>()${}]*)?/gi;

export function findProcessors(files: SourceFile[]): Processor[] {
  const found = new Map<string, Processor>();
  const note = (v: Vendor, ev: Processor["evidence"][number]) => {
    const p = found.get(v.id) ?? { id: v.id, vendor: v.vendor, category: v.category, dataTypically: v.dataTypically, evidence: [] };
    if (!p.evidence.some((e) => e.detail === ev.detail && e.file === ev.file)) p.evidence.push(ev);
    found.set(v.id, p);
  };

  for (const f of files) {
    if (MANIFESTS.test(f.rel)) {
      for (const d of parseManifest(f)) {
        const v = vendorForPackage(d.name);
        if (v) note(v, { kind: "dependency", detail: d.name, file: d.file, line: d.line });
      }
      continue;
    }
    if (f.isTest || /\.(md|txt|lock)$/i.test(f.rel)) continue;
    f.text.split(/\r?\n/).forEach((line, i) => {
      if (line.length > 3000 || !line.includes("//")) return;
      URL_IN_CODE.lastIndex = 0;
      for (const m of line.match(URL_IN_CODE) ?? []) {
        const v = vendorForUrl(m);
        if (v) note(v, { kind: "code-reference", detail: m.replace(/^\/\//, "https://").slice(0, 120), file: f.rel, line: i + 1 });
      }
    });
  }
  return [...found.values()].sort((a, b) => a.category.localeCompare(b.category) || a.vendor.localeCompare(b.vendor));
}

export function processorFindings(processors: Processor[]): Finding[] {
  return processors.map((p) => {
    const first = p.evidence[0];
    return {
      id: `third-party-processor:${p.id}`,
      rule: "third-party-processor" as const,
      title: `Third-party service receives data: ${p.vendor} (${p.category})`,
      severity: "info" as const,
      confidence: first.kind === "dependency" ? ("high" as const) : ("medium" as const),
      location: { file: first.file, line: first.line ?? 1, snippet: first.detail },
      evidence: p.evidence.map((e) => `${e.detail} (${e.file}${e.line ? `:${e.line}` : ""})`).slice(0, 5).join("; "),
      why: `${p.vendor} typically receives: ${p.dataTypically}. Users must be told about it, and you need a contract (DPA) with the vendor.`,
      recommendation:
        "List this vendor in your data inventory and privacy notice, sign or accept its data processing agreement, check where it stores data, and send it only the fields it needs.",
      dpdp: [DPDP.processor, DPDP.notice, DPDP.transfer],
    };
  });
}
