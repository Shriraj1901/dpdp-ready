import fs from "node:fs";
import path from "node:path";

export interface SourceFile {
  /** Relative path with forward slashes. */
  rel: string;
  abs: string;
  text: string;
  isTest: boolean;
}

const IGNORED_DIRS = new Set([
  ".git", "node_modules", ".next", ".nuxt", "dist", "build", "out", "coverage", ".turbo", ".cache",
  "vendor", "venv", ".venv", "env", "__pycache__", ".pytest_cache", "target", "bin", "obj", ".gradle",
  ".idea", ".vscode", "Pods", ".dart_tool", ".expo", "storybook-static", ".svelte-kit", ".vercel",
]);

const TEXT_EXT = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro", ".html", ".htm",
  ".py", ".rb", ".go", ".java", ".kt", ".kts", ".php", ".cs", ".swift", ".dart", ".scala", ".rs",
  ".sql", ".prisma", ".graphql", ".gql", ".yaml", ".yml", ".json", ".toml", ".xml", ".gradle",
  ".env", ".properties", ".ini", ".cfg", ".conf", ".txt", ".md",
]);

const SPECIAL_NAMES = new Set(["Gemfile", "Dockerfile", "go.mod", "requirements.txt", "Pipfile"]);

const SKIP_FILES = [/\.min\.(js|css)$/, /\.map$/, /(^|\/)package-lock\.json$/, /(^|\/)pnpm-lock\.yaml$/, /(^|\/)yarn\.lock$/, /(^|\/)composer\.lock$/, /(^|\/)Gemfile\.lock$/, /(^|\/)poetry\.lock$/, /(^|\/)go\.sum$/];

/** Tests, mocks, seed/demo data and stories: fake data by design, so they are kept out of the inventory and low-precision checks. */
export const TEST_PATH =
  /(^|\/)(test|tests|__tests__|spec|specs|fixtures?|mocks?|__mocks__|mock[-_]?data|testing|test[-_]?utils|test[-_]?helpers|[\w-]*[-_](e2e|testing)(?:[-_][\w-]*)?|e2e|cypress|playwright|examples?|samples?|seeds?|seeders?|[\w-]*[-_]seeder|seed[-_]?data|demo[-_]?data|fake[-_]?data|testdata|__stories__|stories|storybook)(\/|$)|[.-](test|spec|stories|story|mock|fixture|test-support|e2e)\.\w+$|(^|\/)(test|mock|fake)[-_][\w-]*\.\w+$/i;

const MAX_BYTES = 1_000_000;

/** Very small .gitignore support: plain names, dir/ entries, *.ext and leading-slash paths. Negations are ignored. */
export function parseGitignore(text: string): ((rel: string, isDir: boolean) => boolean) {
  const rules: { re: RegExp; dirOnly: boolean }[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith("!")) continue;
    const dirOnly = line.endsWith("/");
    let pat = line.replace(/\/$/, "");
    const anchored = pat.startsWith("/") || pat.includes("/");
    pat = pat.replace(/^\//, "");
    const body = pat
      .split("")
      .map((c) => (c === "*" ? "[^/]*" : c === "?" ? "[^/]" : /[.+^${}()|[\]\\]/.test(c) ? `\\${c}` : c))
      .join("")
      .replace(/\[\^\/\]\*\[\^\/\]\*/g, ".*");
    const re = anchored ? new RegExp(`^${body}(/|$)`) : new RegExp(`(^|/)${body}(/|$)`);
    rules.push({ re, dirOnly });
  }
  return (rel, isDir) => rules.some((r) => (!r.dirOnly || isDir) && r.re.test(rel));
}

export function walk(root: string): { files: SourceFile[]; skipped: number } {
  const files: SourceFile[] = [];
  let skipped = 0;
  const gi = fs.existsSync(path.join(root, ".gitignore")) ? parseGitignore(fs.readFileSync(path.join(root, ".gitignore"), "utf8")) : () => false;

  const visit = (dir: string) => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const abs = path.join(dir, e.name);
      const rel = path.relative(root, abs).split(path.sep).join("/");
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) {
        if (IGNORED_DIRS.has(e.name) || gi(rel, true)) continue;
        visit(abs);
        continue;
      }
      if (!e.isFile()) continue;
      const ext = path.extname(e.name).toLowerCase();
      const isEnv = /^\.env(\..+)?$/.test(e.name);
      if (!(TEXT_EXT.has(ext) || SPECIAL_NAMES.has(e.name) || isEnv) || SKIP_FILES.some((r) => r.test(rel)) || gi(rel, false)) {
        skipped++;
        continue;
      }
      let size = 0;
      try {
        size = fs.statSync(abs).size;
      } catch {
        continue;
      }
      if (size > MAX_BYTES) {
        skipped++;
        continue;
      }
      const text = fs.readFileSync(abs, "utf8");
      if (text.includes("\u0000")) {
        skipped++;
        continue;
      }
      files.push({ rel, abs, text, isTest: TEST_PATH.test(rel) });
    }
  };
  visit(root);
  files.sort((a, b) => a.rel.localeCompare(b.rel));
  return { files, skipped };
}

export function snippetOf(line: string, max = 160): string {
  const t = line.trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}
