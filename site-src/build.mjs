// Builds the static website into docs/ (served by GitHub Pages).
// Usage: node site-src/build.mjs
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const out = path.join(here, "..", "docs");

const CONTACT_EMAIL = "shreerajjadhav19@gmail.com";
const REPO = "https://github.com/Shriraj1901/dpdp-ready";

// HTML character references: browsers show the address normally; naive scrapers don't see "@".
const entities = (s) => [...s].map((c) => `&#${c.codePointAt(0)};`).join("");

function mailto(subject, body) {
  const q = `?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
  return entities(`mailto:${CONTACT_EMAIL}`) + q.replace(/&/g, "&amp;");
}

const replacements = {
  "{{REPO}}": REPO,
  "{{EMAIL_HTML}}": `<a href="${entities(`mailto:${CONTACT_EMAIL}`)}">${entities(CONTACT_EMAIL)}</a>`,
  "{{MAILTO_HELLO}}": mailto("Hello from the DPDP Ready website", ""),
  "{{MAILTO_ASSESS}}": mailto(
    "DPDP readiness assessment request",
    [
      "Hi,",
      "",
      "I'd like a DPDP engineering readiness assessment.",
      "",
      "Company / website:",
      "What the app does:",
      "Main tech stack:",
      "Approx. number of users:",
      "Best time for a 20-minute call:",
      "",
      "Thanks,",
    ].join("\n"),
  ),
};

fs.mkdirSync(out, { recursive: true });
for (const file of ["index.html", "privacy.html"]) {
  let html = fs.readFileSync(path.join(here, file), "utf8");
  for (const [k, v] of Object.entries(replacements)) html = html.split(k).join(v);
  const left = html.match(/\{\{[A-Z_]+\}\}/g);
  if (left) throw new Error(`${file}: unreplaced placeholders ${left.join(", ")}`);
  fs.writeFileSync(path.join(out, file), html);
}
fs.copyFileSync(path.join(here, "styles.css"), path.join(out, "styles.css"));
fs.writeFileSync(path.join(out, ".nojekyll"), "");
console.log(`Site built into ${path.relative(process.cwd(), out) || out}`);
