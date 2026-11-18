import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { scan } from "../src/scan.ts";
import { toMarkdown } from "../src/report/markdown.ts";
import { toSarif } from "../src/report/sarif.ts";
import { main } from "../src/cli.ts";

let dir: string;
const FAKE_AWS = "AKIA" + "Q7ZT4N2LX9WR3B5K";

function write(rel: string, text: string) {
  const p = path.join(dir, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, text);
}

before(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "dpdp-ready-test-"));
  write(".gitignore", "ignored/\n.env.local\n");
  write("package.json", JSON.stringify({ dependencies: { "@sentry/node": "^8", razorpay: "^2" } }));
  write("prisma/schema.prisma", "model User {\n  id Int @id\n  email String @unique\n  mobile String\n  aadhaarNumber String?\n}\n");
  write("src/signup.ts", `export async function signup(user: { email: string }) {\n  console.log(\`new signup \${user.email}\`);\n  const key = "${FAKE_AWS}";\n}\n`);
  write("src/__tests__/signup.test.ts", 'const user = { email: "a@b.in", panNumber: "x" };\n');
  write("ignored/secret.ts", `const key = "${FAKE_AWS}";\n`);
  write(".env.local", `AWS_KEY=${FAKE_AWS}\n`);
  write("node_modules/lib/index.js", `const key = "${FAKE_AWS}";\n`);
});

after(() => fs.rmSync(dir, { recursive: true, force: true }));

test("end-to-end code scan", async () => {
  const r = await scan({ root: dir });
  assert.equal(r.root, path.basename(dir), "report must not contain the full local path");
  const types = r.inventory.map((i) => i.type);
  assert.deepEqual(types, ["email", "phone", "aadhaar"]);
  assert.ok(!r.inventory.some((i) => i.locations.some((l) => l.file.includes("__tests__"))), "test files are not part of the inventory");
  assert.ok(!types.includes("pan"), "PAN only appears in a test file");

  const rules = r.findings.map((f) => `${f.rule}@${f.location?.file ?? ""}`);
  assert.ok(rules.includes("secret-in-code@src/signup.ts"));
  assert.ok(rules.includes("personal-data-in-logs@src/signup.ts"));
  assert.ok(rules.includes("sensitive-personal-data@prisma/schema.prisma"));
  assert.ok(!rules.some((x) => x.includes("ignored/") || x.includes("node_modules") || x.includes(".env.local")), "gitignored and dependency folders are skipped");
  assert.deepEqual(r.processors.map((p) => p.id).sort(), ["razorpay", "sentry"]);
  assert.equal(r.findings[0].severity, "high", "findings sorted by severity");
  assert.ok(r.limitations.at(-1)!.includes("not a legal opinion"));

  const md = toMarkdown(r);
  for (const h of ["## Personal data inventory", "## Third-party services", "## Findings", "## Limitations"]) assert.ok(md.includes(h), h);
  assert.ok(!md.includes(FAKE_AWS), "Markdown report must not contain the secret");

  const sarif = toSarif(r) as { version: string; runs: { results: { ruleId: string; locations: { physicalLocation: { artifactLocation: { uri: string } } }[] }[]; tool: { driver: { rules: { id: string }[] } } }[] };
  assert.equal(sarif.version, "2.1.0");
  const run = sarif.runs[0];
  assert.ok(run.results.length > 0);
  const ruleIds = new Set(run.tool.driver.rules.map((x) => x.id));
  assert.ok(run.results.every((x) => ruleIds.has(x.ruleId)), "every result references a declared rule");
  assert.ok(run.results.every((x) => !x.locations[0].physicalLocation.artifactLocation.uri.includes("\\")), "SARIF paths use forward slashes");
  assert.ok(!JSON.stringify(sarif).includes(FAKE_AWS));
});

test("CLI: usage errors, website authorisation and --fail-on", async () => {
  const quiet = console.log;
  const quietErr = console.error;
  console.log = () => {};
  console.error = () => {};
  try {
    assert.equal(await main([]), 2);
    assert.equal(await main(["scan", dir, "--website", "https://example.com"]), 2, "website scan needs --authorized");
    assert.equal(await main(["scan", dir, "--fail-on", "bogus"]), 2);
    assert.equal(await main(["scan", path.join(dir, "nope")]), 2);
    const md = path.join(dir, "out", "report.md");
    assert.equal(await main(["scan", dir, "--quiet", "--fail-on", "high", "--md", md]), 1, "a committed secret fails the build");
    assert.ok(fs.existsSync(md));
    assert.equal(await main(["scan", path.join(dir, "prisma"), "--quiet", "--fail-on", "high"]), 0);
  } finally {
    console.log = quiet;
    console.error = quietErr;
  }
});

test("website scan against a local test site", async () => {
  const pages: Record<string, string> = {
    "/": `<html><head><script async src="https://www.googletagmanager.com/gtag/js?id=G-1"></script>
      <script>!function(f,b,e,v,n,t,s){}(window,document,'script','https://connect.facebook.net/en_US/fbevents.js');</script>
      <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter"></head>
      <body><form><input type="email" name="email"><input name="phone"></form>
      <footer><a href="/legal/privacy">Privacy Policy</a></footer></body></html>`,
    "/legal/privacy": `<html><body><h1>Privacy</h1><p>${"We respect your privacy. ".repeat(30)}
      Information we collect: name, email. We use it for the purpose of providing the service.
      You may withdraw your consent at any time. Contact our Grievance Officer at privacy@site.in.</p></body></html>`,
  };
  const server = http.createServer((req, res) => {
    const body = pages[req.url ?? "/"];
    if (!body) return void res.writeHead(404).end();
    const headers: Record<string, string | string[]> = { "content-type": "text/html" };
    if (req.url === "/") headers["set-cookie"] = ["_ga=GA1.1.123; Path=/", "session=abc; HttpOnly"];
    res.writeHead(200, headers).end(body);
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as AddressInfo).port;
  try {
    const r = await scan({ root: path.join(dir, "prisma"), website: `http://127.0.0.1:${port}/` });
    const w = r.website!;
    assert.ok(w, "website result present");
    assert.equal(w.privacyNoticeUrl, `http://127.0.0.1:${port}/legal/privacy`);
    assert.deepEqual(w.cookiesOnLoad, ["_ga", "session"]);
    assert.deepEqual(w.formsCollecting.sort(), ["email", "phone"]);
    const vendors = [...new Set(w.thirdParties.map((t) => t.vendor).filter(Boolean))].sort();
    // The Meta pixel is only referenced inside an inline script, so this also checks inline detection.
    assert.deepEqual(vendors, ["Google Analytics / Tag Manager", "Google Fonts", "Meta (Facebook) Pixel / SDK"]);
    const found = Object.fromEntries(w.noticeSignals.map((s) => [s.id, s.found]));
    assert.equal(found["withdraw-consent"], true);
    assert.equal(found["grievance"], true);
    assert.equal(found["board"], false);
    const rules = r.findings.map((f) => f.rule);
    for (const rule of ["web-no-https", "web-trackers", "web-cookies-on-load", "web-notice-gaps"]) assert.ok(rules.includes(rule as never), rule);
    assert.equal(r.findings.find((f) => f.rule === "web-trackers")!.severity, "medium", "no consent tool → medium");
  } finally {
    server.close();
  }
});
