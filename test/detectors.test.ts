import { test } from "node:test";
import assert from "node:assert/strict";
import { classifyIdentifier, findPiiDefinitions, tokenize } from "../src/detectors/pii.ts";
import { findSecrets, mask } from "../src/detectors/secrets.ts";
import { findPiiInLogs, stripStringLiterals } from "../src/detectors/logs.ts";
import { findHardcodedPersonalData } from "../src/detectors/hardcoded.ts";
import { parseManifest, findProcessors } from "../src/detectors/processors.ts";
import { vendorForPackage, vendorForUrl } from "../src/vendors.ts";
import { parseGitignore, type SourceFile } from "../src/walk.ts";

const file = (rel: string, text: string, isTest = false): SourceFile => ({ rel, abs: rel, text, isTest });
// Built at runtime so this repository never contains secret-shaped strings.
const FAKE_AWS = "AKIA" + "Q7ZT4N2LX9WR3B5K";
const FAKE_GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";

test("tokenize splits camelCase, snake_case and acronyms", () => {
  assert.deepEqual(tokenize("userEmailAddress"), ["user", "email", "address"]);
  assert.deepEqual(tokenize("DATE_OF_BIRTH"), ["date", "of", "birth"]);
  assert.deepEqual(tokenize("customerIPAddress"), ["customer", "ip", "address"]);
});

test("classifyIdentifier maps names to data types and avoids common false positives", () => {
  const cases: [string, string | null][] = [
    ["email", "email"], ["userEmailAddress", "email"], ["mobileNumber", "phone"], ["aadhaarNumber", "aadhaar"],
    ["panNumber", "pan"], ["dateOfBirth", "date_of_birth"], ["first_name", "name"], ["billingAddress", "postal_address"],
    ["ip_address", "ip_address"], ["cardNumber", "financial"], ["upiId", "financial"], ["bloodGroup", "health"],
    ["guardianConsent", "children"], ["password", "credentials"],
    // Should NOT be personal data:
    ["mac_address", null], ["healthCheck", null], ["maxAge", null], ["children", null], ["panel", null],
    ["emailTemplate", null], ["showPassword", null], ["kid", null], ["company", null], ["minorVersion", null],
  ];
  for (const [id, want] of cases) assert.equal(classifyIdentifier(id)?.id ?? null, want, id);
});

test("findPiiDefinitions reads schemas, models and forms in several languages", () => {
  const sample = [
    "model User {",
    "  email      String @unique", // Prisma
    "  phone      String?",
    "}",
    "CREATE TABLE kyc (aadhaar_number varchar(12), pan_no text);",
    "  date_of_birth DATE,",
    'class Patient(models.Model):\n    diagnosis = models.TextField()', // Django
    '<input type="tel" name="contact" />',
    "private String passportNumber;", // Java
    "val upiId: String", // Kotlin
    "const x = { children: props.children, maxAge: 3600 };", // must not match
  ].join("\n");
  const hits = findPiiDefinitions(file("src/schema.txt.ts", sample));
  const types = new Set(hits.map((h) => h.type.id));
  for (const t of ["email", "phone", "date_of_birth", "health", "government_id", "financial"]) assert.ok(types.has(t), `missing ${t}`);
  assert.ok(!types.has("children"));
  assert.ok(!types.has("date_of_birth") || hits.filter((h) => h.type.id === "date_of_birth").every((h) => !h.location.snippet.includes("maxAge")));
  // SQL single-line CREATE TABLE has columns mid-line; the line-start SQL pattern catches the second form only.
  assert.ok(hits.some((h) => h.location.line === 6 && h.type.id === "date_of_birth"));
});

test("findSecrets detects real patterns, masks them, and skips placeholders", () => {
  const text = [
    `const aws = "${FAKE_AWS}";`,
    `token: "${FAKE_GH}"`,
    "-----BEGIN RSA " + "PRIVATE KEY-----",
    'DB_PASSWORD = "S3cure!Passw0rd#2026"',
    'apiKey: process.env.API_KEY',
    'password: "changeme123"',
    'const secret = "your_secret_here"',
    'awsKey = "AKIAIOSFODNN7EXAMPLE"',
  ].join("\n");
  const f = findSecrets(file("src/config.ts", text));
  assert.deepEqual(f.map((x) => x.location!.line), [1, 2, 3, 4]);
  assert.ok(f.every((x) => x.severity === "high"));
  assert.ok(!f[0].location!.snippet.includes(FAKE_AWS), "secret must be masked in snippet");
  assert.ok(!f[0].evidence.includes(FAKE_AWS.slice(6)), "secret must be masked in evidence");
  assert.match(mask("abcdefghijklmnop"), /^abcd\*+ \(16 chars\)$/);
});

test("stripStringLiterals keeps template expressions only", () => {
  assert.equal(stripStringLiterals('log("Email sent to", x)').includes("Email"), false);
  assert.ok(stripStringLiterals("log(`to ${user.email}`)").includes("user.email"));
});

test("findPiiInLogs flags personal data passed to loggers, not words inside messages", () => {
  const text = [
    'console.log("Email sent");',
    "console.log(`Signup ${user.email} ${user.phone}`);",
    "logger.info('otp', otp)",
    "print(f\"hello\")",
    "logging.debug(customer.aadhaar_number)",
  ].join("\n");
  const f = findPiiInLogs(file("src/a.ts", text));
  assert.deepEqual(f.map((x) => [x.location!.line, x.severity]), [[2, "medium"], [3, "high"], [5, "high"]]);
});

test("findHardcodedPersonalData ignores role accounts, safe domains and tests", () => {
  const text = [
    'const owner = "fixture.person.dpdp-test@gmail.com";',
    'const support = "support@acme-startup.in";',
    'const demo = "jane@example.com";',
    'const phone = "+91 98450 12345";',
    'const aadhaar = "4567 8912 3456"; // aadhaar of test user',
    "const version = \"react@18.3.1\";",
    "git@github.com:org/repo.git",
  ].join("\n");
  const f = findHardcodedPersonalData(file("src/seed-data.ts", text));
  assert.deepEqual(f.map((x) => x.location!.line), [1, 4, 5]);
  assert.ok(f.every((x) => !x.evidence.includes("fixture.person") && !x.evidence.includes("12345")));
  assert.equal(findHardcodedPersonalData(file("test/fixtures.ts", text, true)).length, 0);
});

test("vendor matching by package (including npm scopes) and by URL", () => {
  assert.equal(vendorForPackage("@sentry/nextjs")?.id, "sentry");
  assert.equal(vendorForPackage("razorpay")?.id, "razorpay");
  assert.equal(vendorForPackage("react"), undefined);
  assert.equal(vendorForUrl("https://www.googletagmanager.com/gtag/js?id=G-1")?.id, "google-analytics");
  assert.equal(vendorForUrl("//connect.facebook.net/en_US/fbevents.js")?.id, "meta");
  assert.equal(vendorForUrl("https://www.facebook.com/tr?id=1")?.id, "meta");
  assert.equal(vendorForUrl("https://www.facebook.com/mypage"), undefined);
  assert.equal(vendorForUrl("https://notgoogletagmanager.com/x"), undefined);
});

test("parseManifest and findProcessors read several ecosystems", () => {
  const pkg = file("package.json", JSON.stringify({ dependencies: { razorpay: "^2", "@sentry/node": "^8", react: "19" }, devDependencies: { "mixpanel-browser": "^2" } }, null, 2));
  const req = file("api/requirements.txt", "openai==1.0\nboto3>=1.34\n# comment\ndjango\n");
  const gem = file("Gemfile", "gem 'rails'\ngem \"twilio\"");
  const code = file("app/layout.tsx", '<script src="https://www.googletagmanager.com/gtag/js?id=G-XYZ"></script>');
  assert.deepEqual(parseManifest(req).map((d) => d.name), ["openai", "boto3", "django"]);
  const ids = findProcessors([pkg, req, gem, code]).map((p) => p.id).sort();
  assert.deepEqual(ids, ["aws", "google-analytics", "mixpanel", "openai", "razorpay", "sentry", "twilio"]);
});

test("regressions from scanning a large real codebase (false positives must stay gone)", () => {
  // Identifiers that are not personal data.
  for (const id of ["apiKeyFingerprint", "healthWellnessAndFitness", "isChildFolder", "passportJwtStrategy"]) {
    assert.equal(classifyIdentifier(id), null, id);
  }
  // Name → UUID constant maps are not data fields.
  assert.equal(findPiiDefinitions(file("src/ids.ts", "  medicalDevices: '5d6a3933-b98d-43aa-a56b-e7334a276dff',")).length, 0);
  assert.equal(findPiiDefinitions(file("src/user.ts", "  medicalHistory: string;")).length, 1);
  // Package names in manifests are not data fields.
  assert.equal(findPiiDefinitions(file("server/package.json", '{ "dependencies": { "passport": "^0.7.0" } }')).length, 0);
  // Constants, routes and icon ids are not secrets; tests' made-up keys are not reported as generic secrets.
  const consts = [
    "INVALID_PRIVATE_KEY: 'INVALID_PRIVATE_KEY',",
    "HIDE_PASSWORD = 'HIDE_PASSWORD',",
    "ResetPassword = '/reset-password/:passwordResetToken',",
    "NewApiKey = 'developers/api-keys/new',",
    '"IconPassword": "icon-password-filled-2",',
  ].join("\n");
  assert.equal(findSecrets(file("src/constants.ts", consts)).length, 0);
  assert.equal(findSecrets(file("src/__tests__/x.test.ts", "apiKey: 'K9x!qTz2Lm8#Rv4w',", true)).length, 0);
  assert.equal(findSecrets(file("src/__tests__/slack.test.ts", "token: 'xoxb-test-token-123'", true)).length, 0);
  const inTest = findSecrets(file("src/__tests__/aws.test.ts", `const k = "${FAKE_AWS}";`, true));
  assert.equal(inTest.length, 1);
  assert.equal(inTest[0].severity, "medium", "provider-format keys in tests are reported, but not as high");
  // CI bots, service accounts, connection strings and example env files are not people's emails.
  const ci = [
    "git config user.email github-actions@twenty.com",
    "serviceAccount: terraform@my-project.iam.gserviceaccount.com",
    "url: postgres://postgres:pw@db.app.svc.cluster.local:5432/app",
  ].join("\n");
  assert.equal(findHardcodedPersonalData(file(".github/workflows/release.yaml", ci)).length, 0);
  assert.equal(findHardcodedPersonalData(file("e2e/.env.example", "USER=fixture.person.dpdp-test@gmail.com")).length, 0);
});

test("test, mock, seed and story paths are recognised", async () => {
  const { TEST_PATH } = await import("../src/walk.ts");
  for (const p of ["src/testing/mock-data/users.ts", "packages/app-e2e-testing/lib/pom/login.ts", "server/dev-seeder/data/people.ts", "ui/__stories__/Card.tsx", "a/b.stories.tsx", "scripts/test-package.mjs", "x/y.test-support.ts", "src/seeds/admin.ts"]) {
    assert.ok(TEST_PATH.test(p), p);
  }
  for (const p of ["src/contest/entry.ts", "src/attestation.ts", "src/latest/index.ts"]) assert.ok(!TEST_PATH.test(p), p);
});

test("parseGitignore handles names, folders, globs and anchored paths", () => {
  const gi = parseGitignore("node_modules/\n*.log\n/build\nsecret.txt\n# comment\n!keep.log\ndocs/**/*.pdf");
  assert.equal(gi("node_modules", true), true);
  assert.equal(gi("app/debug.log", false), true);
  assert.equal(gi("build", true), true);
  assert.equal(gi("src/build", true), false);
  assert.equal(gi("a/secret.txt", false), true);
  assert.equal(gi("docs/x/y/z.pdf", false), true);
  assert.equal(gi("src/index.ts", false), false);
});
