#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";
import { scan, VERSION } from "./scan.js";
import { toMarkdown, toText } from "./report/markdown.js";
import { toSarif } from "./report/sarif.js";
import { SEVERITY_ORDER } from "./types.js";
const HELP = `DPDP Ready ${VERSION}: map personal data, third-party services and leaked secrets in your code.
Runs entirely on your machine. Nothing is uploaded.

Usage:
  dpdp-ready scan [path] [options]

Options:
  --md <file>          Write a Markdown report
  --json <file>        Write a JSON report
  --sarif <file>       Write SARIF (for GitHub code scanning)
  --website <url>      Also check a website's homepage and privacy notice
  --authorized         Required with --website: confirms you own the site or have permission to scan it
  --fail-on <level>    Exit with code 1 if any finding is at or above: high | medium | low | none (default: none)
  --quiet              Do not print the summary
  -h, --help           Show this help
  -v, --version        Show the version

Examples:
  dpdp-ready scan .
  dpdp-ready scan ./my-app --md report.md --sarif results.sarif --fail-on high
  dpdp-ready scan . --website https://my-startup.in --authorized

Results are an engineering aid, not a legal opinion or compliance certificate.`;
export async function main(argv) {
    let parsed;
    try {
        parsed = parseArgs({
            args: argv,
            allowPositionals: true,
            options: {
                md: { type: "string" },
                json: { type: "string" },
                sarif: { type: "string" },
                website: { type: "string" },
                authorized: { type: "boolean", default: false },
                "fail-on": { type: "string", default: "none" },
                quiet: { type: "boolean", default: false },
                help: { type: "boolean", short: "h", default: false },
                version: { type: "boolean", short: "v", default: false },
            },
        });
    }
    catch (e) {
        console.error(`${e.message}\n\nRun "dpdp-ready --help" for usage.`);
        return 2;
    }
    const { values: o, positionals } = parsed;
    if (o.version) {
        console.log(VERSION);
        return 0;
    }
    if (o.help || positionals[0] !== "scan") {
        console.log(HELP);
        return o.help ? 0 : 2;
    }
    const failOn = o["fail-on"];
    if (!["high", "medium", "low", "none"].includes(failOn)) {
        console.error(`--fail-on must be high, medium, low or none (got "${failOn}").`);
        return 2;
    }
    if (o.website && !o.authorized) {
        console.error("Website scans need --authorized to confirm you own the site or have the owner's permission.\n" +
            "The scan only reads the homepage and privacy page, like a visitor's browser would.");
        return 2;
    }
    const root = positionals[1] ?? ".";
    if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) {
        console.error(`Not a folder: ${root}`);
        return 2;
    }
    const result = await scan({ root, website: o.website });
    const write = (file, content) => {
        fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
        fs.writeFileSync(file, content);
    };
    if (o.md)
        write(o.md, toMarkdown(result));
    if (o.json)
        write(o.json, JSON.stringify(result, null, 2));
    if (o.sarif)
        write(o.sarif, JSON.stringify(toSarif(result), null, 2));
    if (!o.quiet) {
        console.log(toText(result));
        const written = [o.md, o.json, o.sarif].filter(Boolean);
        if (written.length)
            console.log(`\nReports written: ${written.join(", ")}`);
        else
            console.log(`\nTip: add --md report.md for the full report with evidence and recommendations.`);
    }
    if (failOn !== "none") {
        const threshold = SEVERITY_ORDER[failOn];
        const failing = result.findings.filter((f) => SEVERITY_ORDER[f.severity] >= threshold);
        if (failing.length) {
            if (!o.quiet)
                console.error(`\n${failing.length} finding(s) at or above "${failOn}". Exiting with code 1.`);
            return 1;
        }
    }
    return 0;
}
// Run when executed directly (not when imported by tests).
const invoked = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (invoked && /cli\.(ts|js)$/.test(invoked)) {
    main(process.argv.slice(2)).then((code) => process.exit(code), (e) => {
        console.error(`dpdp-ready failed: ${e.stack ?? e}`);
        process.exit(3);
    });
}
