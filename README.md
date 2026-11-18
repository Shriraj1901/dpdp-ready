# DPDP Ready scanner

[![CI](https://github.com/Shriraj1901/dpdp-ready/actions/workflows/ci.yml/badge.svg)](https://github.com/Shriraj1901/dpdp-ready/actions/workflows/ci.yml)

Find where your app handles personal data before India's DPDP Rules apply in full (13 May 2027).

**Website:** https://shriraj1901.github.io/dpdp-ready/ · **Sample report:** https://shriraj1901.github.io/dpdp-ready/sample-report.html

`dpdp-ready` scans your code (and, optionally, your website) and tells you:

- **What personal data your code handles.** Emails, phone numbers, Aadhaar, PAN, financial, health and children's data and more, each with file and line.
- **Which third-party services may receive it.** Analytics, ads, payments, messaging, AI providers and others, found from your dependencies and code.
- **Risky patterns.** Secrets committed to the repo, personal data written to logs, and real people's data hardcoded in source.
- **Website basics.** Trackers on the homepage, cookies set before consent, and whether your privacy notice covers key DPDP elements.

It runs **entirely on your machine or in your CI**. No code, data or results are uploaded. It has no runtime dependencies.

> This is an engineering tool, not a legal opinion or a compliance certificate. It shows what it could detect; it cannot prove compliance. Have legal decisions reviewed by a qualified professional.

## Quick start

Requires Node.js 20 or later. Not yet published to npm; run from a clone (no install step needed):

```bash
git clone https://github.com/Shriraj1901/dpdp-ready.git
node dpdp-ready/dist/cli.js scan /path/to/your/app --html report.html
```

Options:

| Option | What it does |
|---|---|
| `--md <file>` | Full report with evidence, reasons and fixes |
| `--html <file>` | The same report as a self-contained web page (prints cleanly to PDF) |
| `--json <file>` | Machine-readable results |
| `--sarif <file>` | SARIF for GitHub code scanning |
| `--website <url> --authorized` | Also check the site's homepage and privacy notice. Only scan sites you own or have permission to scan. |
| `--fail-on high\|medium\|low\|none` | Exit with code 1 when findings reach that severity (for CI) |

## GitHub Action

```yaml
# .github/workflows/dpdp.yml
name: DPDP Ready
on: [pull_request, push]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # only needed with upload-sarif: true
    steps:
      - uses: actions/checkout@v7
      - uses: Shriraj1901/dpdp-ready@v0
        with:
          fail-on: high          # block merges that add committed secrets
          upload-sarif: "false"  # "true" shows findings inline in PRs (free for public repos)
```

The Markdown report appears in the job summary.

## What each finding contains

Every finding includes the file and line, the evidence it found (secrets and personal data are masked), a confidence level, why it matters, what to do, and the DPDP provisions a reviewer should look at.

## Limitations

- Static analysis only. Databases, logs, cloud config, backups and vendor contracts are not inspected.
- Personal data is detected from field names and patterns. Unusual names can be missed, and some matches may not be personal data.
- The website check reads HTML without running JavaScript, so scripts and cookies added at runtime are not seen.
- Secret detection uses high-precision patterns. Use a dedicated tool such as gitleaks for full coverage, including git history.

## Development

```bash
npm ci
npm test          # node:test, no extra dependencies
npm run typecheck
node src/cli.ts scan .   # Node 23.6+ runs the TypeScript source directly
```

The website lives in `site-src/` and is built into `docs/` with `node site-src/build.mjs`. The sample report comes from the fictional app in `examples/demo-shop`.

Licensed under Apache-2.0.
