const SEV_LABEL = { high: "High", medium: "Medium", low: "Low", info: "Info" };
const esc = (s) => s.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
const loc = (f) => (f.location ? `\`${f.location.file}:${f.location.line}\`` : f.url ? f.url : "");
export function counts(r) {
    const c = { high: 0, medium: 0, low: 0, info: 0 };
    for (const f of r.findings)
        c[f.severity]++;
    return c;
}
export function toMarkdown(r) {
    const c = counts(r);
    const out = [];
    out.push(`# DPDP Ready scan: ${r.root}`);
    out.push("");
    out.push(`Scanned ${r.filesScanned} files on ${r.scannedAt.slice(0, 10)} with ${r.tool.name} ${r.tool.version}.`);
    out.push("");
    out.push(`**Findings:** ${c.high} high · ${c.medium} medium · ${c.low} low · ${c.info} info  `);
    out.push(`**Personal data types found:** ${r.inventory.length} (${r.inventory.filter((i) => i.sensitive).length} sensitive)  `);
    out.push(`**Third-party services:** ${r.processors.length}`);
    out.push("");
    out.push(`> ${r.limitations[r.limitations.length - 1]}`);
    out.push("");
    out.push("## Personal data inventory");
    out.push("");
    if (!r.inventory.length)
        out.push("No personal-data fields detected.");
    else {
        out.push("| Data type | Sensitive | Locations | Files | Examples |");
        out.push("|---|---|---|---|---|");
        for (const i of r.inventory) {
            const ex = i.locations.slice(0, 3).map((l) => `\`${l.file}:${l.line}\``).join(", ");
            out.push(`| ${i.label} | ${i.sensitive ? "**Yes**" : "No"} | ${i.count} | ${i.files} | ${ex} |`);
        }
    }
    out.push("");
    out.push("## Third-party services that may receive personal data");
    out.push("");
    if (!r.processors.length)
        out.push("None detected.");
    else {
        out.push("| Service | Category | Typically receives | Detected in |");
        out.push("|---|---|---|---|");
        for (const p of r.processors) {
            const ev = p.evidence.slice(0, 2).map((e) => `\`${esc(e.detail)}\` (${e.file})`).join("; ");
            out.push(`| ${p.vendor} | ${p.category} | ${esc(p.dataTypically)} | ${ev} |`);
        }
    }
    out.push("");
    if (r.website) {
        const w = r.website;
        out.push("## Website");
        out.push("");
        out.push(`Checked ${w.pagesRead.map((u) => `<${u}>`).join(" and ")} (HTTP ${w.status}).`);
        out.push("");
        out.push(`- Privacy notice: ${w.privacyNoticeUrl ? `<${w.privacyNoticeUrl}>` : "**not found**"}`);
        out.push(`- Consent tool detected: ${w.consentTool ?? "none"}`);
        out.push(`- Cookies set on first load: ${w.cookiesOnLoad.length ? w.cookiesOnLoad.join(", ") : "none"}`);
        out.push(`- Homepage form fields collecting: ${w.formsCollecting.length ? w.formsCollecting.join(", ") : "none seen"}`);
        out.push("");
        if (w.thirdParties.length) {
            out.push("| Third-party domain | Known service | Loaded as |");
            out.push("|---|---|---|");
            for (const t of w.thirdParties)
                out.push(`| ${t.domain} | ${t.vendor ? `${t.vendor} (${t.category})` : "—"} | ${t.kinds.join(", ")} |`);
            out.push("");
        }
        if (w.privacyNoticeUrl) {
            out.push("Privacy notice keyword check (not a legal review):");
            out.push("");
            for (const s of w.noticeSignals)
                out.push(`- [${s.found ? "x" : " "}] ${s.label}`);
            out.push("");
        }
        for (const n of w.notes)
            out.push(`- Note: ${n}`);
        if (w.notes.length)
            out.push("");
    }
    out.push("## Findings");
    out.push("");
    if (!r.findings.length)
        out.push("No findings.");
    for (const sev of ["high", "medium", "low", "info"]) {
        const list = r.findings.filter((f) => f.severity === sev);
        if (!list.length)
            continue;
        out.push(`### ${SEV_LABEL[sev]} (${list.length})`);
        out.push("");
        for (const f of list) {
            out.push(`#### ${f.title}`);
            out.push("");
            out.push(`- **Where:** ${loc(f)} · **Confidence:** ${f.confidence}`);
            out.push(`- **Evidence:** ${esc(f.evidence)}`);
            if (f.location?.snippet)
                out.push(`- **Code:** \`${esc(f.location.snippet).replace(/`/g, "'")}\``);
            out.push(`- **Why it matters:** ${f.why}`);
            out.push(`- **What to do:** ${f.recommendation}`);
            out.push(`- **Relevant provisions (for review):** ${f.dpdp.join("; ")}`);
            out.push("");
        }
    }
    out.push("## Limitations");
    out.push("");
    for (const l of r.limitations)
        out.push(`- ${l}`);
    out.push("");
    return out.join("\n");
}
export function toText(r) {
    const c = counts(r);
    const lines = [];
    lines.push(`DPDP Ready ${r.tool.version} — scanned ${r.filesScanned} files in ${r.root}`);
    lines.push(`Findings: ${c.high} high, ${c.medium} medium, ${c.low} low, ${c.info} info`);
    lines.push("");
    lines.push(`Personal data found (${r.inventory.length} types):`);
    for (const i of r.inventory)
        lines.push(`  ${i.sensitive ? "!" : "-"} ${i.label}: ${i.count} location(s) in ${i.files} file(s)`);
    if (!r.inventory.length)
        lines.push("  none detected");
    lines.push("");
    lines.push(`Third-party services (${r.processors.length}):`);
    for (const p of r.processors)
        lines.push(`  - ${p.vendor} [${p.category}]`);
    if (!r.processors.length)
        lines.push("  none detected");
    const important = r.findings.filter((f) => f.severity === "high" || f.severity === "medium");
    if (important.length) {
        lines.push("");
        lines.push("High and medium findings:");
        for (const f of important.slice(0, 30)) {
            lines.push(`  [${f.severity.toUpperCase()}] ${f.title}`);
            lines.push(`      ${f.location ? `${f.location.file}:${f.location.line}` : f.url ?? ""}  (${f.confidence} confidence)`);
        }
        if (important.length > 30)
            lines.push(`  …and ${important.length - 30} more (see the Markdown or JSON report)`);
    }
    if (r.website) {
        lines.push("");
        lines.push(`Website: ${r.website.finalUrl} — notice ${r.website.privacyNoticeUrl ? "found" : "NOT found"}, consent tool: ${r.website.consentTool ?? "none"}, third-party domains: ${r.website.thirdParties.length}`);
    }
    lines.push("");
    lines.push("Not a compliance certificate. Have legal conclusions reviewed by a qualified professional.");
    return lines.join("\n");
}
