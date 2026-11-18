import { counts } from "./markdown.js";
const esc = (s) => String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
/** Only http(s) links are rendered as links; anything else is shown as text. */
const link = (url) => (/^https?:\/\//i.test(url) ? `<a href="${esc(url)}" rel="noopener noreferrer">${esc(url)}</a>` : esc(url));
const SEV = { high: "High", medium: "Medium", low: "Low", info: "Info" };
const CSS = `
:root{--bg:#fff;--fg:#1b1b1f;--muted:#5d5d66;--line:#e3e3e8;--panel:#f7f7f9;--high:#b42318;--medium:#b54708;--low:#175cd3;--info:#5d5d66;--ok:#067647}
@media (prefers-color-scheme:dark){:root{--bg:#141417;--fg:#ececf1;--muted:#a0a0ab;--line:#2c2c33;--panel:#1c1c21;--high:#f97066;--medium:#fdb022;--low:#84adff;--info:#a0a0ab;--ok:#47cd89}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:960px;margin:0 auto;padding:32px 16px 64px}h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:36px 0 12px;padding-top:12px;border-top:1px solid var(--line)}h3{font-size:16px;margin:0 0 6px}
.muted{color:var(--muted)}.small{font-size:13px}.cards{display:grid;gap:10px;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));margin:20px 0}
.card{border:1px solid var(--line);border-radius:10px;padding:12px;background:var(--panel)}.card .n{font-size:24px;font-weight:650;font-variant-numeric:tabular-nums}.card .l{font-size:13px;color:var(--muted)}
.note{border-left:3px solid var(--muted);padding:8px 12px;background:var(--panel);border-radius:4px;font-size:14px}
.scroll{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line);vertical-align:top}th{font-weight:600;color:var(--muted);font-size:13px}
code{font:13px/1.4 ui-monospace,SFMono-Regular,Consolas,monospace;background:var(--panel);border:1px solid var(--line);border-radius:4px;padding:1px 5px;word-break:break-word}
.tag{display:inline-block;font-size:12px;font-weight:600;padding:1px 8px;border-radius:99px;border:1px solid currentColor}.high{color:var(--high)}.medium{color:var(--medium)}.low{color:var(--low)}.info{color:var(--info)}.ok{color:var(--ok)}
.finding{border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:10px 0;background:var(--bg)}.finding dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 12px;margin:8px 0 0;font-size:14px}.finding dt{color:var(--muted)}.finding dd{margin:0}
ul.checks{list-style:none;padding:0}ul.checks li::before{content:"✗ ";color:var(--medium)}ul.checks li.yes::before{content:"✓ ";color:var(--ok)}
a{color:var(--low)}footer{margin-top:40px;font-size:13px;color:var(--muted)}
@media print{body{font-size:12px}main{padding:0}.finding{break-inside:avoid}h2{break-after:avoid}a{color:inherit}}
`;
function findingHtml(f) {
    const where = f.location ? `<code>${esc(f.location.file)}:${f.location.line}</code>` : f.url ? link(f.url) : "";
    return `<article class="finding">
<h3><span class="tag ${f.severity}">${SEV[f.severity]}</span> ${esc(f.title)}</h3>
<dl>
<dt>Where</dt><dd>${where} <span class="muted small">· ${esc(f.confidence)} confidence</span></dd>
<dt>Evidence</dt><dd>${esc(f.evidence)}</dd>
${f.location?.snippet ? `<dt>Code</dt><dd><code>${esc(f.location.snippet)}</code></dd>` : ""}
<dt>Why it matters</dt><dd>${esc(f.why)}</dd>
<dt>What to do</dt><dd>${esc(f.recommendation)}</dd>
<dt>For review</dt><dd class="small muted">${f.dpdp.map(esc).join("<br>")}</dd>
</dl></article>`;
}
/** Self-contained HTML report: no scripts, no external resources, prints cleanly to PDF. */
export function toHtml(r, opts = {}) {
    const c = counts(r);
    const title = opts.title ?? `DPDP Ready scan: ${r.root}`;
    const disclaimer = r.limitations[r.limitations.length - 1];
    const parts = [];
    parts.push(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>${esc(title)}</title><style>${CSS}</style></head><body><main>`);
    parts.push(`<h1>${esc(title)}</h1><p class="muted">${opts.preparedFor ? `Prepared for ${esc(opts.preparedFor)} · ` : ""}Scanned ${r.filesScanned} files on ${esc(r.scannedAt.slice(0, 10))} with ${esc(r.tool.name)} ${esc(r.tool.version)}</p>`);
    parts.push(`<div class="cards">
<div class="card"><div class="n high">${c.high}</div><div class="l">High</div></div>
<div class="card"><div class="n medium">${c.medium}</div><div class="l">Medium</div></div>
<div class="card"><div class="n low">${c.low}</div><div class="l">Low</div></div>
<div class="card"><div class="n">${r.inventory.length}</div><div class="l">Personal data types</div></div>
<div class="card"><div class="n">${r.processors.length}</div><div class="l">Third-party services</div></div>
</div><p class="note">${esc(disclaimer)}</p>`);
    parts.push(`<h2>Personal data inventory</h2>`);
    if (!r.inventory.length)
        parts.push(`<p>No personal-data fields detected.</p>`);
    else {
        parts.push(`<div class="scroll"><table><thead><tr><th>Data type</th><th>Sensitive</th><th>Locations</th><th>Files</th><th>Examples</th></tr></thead><tbody>`);
        for (const i of r.inventory) {
            parts.push(`<tr><td>${esc(i.label)}</td><td>${i.sensitive ? `<span class="tag medium">Yes</span>` : "No"}</td><td>${i.count}</td><td>${i.files}</td><td>${i.locations.slice(0, 3).map((l) => `<code>${esc(l.file)}:${l.line}</code>`).join(" ")}</td></tr>`);
        }
        parts.push(`</tbody></table></div>`);
    }
    parts.push(`<h2>Third-party services that may receive personal data</h2>`);
    if (!r.processors.length)
        parts.push(`<p>None detected.</p>`);
    else {
        parts.push(`<div class="scroll"><table><thead><tr><th>Service</th><th>Category</th><th>Typically receives</th><th>Detected in</th></tr></thead><tbody>`);
        for (const p of r.processors) {
            parts.push(`<tr><td>${esc(p.vendor)}</td><td>${esc(p.category)}</td><td>${esc(p.dataTypically)}</td><td>${p.evidence.slice(0, 2).map((e) => `<code>${esc(e.detail)}</code> <span class="muted small">${esc(e.file)}</span>`).join("<br>")}</td></tr>`);
        }
        parts.push(`</tbody></table></div>`);
    }
    if (r.website) {
        const w = r.website;
        parts.push(`<h2>Website</h2><p>Checked ${w.pagesRead.map(link).join(" and ")} (HTTP ${w.status}).</p><ul>
<li>Privacy notice: ${w.privacyNoticeUrl ? link(w.privacyNoticeUrl) : "<strong>not found</strong>"}</li>
<li>Consent tool detected: ${esc(w.consentTool ?? "none")}</li>
<li>Cookies set on first load: ${esc(w.cookiesOnLoad.join(", ") || "none")}</li>
<li>Homepage form fields collecting: ${esc(w.formsCollecting.join(", ") || "none seen")}</li></ul>`);
        if (w.thirdParties.length) {
            parts.push(`<div class="scroll"><table><thead><tr><th>Third-party domain</th><th>Known service</th><th>Loaded as</th></tr></thead><tbody>`);
            for (const t of w.thirdParties)
                parts.push(`<tr><td>${esc(t.domain)}</td><td>${t.vendor ? `${esc(t.vendor)} <span class="muted small">(${esc(t.category)})</span>` : "—"}</td><td>${esc(t.kinds.join(", "))}</td></tr>`);
            parts.push(`</tbody></table></div>`);
        }
        if (w.privacyNoticeUrl) {
            parts.push(`<p class="small muted">Privacy notice keyword check (not a legal review):</p><ul class="checks">${w.noticeSignals.map((s) => `<li class="${s.found ? "yes" : ""}">${esc(s.label)}</li>`).join("")}</ul>`);
        }
        for (const n of w.notes)
            parts.push(`<p class="small muted">Note: ${esc(n)}</p>`);
    }
    parts.push(`<h2>Findings</h2>`);
    if (!r.findings.length)
        parts.push(`<p>No findings.</p>`);
    for (const sev of ["high", "medium", "low", "info"]) {
        const list = r.findings.filter((f) => f.severity === sev);
        if (list.length)
            parts.push(`<h3 class="${sev}" style="margin-top:20px">${SEV[sev]} (${list.length})</h3>${list.map(findingHtml).join("")}`);
    }
    parts.push(`<h2>Limitations</h2><ul>${r.limitations.map((l) => `<li>${esc(l)}</li>`).join("")}</ul>`);
    parts.push(`<footer>Generated by ${esc(r.tool.name)} ${esc(r.tool.version)}, an open-source scanner. The scan ran locally; no code or results were uploaded.</footer></main></body></html>`);
    return parts.join("\n");
}
