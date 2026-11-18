import { CONSENT_TOOLS, vendorForUrl } from "./vendors.js";
import { DPDP } from "./dpdp.js";
export const USER_AGENT = "DPDPReadyScanner/0.1 (+owner-authorised scan)";
const TIMEOUT_MS = 15_000;
const MAX_BYTES = 2_000_000;
/** Cookie names commonly set by analytics/advertising tools. */
const TRACKING_COOKIE = /^(_ga|_gid|_gat|_gcl_|_fbp|_fbc|_hj|_clck|_clsk|mp_|amplitude|ajs_|_uetsid|_uetvid|li_|bcookie|_ttp|IDE|NID)/i;
export const NOTICE_SIGNALS = [
    { id: "data-items", label: "Lists the personal data collected", re: /(personal (data|information) (we|that we) (collect|process)|information we collect|data we collect|categories of (personal )?data)/i },
    { id: "purpose", label: "States purposes of processing", re: /\bpurpose(s)?\b/i },
    { id: "withdraw-consent", label: "Explains how to withdraw consent", re: /withdraw(al)? (of )?(your )?consent|withdraw consent/i },
    { id: "rights", label: "Explains user rights (access, correction, erasure)", re: /(right to (access|correct|correction|erase|erasure|be forgotten)|correct(ion)? (and|or) eras(e|ure)|access, correct)/i },
    { id: "grievance", label: "Gives a grievance / privacy contact", re: /(grievance (officer|redressal)|data protection officer|privacy officer|\bdpo\b|contact us at|email us at)/i },
    { id: "board", label: "Mentions complaint to the Data Protection Board", re: /data protection board/i },
    { id: "dpdp", label: "Refers to India's DPDP Act", re: /digital personal data protection|\bdpdp\b/i },
];
function htmlToText(html) {
    return html
        .replace(/<(script|style|noscript|svg)[\s\S]*?<\/\1>/gi, " ")
        .replace(/<[^>]+>/g, " ")
        .replace(/&nbsp;/g, " ")
        .replace(/&amp;/g, "&")
        .replace(/\s+/g, " ");
}
async function get(url, fetchImpl) {
    const res = await fetchImpl(url, { headers: { "user-agent": USER_AGENT, accept: "text/html" }, redirect: "follow", signal: AbortSignal.timeout(TIMEOUT_MS) });
    const buf = await res.arrayBuffer();
    const body = new TextDecoder().decode(buf.byteLength > MAX_BYTES ? buf.slice(0, MAX_BYTES) : buf);
    const cookies = typeof res.headers.getSetCookie === "function" ? res.headers.getSetCookie() : (res.headers.get("set-cookie") ?? "").split(/,(?=\s*[^;,=\s]+=)/).filter(Boolean);
    return { status: res.status, finalUrl: res.url || url, body, cookies: cookies.map((c) => c.split("=")[0].trim()).filter(Boolean) };
}
export function extractResources(html, base) {
    const out = [];
    const re = /<(script|iframe|img|link)\b[^>]*?\s(?:src|href)\s*=\s*["']([^"']+)["']/gi;
    let m;
    while ((m = re.exec(html))) {
        try {
            const u = new URL(m[2], base);
            if (u.protocol === "http:" || u.protocol === "https:")
                out.push({ url: u.toString(), kind: m[1].toLowerCase() });
        }
        catch {
            /* ignore */
        }
    }
    // Inline loaders, e.g. gtag snippets that inject scripts at runtime.
    for (const m2 of html.matchAll(/["'](https?:)?\/\/([a-z0-9.-]+\.[a-z]{2,})(\/[^"'\s]*)?["']/gi)) {
        out.push({ url: `https://${m2[2]}${m2[3] ?? ""}`, kind: "inline-reference" });
    }
    return out;
}
export function findPrivacyLink(html, base) {
    for (const m of html.matchAll(/<a\b[^>]*href\s*=\s*["']([^"'#]+)["'][^>]*>([\s\S]*?)<\/a>/gi)) {
        if (/privacy/i.test(m[1]) || /privacy/i.test(m[2].replace(/<[^>]+>/g, ""))) {
            try {
                return new URL(m[1], base).toString();
            }
            catch {
                /* ignore */
            }
        }
    }
    return null;
}
export async function scanWebsite(target, fetchImpl = fetch) {
    const url = new URL(target.includes("://") ? target : `https://${target}`);
    const notes = [];
    const home = await get(url.toString(), fetchImpl);
    const base = new URL(home.finalUrl);
    const host = base.hostname.replace(/^www\./, "");
    const pagesRead = [home.finalUrl];
    // Third parties referenced by the homepage HTML.
    const tp = new Map();
    for (const r of extractResources(home.body, base)) {
        const h = new URL(r.url).hostname.toLowerCase();
        if (h === base.hostname || h.endsWith(`.${host}`) || h === host)
            continue;
        const v = vendorForUrl(r.url);
        // Quoted URLs inside inline scripts are only interesting when they belong to a known vendor.
        if (r.kind === "inline-reference" && !v)
            continue;
        const key = h;
        const entry = tp.get(key) ?? { domain: h, vendor: v?.vendor, category: v?.category, kinds: [] };
        if (!entry.vendor && v)
            Object.assign(entry, { vendor: v.vendor, category: v.category });
        if (!entry.kinds.includes(r.kind))
            entry.kinds.push(r.kind);
        tp.set(key, entry);
    }
    const thirdParties = [...tp.values()].sort((a, b) => Number(!!b.vendor) - Number(!!a.vendor) || a.domain.localeCompare(b.domain));
    const consent = CONSENT_TOOLS.find((c) => c.pattern.test(home.body))?.name ?? null;
    const forms = new Set();
    for (const m of home.body.matchAll(/<input\b[^>]*>/gi)) {
        const tag = m[0];
        if (/type\s*=\s*["']email["']|name\s*=\s*["'][^"']*email/i.test(tag))
            forms.add("email");
        if (/type\s*=\s*["']tel["']|name\s*=\s*["'][^"']*(phone|mobile)/i.test(tag))
            forms.add("phone");
        if (/name\s*=\s*["'][^"']*(name)["']/i.test(tag))
            forms.add("name");
    }
    // Privacy notice.
    let privacyUrl = findPrivacyLink(home.body, base);
    let noticeText = "";
    if (privacyUrl) {
        try {
            const p = await get(privacyUrl, fetchImpl);
            if (p.status < 400) {
                noticeText = htmlToText(p.body);
                privacyUrl = p.finalUrl;
                pagesRead.push(p.finalUrl);
            }
            else
                notes.push(`Privacy link returned HTTP ${p.status}.`);
        }
        catch (e) {
            notes.push(`Privacy page could not be read: ${e.message}`);
        }
    }
    const noticeSignals = NOTICE_SIGNALS.map((s) => ({ id: s.id, label: s.label, found: noticeText ? s.re.test(noticeText) : false }));
    if (noticeText && noticeText.length < 500)
        notes.push("Privacy page has very little text; it may be rendered by JavaScript, which this scan does not run.");
    const result = {
        url: url.toString(),
        finalUrl: home.finalUrl,
        status: home.status,
        pagesRead,
        thirdParties,
        cookiesOnLoad: home.cookies,
        consentTool: consent,
        privacyNoticeUrl: privacyUrl && noticeText ? privacyUrl : null,
        noticeSignals,
        formsCollecting: [...forms],
        notes,
    };
    return { result, findings: websiteFindings(result) };
}
export function websiteFindings(w) {
    const f = [];
    const base = { confidence: "medium", url: w.finalUrl };
    if (w.finalUrl.startsWith("http://")) {
        f.push({ ...base, id: "web-no-https", rule: "web-no-https", title: "Website is served without HTTPS", severity: "high", confidence: "high", evidence: w.finalUrl, why: "Personal data sent over plain HTTP can be read or changed in transit.", recommendation: "Serve the whole site over HTTPS and redirect HTTP to HTTPS.", dpdp: [DPDP.security, DPDP.securityRule] });
    }
    if (!w.privacyNoticeUrl) {
        f.push({ ...base, id: "web-no-privacy-notice", rule: "web-no-privacy-notice", title: "No privacy notice found from the homepage", severity: "medium", evidence: "No readable link containing 'privacy' on the homepage.", why: "People must be told what personal data you collect, why, and how to exercise their rights.", recommendation: "Link a clear privacy notice from every page (usually the footer) and from every form that collects personal data.", dpdp: [DPDP.notice, DPDP.rights] });
    }
    else {
        const missing = w.noticeSignals.filter((s) => !s.found);
        if (missing.length) {
            f.push({ ...base, id: "web-notice-gaps", rule: "web-notice-gaps", title: `Privacy notice may be missing ${missing.length} element(s)`, severity: "low", confidence: "low", url: w.privacyNoticeUrl, evidence: `Not found by keyword search: ${missing.map((s) => s.label).join("; ")}`, why: "A DPDP notice should itemise the data and purposes and explain how to withdraw consent, exercise rights and complain to the Data Protection Board.", recommendation: "Review the notice with a qualified professional. This check only searches for keywords and can miss content phrased differently.", dpdp: [DPDP.notice, DPDP.rights, DPDP.consent] });
        }
    }
    const trackers = w.thirdParties.filter((t) => t.category && /Analytics|Advertising|Session recording|Attribution/.test(t.category));
    if (trackers.length) {
        f.push({ ...base, id: "web-trackers", rule: "web-trackers", title: `Tracking or analytics loaded by the homepage (${trackers.map((t) => t.vendor).filter((v, i, a) => a.indexOf(v) === i).join(", ")})`, severity: w.consentTool ? "info" : "medium", confidence: "low", evidence: `${trackers.map((t) => t.domain).join(", ")}${w.consentTool ? `; consent tool detected: ${w.consentTool}` : "; no consent tool detected in the HTML"}`, why: "Non-essential tracking generally needs informed consent before it runs. This scan reads HTML only, so it cannot tell whether scripts wait for consent.", recommendation: "Load analytics, ads and session-recording scripts only after the user agrees, and list these vendors in your notice. Verify in a browser with a fresh profile.", dpdp: [DPDP.consent, DPDP.notice, DPDP.processor] });
    }
    const trackingCookies = w.cookiesOnLoad.filter((c) => TRACKING_COOKIE.test(c));
    if (trackingCookies.length) {
        f.push({ ...base, id: "web-cookies-on-load", rule: "web-cookies-on-load", title: "Tracking cookies set on the first page load", severity: "medium", evidence: `Set-Cookie on first response: ${trackingCookies.join(", ")}`, why: "These cookies were set before any interaction, so before consent could be given.", recommendation: "Set analytics/advertising cookies only after consent.", dpdp: [DPDP.consent] });
    }
    return f;
}
