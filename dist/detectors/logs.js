import { classifyIdentifier } from "./pii.js";
import { DPDP } from "../dpdp.js";
import { snippetOf } from "../walk.js";
const LOG_CALL = /\b(?:console\.(?:log|info|warn|error|debug|trace)|logger\.\w+|log\.(?:info|warn|warning|error|debug|trace|fatal|print\w*)|logging\.\w+|print|println|printf|System\.out\.print\w*|Log\.[dievw]|fmt\.Print\w*|puts|Rails\.logger\.\w+|error_log|var_dump)\s*\(/;
const HIGH_RISK = new Set(["credentials", "aadhaar", "financial", "biometric", "health", "pan", "government_id"]);
/** Removes string-literal text but keeps ${...} template expressions, so "Email sent" doesn't count but `${user.email}` does. */
export function stripStringLiterals(line) {
    let out = "";
    let i = 0;
    while (i < line.length) {
        const c = line[i];
        if (c === '"' || c === "'") {
            const end = findClose(line, i + 1, c);
            out += " ";
            i = end + 1;
        }
        else if (c === "`") {
            let j = i + 1;
            while (j < line.length && line[j] !== "`") {
                if (line[j] === "\\")
                    j += 2;
                else if (line[j] === "$" && line[j + 1] === "{") {
                    const close = line.indexOf("}", j);
                    if (close < 0)
                        break;
                    out += ` ${line.slice(j + 2, close)} `;
                    j = close + 1;
                }
                else
                    j++;
            }
            i = j + 1;
        }
        else {
            out += c;
            i++;
        }
    }
    return out;
}
function findClose(s, from, q) {
    for (let j = from; j < s.length; j++) {
        if (s[j] === "\\")
            j++;
        else if (s[j] === q)
            return j;
    }
    return s.length;
}
export function findPiiInLogs(file) {
    if (file.isTest || /\.(md|txt|json|ya?ml|sql|html?)$/i.test(file.rel))
        return [];
    const out = [];
    file.text.split(/\r?\n/).forEach((line, i) => {
        if (!LOG_CALL.test(line) || line.length > 1000)
            return;
        const code = stripStringLiterals(line.slice(line.search(LOG_CALL)));
        const types = new Map();
        for (const ident of code.match(/[A-Za-z_$][\w$]*/g) ?? []) {
            const t = classifyIdentifier(ident);
            if (t && !types.has(t.id))
                types.set(t.id, t.label);
        }
        if (types.size === 0)
            return;
        const high = [...types.keys()].some((t) => HIGH_RISK.has(t));
        out.push({
            id: `personal-data-in-logs:${file.rel}:${i + 1}`,
            rule: "personal-data-in-logs",
            title: `Personal data may be written to logs (${[...types.values()].join(", ")})`,
            severity: high ? "high" : "medium",
            confidence: "medium",
            location: { file: file.rel, line: i + 1, snippet: snippetOf(line) },
            evidence: `Log call references: ${[...types.values()].join(", ")}`,
            why: "Logs are copied to many places (log tools, backups, developer laptops), are rarely access-controlled like the database, and are often kept longer than the data itself.",
            recommendation: "Log a user ID or a masked value instead (e.g. a***@gmail.com, ******1234). Never log passwords, OTPs, card or Aadhaar numbers.",
            dpdp: [DPDP.security, DPDP.securityRule, DPDP.erasure],
        });
    });
    return out;
}
