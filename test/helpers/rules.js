import { sanItem } from "../../src/policy.js";
import { EXTENDED_KEY_USAGE_OIDS } from "../../src/usage.js";

// What the README's table of reason codes says each rule does, written again here from the table
// and with none of the rules of `src/rules.js`: it is the oracle the examples and the evaluation
// of every fixture are checked against, so a rule that drifts from the table fails a test instead
// of agreeing with itself. It shares only how an `expectSan` item is read, which the policy owns.

/** The code each entry of the policy produces, which is where a result's `rule` leads back to. */
export const CODE_OF = /** @type {Record<string, string>} */ ({
    validityStarted: "NOT_YET_VALID",
    validityNotEnded: "EXPIRED",
    expiresWithin: "EXPIRES_SOON",
    maxLifetimeUsed: "LIFETIME_USED_EXCEEDED",
    expectEku: "EKU_MISSING",
    ekuAllows: "EKU_NOT_PERMITTED",
    rejectEku: "EKU_FORBIDDEN",
    expectSan: "SAN_MISSING",
    expectFingerprint: "FINGERPRINT_MISMATCH",
    expectKind: "TARGET_NOT_END_ENTITY",
    matchesPrivateKey: "KEY_MISMATCH",
});

/** @param {string} iso */
const seconds = (iso) => Date.parse(iso) / 1000;

/**
 * What a rule says about a certificate, from the dates, the usages and the names alone: what the
 * README's table says makes each code pass. The examples are checked against it so that they
 * cannot show a result the rules would not give.
 * @param {any} result
 * @param {any} entry The entry of the applied policy the result's rule names.
 * @param {any} target
 * @param {string} now
 */
export function checked(result, entry, target, now) {
    const name = result.rule.name;
    const nowSeconds = seconds(now);
    const notBefore = seconds(target.notBefore);
    const notAfter = seconds(target.notAfter);
    const listed = (/** @type {string} */ usage) => target.eku?.includes(usage) ?? false;
    const wanted = (Array.isArray(entry.value) ? entry.value : []).map((/** @type {string} */ usage) => Object.entries(EXTENDED_KEY_USAGE_OIDS).find(([, oid]) => oid === usage)?.[0] ?? usage);
    switch (name) {
        case "validityStarted":
            return { holds: notBefore <= nowSeconds, actual: target.notBefore, expected: now };
        case "validityNotEnded":
            return { holds: notAfter >= nowSeconds, actual: target.notAfter, expected: now };
        case "expiresWithin": {
            const threshold = Number.parseInt(entry.value) * (entry.value.endsWith("d") ? 86400 : 3600);
            return { holds: notAfter - nowSeconds >= threshold, actual: notAfter - nowSeconds, expected: threshold };
        }
        case "maxLifetimeUsed":
            return {
                holds: nowSeconds - notBefore <= entry.value * (notAfter - notBefore),
                actual: notAfter > notBefore ? (nowSeconds - notBefore) / (notAfter - notBefore) : null,
                expected: entry.value,
            };
        case "expectEku":
            return { holds: target.eku !== null && wanted.every(listed), actual: target.eku, expected: wanted };
        case "ekuAllows":
            return { holds: target.eku === null || wanted.every(listed), actual: target.eku, expected: wanted };
        case "rejectEku":
            return { holds: target.eku === null || !wanted.some(listed), actual: target.eku, expected: wanted };
        case "expectSan": {
            const items = entry.value.map(sanItem);
            const expected = {
                dns: items.filter((/** @type {any} */ item) => item.kind === "dns").map((/** @type {any} */ item) => item.name).sort(),
                ip: items.filter((/** @type {any} */ item) => item.kind === "ip").map((/** @type {any} */ item) => item.name).sort(),
            };
            const holds = expected.dns.every((/** @type {string} */ dns) => target.san.dns.includes(dns)) && expected.ip.every((/** @type {string} */ ip) => target.san.ip.includes(ip));
            return { holds, actual: { dns: target.san.dns, ip: target.san.ip }, expected };
        }
        case "expectFingerprint":
            return { holds: target.sha256 === entry.value, actual: target.sha256, expected: entry.value };
        case "expectKind":
            return { holds: target.kind === "end-entity", actual: target.kind, expected: "end-entity" };
        default:
            throw new Error(`no oracle for ${name}`);
    }
}

