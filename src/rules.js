import { outsideValidity } from "./derived.js";
import { sanItem } from "./policy.js";
import { usageName } from "./usage.js";

// What each entry of a policy decides, as the README's table of reason codes says it. A rule reads
// the certificate the observation targets, the instant and its own value, and answers whether it
// holds, what to say about it and what it found against what it required. It does not know the
// severity, the code or the order: `evaluate` writes those, so a rule is only the decision.
//
// Every time here is whole seconds, from the certificate's original dates and never from the
// rounded values in `derived`.

/**
 * The part of the target's observation the rules read.
 * @typedef {object} Target
 * @property {string} notBefore
 * @property {string} notAfter
 * @property {string} kind
 * @property {string} sha256
 * @property {string[] | null} eku
 * @property {{ dns: string[], ip: string[] }} san
 */

/**
 * What a rule is given. `value` is the entry's value, already checked by `policyProblems`.
 * @typedef {object} Input
 * @property {Target} target
 * @property {number} notBefore `target.notBefore` as seconds.
 * @property {number} notAfter `target.notAfter` as seconds.
 * @property {number} now The instant as seconds.
 * @property {string} nowText The same instant as the timestamp the result records.
 * @property {any} value
 */

/**
 * What a rule found, and what it compared it with.
 * @typedef {object} Finding
 * @property {boolean} holds
 * @property {string} message
 * @property {unknown} actual
 * @property {unknown} expected
 */

/** @type {Record<string, (input: Input) => Finding>} */
export const RULES = {
    validityStarted({ target, nowText }) {
        const word = outsideValidity(target.notBefore, target.notAfter, nowText).find((found) => found === "not yet valid");
        return {
            holds: word === undefined,
            message: word === undefined ? `the certificate is valid from ${target.notBefore}` : `the certificate is ${word}: it is valid from ${target.notBefore}`,
            actual: target.notBefore,
            expected: nowText,
        };
    },

    validityNotEnded({ target, nowText }) {
        const word = outsideValidity(target.notBefore, target.notAfter, nowText).find((found) => found === "expired");
        return {
            holds: word === undefined,
            message: word === undefined ? `the certificate is valid until ${target.notAfter}` : `the certificate is ${word}: it was valid until ${target.notAfter}`,
            actual: target.notAfter,
            expected: nowText,
        };
    },

    expiresWithin({ notAfter, now, value }) {
        const unit = value.endsWith("d") ? 86400 : 3600;
        const threshold = Number.parseInt(value, 10) * unit;
        const left = notAfter - now;
        const holds = left >= threshold;
        // Whole units, rounded down: never more time than there is, so "below" and "not below"
        // read the way the comparison went.
        const whole = Math.floor(left / unit);
        const noun = unit === 86400 ? "day" : "hour";
        const remaining = left < 0 ? "the certificate has already ended, so no time is left" : `${whole} ${noun}${whole === 1 ? " is" : "s are"} left`;
        return { holds, message: `${remaining}, ${holds ? "not below" : "below"} ${value}`, actual: left, expected: threshold };
    },

    maxLifetimeUsed({ notBefore, notAfter, now, value }) {
        // The threshold as the decimal its shortest text writes, so 0.57 is 57 hundredths and not
        // the double nearest to it, which times 100 is 56.99999999999999. The comparison is
        // between whole numbers: a validity lasts up to about 3.2e11 seconds, which times a power
        // of ten of the threshold's digits leaves the safe integers.
        const { digits, scale } = decimalOf(value);
        const used = BigInt(now - notBefore);
        const duration = BigInt(notAfter - notBefore);
        const holds = used * 10n ** BigInt(scale) <= digits * duration;
        const threshold = `${percentOf(digits, scale)}%`;
        if (duration <= 0n) {
            return {
                holds,
                message: `no fraction of the lifetime can be worked out, because the validity does not end after it starts, and the rule ${holds ? "holds" : "does not hold"} for ${threshold}`,
                actual: null,
                expected: value,
            };
        }
        // Rounded the way the verdict went, so a message never says "57% used, above 57%".
        const percent = divide(100n * used, duration, holds ? "down" : "up");
        return {
            holds,
            message: `${percent}% of the lifetime is used, ${holds ? "within" : "above"} ${threshold}`,
            actual: (now - notBefore) / (notAfter - notBefore),
            expected: value,
        };
    },

    expectEku({ target, value }) {
        const wanted = usagesOf(value);
        const missing = unique(wanted.filter((usage) => !(target.eku ?? []).includes(usage)));
        // An absent extension lists nothing, so every usage is missing and it fails like an empty one.
        const holds = missing.length === 0;
        return {
            holds,
            message: holds ? `${ekuState(target.eku)}, which includes ${unique(wanted).join(", ")}` : `${ekuState(target.eku)}, so it does not list ${missing.join(", ")}`,
            actual: target.eku,
            expected: wanted,
        };
    },

    ekuAllows({ target, value }) {
        const wanted = usagesOf(value);
        const missing = unique(wanted.filter((usage) => !(target.eku ?? []).includes(usage)));
        const holds = target.eku === null || missing.length === 0;
        return {
            holds,
            message: target.eku === null ? `${ekuState(target.eku)}, which restricts nothing` : holds ? `${ekuState(target.eku)}, which includes ${unique(wanted).join(", ")}` : `${ekuState(target.eku)}, which does not include ${missing.join(", ")}`,
            actual: target.eku,
            expected: wanted,
        };
    },

    rejectEku({ target, value }) {
        const wanted = usagesOf(value);
        const listed = unique(wanted.filter((usage) => (target.eku ?? []).includes(usage)));
        const holds = listed.length === 0;
        return {
            holds,
            message: holds ? `${ekuState(target.eku)}, which does not include ${unique(wanted).join(", ")}` : `${ekuState(target.eku)}, which includes ${listed.join(", ")}`,
            actual: target.eku,
            expected: wanted,
        };
    },

    expectSan({ target, value }) {
        const items = /** @type {{ kind: "ip" | "dns", name: string }[]} */ (value.map(sanItem));
        const expected = {
            dns: items.filter((item) => item.kind === "dns").map((item) => item.name).sort(),
            ip: items.filter((item) => item.kind === "ip").map((item) => item.name).sort(),
        };
        // Sets, because a certificate can list thousands of names and a policy can ask for as many.
        const listed = { dns: new Set(target.san.dns), ip: new Set(target.san.ip) };
        const missing = unique([...expected.dns.filter((name) => !listed.dns.has(name)), ...expected.ip.filter((address) => !listed.ip.has(address))]);
        return {
            holds: missing.length === 0,
            message: missing.length === 0 ? "the certificate lists every expected name" : `the certificate does not list ${missing.join(", ")}`,
            actual: { dns: [...target.san.dns], ip: [...target.san.ip] },
            expected,
        };
    },

    expectFingerprint({ target, value }) {
        const holds = target.sha256 === value;
        return {
            holds,
            message: holds ? "the certificate has the expected fingerprint" : "the certificate does not have the expected fingerprint",
            actual: target.sha256,
            expected: value,
        };
    },

    expectKind({ target }) {
        const holds = target.kind === "end-entity";
        return {
            holds,
            message: holds ? "the target is an end-entity certificate" : `the target's kind is ${target.kind}, not end-entity`,
            actual: target.kind,
            expected: "end-entity",
        };
    },
};

/**
 * What the certificate says about Extended Key Usage, as the start of a message. An absent
 * extension and one that lists nothing are different, and each says so.
 * @param {string[] | null} eku
 */
function ekuState(eku) {
    if (eku === null) return "the certificate has no Extended Key Usage extension";
    if (eku.length === 0) return "the Extended Key Usage extension lists nothing";
    return `the Extended Key Usage extension lists ${eku.join(", ")}`;
}

/**
 * The usages of an entry as the observation names them, in the order and with the repeats the policy
 * wrote, so each is still the one at its position in the entry's value.
 * @param {string[]} value
 * @returns {string[]}
 */
function usagesOf(value) {
    return value.map((usage) => usageName(usage));
}

/**
 * @param {string[]} list
 * @returns {string[]}
 */
function unique(list) {
    return [...new Set(list)];
}

/**
 * A number between 0 and 1 as the decimal its shortest text writes: `digits` over ten to the
 * `scale`. `String` gives the shortest text that reads back as the same number (`0.57`), and
 * switches to an exponent below 1e-6 (`1e-7`, `5e-324`).
 * @param {number} value
 * @returns {{ digits: bigint, scale: number }}
 */
function decimalOf(value) {
    const [, whole, fraction = "", exponent = "0"] = /** @type {RegExpExecArray} */ (/^(\d+)(?:\.(\d+))?(?:e-(\d+))?$/.exec(String(value)));
    return { digits: BigInt(whole + fraction), scale: fraction.length + Number(exponent) };
}

/**
 * The threshold as a percentage, exactly: `digits` over ten to the `scale`, times a hundred.
 * @param {bigint} digits
 * @param {number} scale
 */
function percentOf(digits, scale) {
    if (scale <= 2) return String(digits * 10n ** BigInt(2 - scale));
    // The shortest text of a number never ends in a zero, so neither does the fraction here.
    const places = scale - 2;
    const text = String(digits).padStart(places + 1, "0");
    return `${text.slice(0, text.length - places)}.${text.slice(text.length - places)}`;
}

/**
 * A division of whole numbers rounded down or up, for a positive divisor. BigInt division
 * truncates toward zero, which is neither once the dividend is negative.
 * @param {bigint} dividend
 * @param {bigint} divisor
 * @param {"down" | "up"} direction
 * @returns {bigint}
 */
function divide(dividend, divisor, direction) {
    const quotient = dividend / divisor;
    const remainder = dividend % divisor;
    if (direction === "down") return remainder < 0n ? quotient - 1n : quotient;
    return remainder > 0n ? quotient + 1n : quotient;
}
