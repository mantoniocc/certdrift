import { canonicalAddress } from "./san.js";
import { EXTENDED_KEY_USAGE_OIDS } from "./usage.js";

// The shape check of a policy, written by hand: the package has no JSON Schema validator at run
// time (Ajv is a development dependency), so `schema/policy.schema.json` cannot be what rejects a
// bad policy. A test compares this code with the schema on valid and invalid policies, and
// compares the patterns below with the schema's own text, so the two cannot drift apart.
//
// A policy is a portable JSON document. The check refuses everything JSON cannot hold, at any
// depth and under any key, the ones this version does not know included: a function put in a
// policy by mistake (an own rule belongs to the function that evaluates, not to the document)
// would otherwise be ignored without a word.

/** A duration the way `expiresWithin` writes it: whole days or whole hours, at most six digits. */
export const DURATION = /^[1-9][0-9]{0,5}[dh]$/;

const LABEL = "[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?";
// Resolvers read a last label that is a number as part of an IPv4 address (`127.1` is 127.0.0.1,
// `0x7f.0.0.1` is too), so a name ending in one could never be what a certificate lists.
const NUMBER = "(?:[0-9]+|0[xX][0-9A-Fa-f]*)";

/**
 * A DNS name an `expectSan` entry may list: dot separated labels of ASCII letters, digits, hyphens
 * and underscores, optionally starting with a `*.` label, the last label not a number. At most
 * 253 characters, which this pattern does not check.
 */
export const DNS_NAME = new RegExp(`^(?:\\*\\.)?(?:${LABEL}\\.)*(?!${NUMBER}$)${LABEL}$`);

/** The longest a DNS name may be. */
export const DNS_NAME_LENGTH = 253;

/** A usage in an Extended Key Usage entry: one of the names the contract knows, or an OID. */
export const OID = /^[0-2](?:\.(?:0|[1-9][0-9]*)){1,}$/;

/** A SHA-256 digest as the observation writes it. */
export const SHA256 = /^[0-9a-f]{64}$/;

const SEVERITIES = ["fail", "warn"];

/** @typedef {"none" | "duration" | "fraction" | "usages" | "names" | "sha256" | "end-entity"} ValueKind */

/**
 * The entries of a policy and what each takes as `value` (`none` for an entry that has only a
 * severity), in the order they are written everywhere: the schema, the serializer, the README and
 * the results.
 * @type {readonly (readonly [string, ValueKind])[]}
 */
export const ENTRIES = Object.freeze(/** @type {(readonly [string, ValueKind])[]} */ ([
    ["validityStarted", "none"],
    ["validityNotEnded", "none"],
    ["expiresWithin", "duration"],
    ["maxLifetimeUsed", "fraction"],
    ["expectEku", "usages"],
    ["ekuAllows", "usages"],
    ["rejectEku", "usages"],
    ["expectSan", "names"],
    ["expectFingerprint", "sha256"],
    ["expectKind", "end-entity"],
    ["matchesPrivateKey", "none"],
]));

/**
 * How an `expectSan` item is read: an IP address exactly when `canonicalAddress` accepts it, which
 * is also the form it is compared in; otherwise a DNS name, compared in lower case as the
 * observation writes `san.dns`; otherwise `null`, since nothing a certificate lists could be it.
 * @param {string} text
 * @returns {{ kind: "ip" | "dns", name: string } | null}
 */
export function sanItem(text) {
    const address = canonicalAddress(text);
    if (address !== null) return { kind: "ip", name: address };
    if (text.length > DNS_NAME_LENGTH || !DNS_NAME.test(text)) return null;
    return { kind: "dns", name: text.replace(/[A-Z]/g, (letter) => letter.toLowerCase()) };
}

/**
 * Whether a policy has the shape that evaluating it reads, and if not, everything that is wrong.
 * An empty list means it is valid. A property or an entry this version does not know is
 * tolerated, as long as what it holds is JSON.
 *
 * It does not call code of the policy: a property that is an accessor is a problem and is not
 * read. It lists at most 100 problems that come from values JSON cannot hold, which is enough to
 * find them and keeps a policy full of them from producing an answer as long as itself.
 * @param {unknown} policy
 * @returns {import("./index.js").PolicyProblem[]}
 */
export function policyProblems(policy) {
    try {
        return problemsOf(policy);
    } catch {
        // An object that throws when its prototype or its properties are read, such as a revoked
        // proxy, is not something JSON can hold either.
        return [{ path: "", message: "the policy cannot be read as a JSON object" }];
    }
}

/**
 * @param {unknown} policy
 * @returns {import("./index.js").PolicyProblem[]}
 */
function problemsOf(policy) {
    if (!isPlain(policy)) return [{ path: "", message: "the policy must be a JSON object" }];

    const problems = jsonProblems(policy);

    if (!Object.hasOwn(policy, "contract")) {
        problems.push({ path: "/contract", message: "is required" });
    } else if (isData(policy, "contract") && dataOf(policy, "contract") !== 1) {
        const contract = dataOf(policy, "contract");
        const given = typeof contract === "number" ? ` ${contract}` : "";
        problems.push({ path: "/contract", message: `contract${given} is not one this version knows: it must be 1` });
    }

    for (const [name, value] of ENTRIES) {
        // An accessor was reported with the values JSON cannot hold, and is not read again here.
        if (!Object.hasOwn(policy, name) || !isData(policy, name)) continue;
        const entry = dataOf(policy, name);
        const path = `/${name}`;
        if (!isPlain(entry)) {
            problems.push({ path, message: "must be an object" });
            continue;
        }
        if (Object.hasOwn(entry, "severity") && isData(entry, "severity") && !SEVERITIES.includes(/** @type {string} */ (dataOf(entry, "severity")))) {
            problems.push({ path: `${path}/severity`, message: `must be "fail" or "warn"` });
        }
        if (value === "none") continue;
        if (!Object.hasOwn(entry, "value")) {
            problems.push({ path: `${path}/value`, message: "is required" });
            continue;
        }
        if (!isData(entry, "value")) continue;
        const reason = valueProblem(value, dataOf(entry, "value"));
        if (reason !== null) problems.push({ path: `${path}/value`, message: reason });
    }
    return problems;
}

/**
 * What is wrong with the value of an entry, or `null`.
 * @param {ValueKind} kind
 * @param {unknown} value
 * @returns {string | null}
 */
function valueProblem(kind, value) {
    switch (kind) {
        case "duration":
            return typeof value === "string" && DURATION.test(value) ? null : "must be a whole number of days or hours, such as 30d or 72h, of at most six digits";
        case "fraction":
            return typeof value === "number" && value >= 0 && value <= 1 ? null : "must be a number from 0 to 1";
        case "sha256":
            return typeof value === "string" && SHA256.test(value) ? null : "must be 64 lowercase hexadecimal characters";
        case "end-entity":
            return value === "end-entity" ? null : `must be "end-entity"`;
        case "usages":
            return nonEmptyList(value, (usage) => typeof usage === "string" && (Object.hasOwn(EXTENDED_KEY_USAGE_OIDS, usage) || OID.test(usage)));
        case "names":
            return nonEmptyList(value, (name) => typeof name === "string" && sanItem(name) !== null);
        default:
            return null;
    }
}

/**
 * What is wrong with a list that must hold at least one item, each satisfying a test, or `null`.
 * The message says which item, by position, and never what it holds.
 * @param {unknown} value
 * @param {(item: unknown) => boolean} accepts
 * @returns {string | null}
 */
function nonEmptyList(value, accepts) {
    if (!Array.isArray(value) || value.length === 0) return "must be a list with at least one item";
    const position = value.findIndex((item) => !accepts(item));
    return position === -1 ? null : `item ${position} is not one this entry accepts`;
}

/**
 * Whether a value is an object JSON can hold: plain (or with no prototype) and not an array.
 * @param {unknown} value
 * @returns {value is Record<string, unknown>}
 */
function isPlain(value) {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}

/**
 * Whether an own property is a data property, as opposed to an accessor, without calling it.
 * @param {Record<string, unknown>} object
 * @param {string} key
 */
function isData(object, key) {
    const descriptor = Object.getOwnPropertyDescriptor(object, key);
    return descriptor !== undefined && "value" in descriptor;
}

/**
 * The value of an own data property, without calling an accessor. `undefined` for an accessor.
 * @param {Record<string, unknown>} object
 * @param {string} key
 */
function dataOf(object, key) {
    const descriptor = Object.getOwnPropertyDescriptor(object, key);
    return descriptor !== undefined && "value" in descriptor ? descriptor.value : undefined;
}

/** The most problems listed: a document with thousands of bad values does not need thousands of lines. */
const MAX_PROBLEMS = 100;

/**
 * One level of the walk: the object, the key it was found under and the level it is in.
 * @typedef {{ value: object, key: string, parent: Level | null }} Level
 */

/**
 * A JSON Pointer (RFC 6901) to a key under a level, built only when a problem is reported: a
 * path kept for every level would take time and memory in proportion to the square of the depth.
 * @param {Level | null} parent
 * @param {string} key
 */
function pointerTo(parent, key) {
    const tokens = [key];
    for (let level = parent; level !== null && level.parent !== null; level = level.parent) tokens.push(level.key);
    return tokens.reverse().map((token) => `/${token.replaceAll("~", "~0").replaceAll("/", "~1")}`).join("");
}

/**
 * Every place under the root that JSON cannot hold, in depth-first order with keys sorted so the
 * same policy always lists the same problems in the same order, up to `MAX_PROBLEMS`.
 *
 * It walks with a stack of its own: `JSON.parse` accepts nesting far deeper than the call stack
 * allows, so a recursive walk would throw `RangeError` on a policy that is valid JSON.
 * @param {Record<string, unknown>} root
 * @returns {import("./index.js").PolicyProblem[]}
 */
function jsonProblems(root) {
    /** @type {import("./index.js").PolicyProblem[]} */
    const problems = [];
    /** @type {{ level: Level, leaving: boolean }[]} */
    const stack = [{ level: { value: root, key: "", parent: null }, leaving: false }];
    const ancestors = new Set();

    while (stack.length > 0 && problems.length < MAX_PROBLEMS) {
        const { level, leaving } = /** @type {{ level: Level, leaving: boolean }} */ (stack.pop());
        if (leaving) {
            ancestors.delete(level.value);
            continue;
        }
        ancestors.add(level.value);
        stack.push({ level, leaving: true });

        const keys = Array.isArray(level.value) ? Array.from({ length: level.value.length }, (_, index) => String(index)) : Object.keys(level.value).sort();
        /** @type {typeof stack} */
        const children = [];
        for (const key of keys) {
            if (problems.length >= MAX_PROBLEMS) break;
            /** @param {string} message */
            const report = (message) => problems.push({ path: pointerTo(level, key), message });
            const descriptor = Object.getOwnPropertyDescriptor(level.value, key);
            if (descriptor === undefined) {
                report("is missing from a list that has a gap here");
                continue;
            }
            if (!("value" in descriptor)) {
                report("is an accessor, which JSON cannot hold");
                continue;
            }
            const value = descriptor.value;
            if (typeof value === "object" && value !== null) {
                if (ancestors.has(value)) report("contains itself, which JSON cannot hold");
                else if (!Array.isArray(value) && !isPlain(value)) report("is not a plain object, which JSON cannot hold");
                else children.push({ level: { value, key, parent: level }, leaving: false });
            } else if (typeof value === "number") {
                if (!Number.isFinite(value)) report("is not a finite number, which JSON cannot hold");
            } else if (typeof value !== "string" && typeof value !== "boolean" && value !== null) {
                report(`is ${typeof value === "undefined" ? "undefined" : `a ${typeof value}`}, which JSON cannot hold`);
            }
        }
        // Pushed in reverse so that the first child is the next one walked.
        for (const child of children.reverse()) stack.push(child);
    }
    return problems;
}
