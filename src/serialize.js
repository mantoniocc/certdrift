import { ENTRIES } from "./policy.js";

/**
 * How the keys of one kind of object are ordered, and the shape of what is inside it.
 * @typedef {object} Shape
 * @property {string[]} [keys] The keys the contract names, in the order they are written.
 * @property {Record<string, Shape>} [children] The shape of the value under a key.
 * @property {Shape} [items] The shape of every element, for an array.
 */

// The order is the one in `schema/examples/observation/`, which is the reference. It is written
// out here and not read from the schema: the order of properties in a JSON Schema means
// nothing, so reordering them there for readability must not change every saved observation.
/** @type {Shape} */
const name = { keys: ["cn", "dn"] };

/** @type {Shape} */
const certificate = {
    keys: [
        "index", "kind", "selfSigned", "issuedBy", "subject", "issuer", "serial", "notBefore", "notAfter",
        "san", "eku", "key", "sha256", "spkiSha256", "derived",
    ],
    children: {
        subject: name,
        issuer: name,
        san: { keys: ["dns", "ip", "email", "uri"] },
        key: { keys: ["algorithm", "size", "curve"] },
        derived: { keys: ["daysRemaining", "lifetimeFraction"] },
    },
};

// When an observation was made and where its material came from. The observation has it under
// `observation`, and a delta under `before` and `after`, so it is written once.
/** @type {Shape} */
const observed = {
    keys: ["at", "source"],
    children: { source: { keys: ["kind", "ref", "servername", "provider"] } },
};

/** @type {Shape} */
const observation = {
    keys: ["contract", "format", "observation", "target", "certificates", "warnings"],
    children: {
        observation: observed,
        certificates: { items: certificate },
        warnings: { items: { keys: ["code", "certificate", "message"] } },
    },
};

// The order of a check result puts the verdict first and the observation, which is most of the
// bytes, last. The entries of the policy follow the order they are listed in everywhere else,
// and the observation inside it uses the table above, not a copy of it.
/** @type {Shape} */
const checkResult = {
    keys: ["contract", "now", "summary", "results", "policy", "observation"],
    children: {
        summary: { keys: ["status", "pass", "warn", "fail"] },
        results: {
            items: {
                keys: ["code", "status", "rule", "message", "actual", "expected"],
                children: { rule: { keys: ["name", "value"] } },
            },
        },
        policy: {
            keys: ["contract", ...ENTRIES.map(([entry]) => entry)],
            children: Object.fromEntries(ENTRIES.map(([entry]) => [entry, { keys: ["value", "severity"] }])),
        },
        observation,
    },
};

// The two sides come first, as the legend of the changes after them. A change's `before` and
// `after` hold whatever the field holds, so only a link of the chain has keys to order: a value
// of another kind has none and is written as it is.
/** @type {Shape} */
const link = { keys: ["position", "sha256"] };

/** @type {Shape} */
const delta = {
    keys: ["contract", "identical", "before", "after", "changes"],
    children: {
        before: observed,
        after: observed,
        changes: { items: { keys: ["field", "direction", "before", "after"], children: { before: link, after: link } } },
    },
};

/**
 * An observation as the bytes to save, print or compare: the same observation always gives the
 * same text, whatever order the caller built its objects in.
 *
 * The text is JSON with two-space indentation and a single newline at the end, the keys of the
 * contract in the order of `schema/examples/observation/`. A key the contract does not name
 * (a caller's own field in `source`, for instance) is kept, after the named ones and sorted by
 * code unit, so it cannot make two equal observations differ. Arrays keep their order, which
 * means something in them (the certificates are in input order, the warnings as they were found).
 * Text is written as UTF-8 characters, not escaped, except for what JSON requires to be escaped.
 *
 * @param {import("./index.js").Observation} value
 * @returns {string}
 * @throws {TypeError} The argument is not an object, or it contains itself.
 */
export function serializeObservation(value) {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new TypeError("the observation must be an object");
    }
    return `${JSON.stringify(arrange(value, observation, "", new Set(), "observation"), null, 2)}\n`;
}

/**
 * A check result as the bytes to save, print or compare, written the way `serializeObservation`
 * writes an observation: two-space indentation, one newline at the end, the keys of the contract
 * in a fixed order, any other key after them and sorted, arrays in the order they have. The
 * observation inside it is written in the observation's own order. The same check result always
 * gives the same text, whatever order its objects were built in.
 *
 * @param {import("./index.js").CheckResult} value
 * @returns {string}
 * @throws {TypeError} The argument is not an object, or it contains itself.
 */
export function serializeCheckResult(value) {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new TypeError("the check result must be an object");
    }
    return `${JSON.stringify(arrange(value, checkResult, "", new Set(), "check result"), null, 2)}\n`;
}

/**
 * A delta as the bytes to save, print or compare, written the way `serializeCheckResult` writes a
 * check result: two-space indentation, one newline at the end, the keys of the contract in a fixed
 * order, any other key after them and sorted, arrays in the order they have. The `at` and the
 * `source` of each side are written in the order of the observation's own. The same delta always
 * gives the same text, whatever order its objects were built in.
 *
 * A change that was built with a side set to `undefined` is written without it, as `JSON.stringify`
 * does for any property: a side that is absent and a side that is `undefined` are the same, and
 * `null` is the only way to write a side whose value is null.
 *
 * @param {import("./index.js").Delta} value
 * @returns {string}
 * @throws {TypeError} The argument is not an object, or it contains itself.
 */
export function serializeDelta(value) {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new TypeError("the delta must be an object");
    }
    return `${JSON.stringify(arrange(value, delta, "", new Set(), "delta"), null, 2)}\n`;
}

/**
 * A copy of a value whose objects list their keys in the order of the shape, so that
 * `JSON.stringify` writes them that way.
 *
 * A value with a `toJSON` method is replaced by its result first, as `JSON.stringify` would: a
 * `Date` has no own keys and would otherwise be copied as `{}`. Objects are rebuilt with
 * `Object.fromEntries`, which defines every key, where an assignment of `__proto__` (a key
 * `JSON.parse` can produce) would set the prototype and lose it. A key that looks like an array
 * index (`"2"`) is always enumerated first, in numeric order, wherever it is inserted; no key of
 * the contract looks like one, and the order is the same for equal input anyway.
 * @param {unknown} value
 * @param {Shape | undefined} shape
 * @param {string} key The key the value is under, which `toJSON` receives.
 * @param {Set<object>} ancestors The objects being copied, to find a value that contains itself.
 * @param {string} noun What is being written, for the message about a value that contains itself.
 * @returns {unknown}
 * @throws {TypeError}
 */
function arrange(value, shape, key, ancestors, noun) {
    const toJSON = typeof value === "object" && value !== null ? /** @type {{ toJSON?: unknown }} */ (value).toJSON : undefined;
    const plain = typeof toJSON === "function" ? toJSON.call(value, key) : value;
    if (typeof plain !== "object" || plain === null) return plain;

    // Without this, the stack would overflow before JSON.stringify could notice, as it only ever
    // sees the copy.
    if (ancestors.has(plain)) throw new TypeError(`the ${noun} contains itself`);
    ancestors.add(plain);
    try {
        if (Array.isArray(plain)) {
            return plain.map((item, index) => arrange(item, shape?.items, String(index), ancestors, noun));
        }
        const present = Object.keys(plain);
        const named = (shape?.keys ?? []).filter((known) => present.includes(known));
        const others = present.filter((own) => !named.includes(own)).sort();
        return Object.fromEntries(
            [...named, ...others].map((own) => [
                own,
                arrange(/** @type {Record<string, unknown>} */ (plain)[own], shape?.children?.[own], own, ancestors, noun),
            ]),
        );
    } finally {
        ancestors.delete(plain);
    }
}
