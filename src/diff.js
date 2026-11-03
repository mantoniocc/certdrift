import { ContractMismatchError } from "./errors.js";
import { MAX_VALUES, copyJson, dataOf, isPlain } from "./json.js";
import { SHA256 } from "./policy.js";

/** @import { Change, Delta, Observation, Source } from "./index.js" */

// What a value of each kind must be. Each is the whole check of its kind, so a field is described
// by naming its kind below and a new field cannot forget to check its value.
/** @type {Record<"text" | "textOrNull" | "flag" | "sizeOrNull" | "hash", [(value: unknown) => boolean, string]>} */
const KINDS = {
    text: [(/** @type {unknown} */ value) => typeof value === "string", "text"],
    textOrNull: [(/** @type {unknown} */ value) => value === null || typeof value === "string", "text or null"],
    flag: [(/** @type {unknown} */ value) => typeof value === "boolean", "true or false"],
    sizeOrNull: [(/** @type {unknown} */ value) => value === null || Number.isInteger(value), "a whole number or null"],
    hash: [(/** @type {unknown} */ value) => typeof value === "string" && SHA256.test(value), "64 lowercase hexadecimal characters"],
};

// The fields of the target that are compared, in the order of `changes`, which is the order the
// schema lists them in; the chain comes after all of them. `set` is a list compared as a set, and
// `usages` is the Extended Key Usage, a set that can also be `null`.
const FIELDS = /** @type {const} */ ([
    ["kind", "text"], ["selfSigned", "flag"], ["subject.cn", "textOrNull"], ["subject.dn", "text"],
    ["issuer.cn", "textOrNull"], ["issuer.dn", "text"], ["serial", "text"],
    ["notBefore", "text"], ["notAfter", "text"],
    ["san.dns", "set"], ["san.ip", "set"], ["san.email", "set"], ["san.uri", "set"], ["eku", "usages"],
    ["key.algorithm", "textOrNull"], ["key.size", "sizeOrNull"], ["key.curve", "textOrNull"],
    ["sha256", "hash"], ["spkiSha256", "hash"],
]);

/**
 * Says what changed between two observations of a certificate, in the shape of
 * `schema/delta.schema.json`, and judges nothing: whether a change matters is for whoever reads it.
 *
 * The first observation is `before` and the second is `after`, for the whole result: a change
 * `removed` was in `before` and is not in `after`. Neither says which is older.
 *
 * The target of each observation (the certificate its `target` points at) is compared field by
 * field, each as the observation writes it, which is already normalized: a field that is not a set
 * is `changed` when the two values differ, `null` included, and is absent when they are equal. The
 * SAN lists and the Extended Key Usage are sets: an element that is only on one side is `added` or
 * `removed`, one change each, and how many times a list repeats it is not compared. The Extended
 * Key Usage going between `null` (no extension, any purpose) and a list (`[]` included, which allows
 * nothing) is one `changed` with the whole value on each side. The chain is the other certificates of
 * the observation, told apart by their `sha256`: a link that only one side sends is `removed` or
 * `added`, and the links both send in another relative order are one `changed`. A link repeated in
 * one observation counts once, at its first position. `identical` is about the two targets only.
 *
 * Not compared: `warnings`, `derived`, `observation.at` and `observation.source` (the last two are
 * the legend of the result), and `issuedBy`, `index` and `target`, which are positions inside one
 * observation. A difference between two certificates is never an error.
 *
 * It reads only the fields it uses, as own data properties and once (an accessor is never called),
 * and nothing it was given is changed or shared with the result.
 *
 * @param {Observation} before As `inspect()` returns it.
 * @param {Observation} after As `inspect()` returns it.
 * @returns {Delta}
 * @throws {import("./errors.js").ContractMismatchError} The two do not have the same `contract` or the
 *   same `format`; `field` says which.
 * @throws {TypeError} An argument is not an observation this function can read, or both have a
 *   `contract` or a `format` this version does not know. The message names what is wrong and never
 *   quotes a value other than a contract number.
 */
export function diff(before, after) {
    const budget = { left: MAX_VALUES };
    const first = headerOf(before, "before");
    const second = headerOf(after, "after");
    // Before anything else is read: another contract may have another shape.
    if (first.contract !== second.contract) {
        throw new ContractMismatchError("contract", `the observations do not have the same contract: before has ${first.contract} and after has ${second.contract}`);
    }
    if (first.format !== second.format) throw new ContractMismatchError("format", "the observations do not have the same format");
    if (first.contract !== 1) throw new TypeError("contract must be 1 in both observations");
    if (first.format !== "x509") throw new TypeError('format must be "x509" in both observations');

    const left = readable(before, "before", budget);
    const right = readable(after, "after", budget);

    /** @type {Change[]} */
    const changes = [];
    for (const [field, kind] of FIELDS) {
        const was = left.values.get(field);
        const is = right.values.get(field);
        if (kind === "set") append(changes, setChanges(field, /** @type {string[]} */ (was), /** @type {string[]} */ (is)));
        else if (kind === "usages") append(changes, usageChanges(/** @type {string[] | null} */ (was), /** @type {string[] | null} */ (is)));
        else if (was !== is) changes.push({ field, direction: "changed", before: was, after: is });
    }
    append(changes, chainChanges(left.links, right.links));
    return {
        contract: 1,
        identical: left.values.get("sha256") === right.values.get("sha256"),
        before: left.side,
        after: right.side,
        changes,
    };
}

// ---------------------------------------------------------------------------------------------
// The changes

/**
 * Adds changes to a list one at a time. `list.push(...more)` hands every element to the call as an
 * argument, and a list of a hundred thousand overflows the stack, which two lists of that many
 * names that have nothing in common would make.
 * @param {Change[]} changes
 * @param {Change[]} more
 */
function append(changes, more) {
    for (const change of more) changes.push(change);
}

/**
 * One change for each element that is only on one side: first those that left, then those that
 * arrived, each in the order of the list it comes from. A repeated element is one element.
 * @param {string} field
 * @param {string[]} was
 * @param {string[]} is
 * @returns {Change[]}
 */
function setChanges(field, was, is) {
    const inWas = new Set(was);
    const inIs = new Set(is);
    return [
        ...[...inWas].filter((element) => !inIs.has(element)).map((element) => ({ field, direction: /** @type {const} */ ("removed"), before: element })),
        ...[...inIs].filter((element) => !inWas.has(element)).map((element) => ({ field, direction: /** @type {const} */ ("added"), after: element })),
    ];
}

/**
 * The Extended Key Usage. `null` is the extension absent, which allows any purpose, and a list is
 * the extension present: a change between the two carries the whole value of each side, because a
 * change that named only the elements could not say `null`. Between two lists it is a set.
 * @param {string[] | null} was
 * @param {string[] | null} is
 * @returns {Change[]}
 */
function usageChanges(was, is) {
    if (was === null || is === null) {
        return was === is ? [] : [{ field: "eku", direction: "changed", before: was, after: is }];
    }
    return setChanges("eku", was, is);
}

/**
 * @typedef {object} Link
 * @property {number} position Among the certificates other than the target, from 0.
 * @property {string} sha256
 */

/**
 * A link only one side sends is `removed` (with its position in `before`) or `added` (with its
 * position in `after`), so a replacement is one of each at the same position and a link that moves
 * only because another came or went before it is no change. The links both sides send are one
 * `changed` when they are in another relative order.
 * @param {Link[]} was
 * @param {Link[]} is
 * @returns {Change[]}
 */
function chainChanges(was, is) {
    const inWas = new Set(was.map((link) => link.sha256));
    const inIs = new Set(is.map((link) => link.sha256));
    const kept = (/** @type {Link[]} */ links, /** @type {Set<string>} */ other) => links.filter((link) => other.has(link.sha256)).map((link) => link.sha256);
    // The same links on both sides, so the two lists are as long as each other.
    const keptWas = kept(was, inIs);
    const keptIs = kept(is, inWas);
    /** @type {Change[]} */
    const changes = [
        ...was.filter((link) => !inIs.has(link.sha256)).map((link) => ({ field: "chain", direction: /** @type {const} */ ("removed"), before: link })),
        ...is.filter((link) => !inWas.has(link.sha256)).map((link) => ({ field: "chain", direction: /** @type {const} */ ("added"), after: link })),
    ];
    if (keptWas.some((sha256, index) => sha256 !== keptIs[index])) {
        changes.push({ field: "chain", direction: "changed", before: keptWas, after: keptIs });
    }
    return changes;
}

// ---------------------------------------------------------------------------------------------
// Reading an observation

/**
 * Errors this file raised on purpose, so that `guarded` can tell them from what an object throws
 * while it is being read (a proxy's trap), which looks the same: a revoked proxy raises a
 * `TypeError` of its own.
 * @type {WeakSet<object>}
 */
const OURS = new WeakSet();

/**
 * @param {string} message
 * @returns {TypeError}
 */
function wrong(message) {
    const error = new TypeError(message);
    OURS.add(error);
    return error;
}

/**
 * Runs a reader of one argument. What it refuses is a `TypeError` that names the place; what the
 * object itself throws is a `TypeError` that says it cannot be read, with nothing of the object in it.
 * @template T
 * @param {string} name The argument: `before` or `after`.
 * @param {() => T} read
 * @returns {T}
 * @throws {TypeError}
 */
function guarded(name, read) {
    try {
        return read();
    } catch (error) {
        if (OURS.has(/** @type {object} */ (error))) throw error;
        throw new TypeError(`${name} cannot be read`);
    }
}

/**
 * @param {keyof typeof KINDS} kind
 * @param {unknown} value
 * @param {string} path Where the value is, for the message.
 * @returns {any} The value, which is of the kind.
 * @throws {TypeError}
 */
function checked(kind, value, path) {
    const [holds, what] = KINDS[kind];
    if (!holds(value)) throw wrong(`${path} must be ${what}`);
    return value;
}

/**
 * Takes `count` values from what an observation may hold, which is a million for both together. A
 * list can claim more than any memory holds (a sparse one claims four billion), so it is charged
 * before it is walked.
 * @param {{ left: number }} budget
 * @param {number} count
 * @param {string} path
 * @throws {TypeError}
 */
function take(budget, count, path) {
    budget.left -= count;
    if (budget.left < 0) throw wrong(`${path} is past the million values that are read`);
}

/**
 * The version of an observation: its `contract` and its `format`, the only fields read before the
 * two are known to be of the same kind.
 * @param {unknown} given
 * @param {string} name
 * @returns {{ contract: number, format: string }}
 * @throws {TypeError}
 */
function headerOf(given, name) {
    return guarded(name, () => {
        if (!isPlain(given)) throw wrong(`${name} must be an observation: an object`);
        const contract = dataOf(given, "contract");
        if (!Number.isInteger(contract)) throw wrong(`${name}.contract must be a whole number`);
        return { contract: /** @type {number} */ (contract), format: checked("text", dataOf(given, "format"), `${name}.format`) };
    });
}

/**
 * The value at a dotted path of the target (`subject.cn`), the objects on the way being checked.
 * @param {unknown} certificate
 * @param {string} field
 * @param {string} from Where the certificate is, for the message.
 * @returns {unknown}
 * @throws {TypeError}
 */
function valueAt(certificate, field, from) {
    /** @type {unknown} */
    let value = certificate;
    let where = from;
    for (const key of field.split(".")) {
        if (!isPlain(value)) throw wrong(`${where} must be an object`);
        value = dataOf(value, key);
        where += `.${key}`;
    }
    return value;
}

/**
 * A list of text as a new array, each element read once as an own data property. A hole reads as
 * `undefined`, which is not text.
 * @param {unknown} value
 * @param {string} path
 * @param {{ left: number }} budget
 * @returns {string[]}
 * @throws {TypeError}
 */
function listOf(value, path, budget) {
    if (!Array.isArray(value)) throw wrong(`${path} must be a list of text`);
    take(budget, value.length, path);
    return Array.from({ length: value.length }, (_, index) => {
        const item = dataOf(value, String(index));
        if (typeof item !== "string") throw wrong(`${path}[${index}] must be text`);
        return item;
    });
}

/**
 * What the comparison reads of an observation, checked and copied: the legend of its side, the
 * value of each compared field of the target, and the links of its chain. Everything else in the
 * observation is left unread.
 * @param {unknown} given Known to be an object with a `contract` and a `format`.
 * @param {string} name
 * @param {{ left: number }} budget
 * @returns {{ side: { at: string, source: Source }, values: Map<string, unknown>, links: Link[] }}
 * @throws {TypeError}
 */
function readable(given, name, budget) {
    return guarded(name, () => {
        const observed = dataOf(/** @type {object} */ (given), "observation");
        if (!isPlain(observed)) throw wrong(`${name}.observation must be an object`);
        const at = checked("text", dataOf(observed, "at"), `${name}.observation.at`);
        const written = dataOf(observed, "source");
        if (!isPlain(written)) throw wrong(`${name}.observation.source must be an object`);
        const source = copyJson(written);
        if (!source.ok) {
            throw wrong(`${name}.observation.source holds something JSON cannot, at ${source.path === "" ? "the top" : source.path}: it ${source.reason}`);
        }

        const certificates = dataOf(/** @type {object} */ (given), "certificates");
        const target = dataOf(/** @type {object} */ (given), "target");
        const lost = `${name}.target must be the position of a certificate in ${name}.certificates`;
        if (!Array.isArray(certificates) || !Number.isInteger(target)) throw wrong(lost);
        const certificate = dataOf(certificates, String(target));
        if (!isPlain(certificate)) throw wrong(lost);

        const where = `${name}.certificates[${target}]`;
        /** @type {Map<string, unknown>} */
        const values = new Map();
        for (const [field, kind] of FIELDS) {
            const path = `${where}.${field}`;
            const value = valueAt(certificate, field, where);
            if (kind === "set") values.set(field, listOf(value, path, budget));
            else if (kind === "usages") values.set(field, value === null ? null : listOf(value, path, budget));
            else values.set(field, checked(kind, value, path));
        }

        // The chain: every certificate but the target, told apart by its sha256. The position counts
        // them all, a repeat included, and a repeat is kept only where it first appears.
        take(budget, certificates.length, `${name}.certificates`);
        /** @type {Map<string, Link>} */
        const links = new Map();
        let position = 0;
        for (let index = 0; index < certificates.length; index += 1) {
            if (index === target) continue;
            const other = dataOf(certificates, String(index));
            if (!isPlain(other)) throw wrong(`${name}.certificates[${index}] must be an object`);
            const sha256 = checked("hash", dataOf(other, "sha256"), `${name}.certificates[${index}].sha256`);
            if (!links.has(sha256)) links.set(sha256, { position, sha256 });
            position += 1;
        }

        return { side: { at, source: /** @type {Source} */ (source.value) }, values, links: [...links.values()] };
    });
}
