// A copy of a value that JSON can hold, made without running anything the value owns.
//
// `structuredClone` is not used: it calls getters, throws a `DOMException` on a function or a
// proxy, and overflows the stack at about five thousand levels, while the serializer overflows at
// about two thousand. This copy reads data properties only, stops at a depth far below both, and
// stops at a number of values, because a value that refers to the same list twice at every level
// is small to write and has a copy of exponential size.

/** The deepest nesting copied: far more than any observation or result holds, far below the stack. */
const MAX_DEPTH = 100;

/** The most values copied: an observation of thousands of certificates is a fraction of this. */
const MAX_VALUES = 1_000_000;

/**
 * Whether a value is an object JSON can hold: plain (or with no prototype) and not an array.
 * @param {unknown} value
 * @returns {value is Record<string, unknown>}
 */
export function isPlain(value) {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}

/**
 * The value of an own data property, without calling an accessor. `undefined` for an accessor and
 * for a property that is not there.
 * @param {object} object
 * @param {string} key
 * @returns {unknown}
 */
export function dataOf(object, key) {
    // The descriptor of an accessor has no `value`, so it reads as `undefined` without being called.
    return Object.getOwnPropertyDescriptor(object, key)?.value;
}

/**
 * @typedef {{ ok: true, value: unknown } | { ok: false, path: string, reason: string }} Copy
 */

/**
 * A copy of a value made only of what JSON holds: `null`, booleans, strings, finite numbers, lists
 * and plain objects. Nothing in the copy is shared with the value, and a key such as `__proto__`
 * stays an own key. A property that is not enumerable, a key that is a symbol and a property of a
 * list that is not an index are not copied, as `JSON.stringify` leaves them out.
 *
 * It fails, and says where and why, for anything else: a function, `undefined`, a BigInt, a symbol,
 * `NaN` or an infinity, an object with a prototype of its own, a list with a gap, an accessor
 * (which is never called), a value that contains itself, nesting deeper than 100 levels, more than
 * a million values, and an object that throws when it is read, such as a revoked proxy.
 * @param {unknown} value
 * @param {{ freeze?: boolean }} [options] `freeze` freezes every object and list of the copy.
 * @returns {Copy}
 */
export function copyJson(value, options) {
    const freeze = options?.freeze === true;
    let count = 0;
    /** @type {Set<object>} */
    const ancestors = new Set();

    /**
     * @param {unknown} found
     * @param {Frame | null} frame Where the value is: its key and the object it is in.
     * @param {number} depth
     * @returns {unknown}
     */
    const walk = (found, frame, depth) => {
        count += 1;
        if (count > MAX_VALUES) throw new Unwritable(frame, "is past the million values that are copied");
        if (found === null || typeof found === "string" || typeof found === "boolean") return found;
        if (typeof found === "number") {
            if (!Number.isFinite(found)) throw new Unwritable(frame, "is not a finite number");
            return found;
        }
        if (typeof found !== "object") throw new Unwritable(frame, `is ${found === undefined ? "undefined" : `a ${typeof found}`}`);
        if (ancestors.has(found)) throw new Unwritable(frame, "contains itself");
        if (depth >= MAX_DEPTH) throw new Unwritable(frame, `is nested deeper than ${MAX_DEPTH} levels`);
        const list = Array.isArray(found);
        if (!list && !isPlain(found)) throw new Unwritable(frame, "is not a plain object or a list");
        // Checked before the keys are listed: a sparse list can claim four billion of them.
        if (list && found.length > MAX_VALUES - count) throw new Unwritable(frame, "is past the million values that are copied");

        ancestors.add(found);
        /** @type {[string, unknown][]} */
        const entries = [];
        const keys = list ? Array.from({ length: found.length }, (_, index) => String(index)) : Object.keys(found);
        for (const key of keys) {
            /** @type {Frame} */
            const here = { key, parent: frame };
            const descriptor = Object.getOwnPropertyDescriptor(found, key);
            if (descriptor === undefined) throw new Unwritable(here, "is missing from a list that has a gap");
            if (!("value" in descriptor)) throw new Unwritable(here, "is an accessor");
            entries.push([key, walk(descriptor.value, here, depth + 1)]);
        }
        ancestors.delete(found);

        const copy = list ? entries.map(([, item]) => item) : Object.fromEntries(entries);
        return freeze ? Object.freeze(copy) : copy;
    };

    try {
        return { ok: true, value: walk(value, null, 0) };
    } catch (error) {
        if (error instanceof Unwritable) return { ok: false, path: pointerTo(error.frame), reason: error.reason };
        // A proxy trap, or anything else the value runs when it is read.
        return { ok: false, path: "", reason: "cannot be read" };
    }
}

/**
 * Where a value is: its key and the frame of the object it is in, `null` for the value itself.
 * @typedef {{ key: string, parent: Frame | null }} Frame
 */

/**
 * A JSON Pointer (RFC 6901) to a place, built only when a value is refused: building one for every
 * value would make a copy of a million of them cost as much again in strings.
 * @param {Frame | null} frame
 * @returns {string}
 */
function pointerTo(frame) {
    /** @type {string[]} */
    const tokens = [];
    for (let level = frame; level !== null; level = level.parent) tokens.push(level.key.replaceAll("~", "~0").replaceAll("/", "~1"));
    return tokens.reverse().map((token) => `/${token}`).join("");
}

/** Why a value cannot be copied, and where. Never leaves this file. */
class Unwritable extends Error {
    /**
     * @param {Frame | null} frame
     * @param {string} reason
     */
    constructor(frame, reason) {
        super(reason);
        this.frame = frame;
        this.reason = reason;
    }
}
