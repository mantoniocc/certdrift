import { test } from "node:test";
import assert from "node:assert/strict";
import { runInNewContext } from "node:vm";
import { copyJson, dataOf, isPlain } from "../src/json.js";

// The copy `evaluate` makes of what it is given and of what a rule of the caller's own returns.

/**
 * What a copy says went wrong.
 * @param {unknown} value
 */
function refusal(value) {
    const copy = copyJson(value);
    assert.equal(copy.ok, false, "it was copied");
    return copy.ok ? null : { path: copy.path, reason: copy.reason };
}

/** @param {unknown} value */
function copied(value) {
    const copy = copyJson(value);
    assert.equal(copy.ok, true, JSON.stringify(copy));
    return copy.ok ? copy.value : undefined;
}

test("a value made of what JSON holds is copied, and the copy shares nothing with it", () => {
    const value = JSON.parse('{"a":null,"b":true,"c":"text","d":1.5,"e":[1,[2,[3]]],"f":{"g":{"h":[]}},"":0,"__proto__":{"own":1}}');
    const copy = /** @type {any} */ (copied(value));
    assert.deepEqual(copy, value);
    assert.notEqual(copy, value);
    assert.notEqual(copy.e, value.e);
    assert.notEqual(copy.e[1], value.e[1]);
    assert.notEqual(copy.f.g, value.f.g);
    assert.equal(Object.hasOwn(copy, "__proto__"), true, "a key named __proto__ stays an own key");
    assert.equal(Object.getPrototypeOf(copy), Object.prototype);
    for (const primitive of [null, true, false, "", "text", 0, -1.5, 1e300]) assert.equal(copied(primitive), primitive);
    assert.equal(Object.is(copied(-0), -0), true, "-0 is a number JSON can write");
});

test("an object with no prototype is plain, and is copied into an object with one", () => {
    const bare = Object.assign(Object.create(null), { a: [Object.assign(Object.create(null), { b: 1 })] });
    assert.equal(isPlain(bare), true);
    const copy = /** @type {any} */ (copied(bare));
    assert.deepEqual(copy, { a: [{ b: 1 }] });
    assert.equal(Object.getPrototypeOf(copy), Object.prototype);
    assert.equal(Object.getPrototypeOf(copy.a[0]), Object.prototype);
});

test("isPlain is true for an object made by a literal or with no prototype, and false for everything else", () => {
    assert.equal(isPlain({}), true);
    assert.equal(isPlain(Object.create(null)), true);
    for (const other of [null, undefined, 0, "", [], () => 1, new Date(0), new Map(), Object.create({}), new (class Own {})(), runInNewContext("({})"), new Proxy([], {})]) {
        assert.equal(isPlain(other), false);
    }
    assert.equal(isPlain(new Proxy({}, {})), true, "a proxy answers as its target does");
    // A list is not an object, even when someone has taken its prototype away.
    assert.equal(isPlain(Object.setPrototypeOf([], null)), false);
    assert.equal(isPlain(Object.setPrototypeOf([], Object.prototype)), false);
});

test("what cannot be copied is refused with where it is and why", () => {
    /** @type {any} */
    const cycle = { next: {} };
    cycle.next.back = cycle;
    /** @type {[unknown, string, string][]} */
    const cases = [
        [undefined, "", "is undefined"],
        [() => 1, "", "is a function"],
        [10n, "", "is a bigint"],
        [Symbol("s"), "", "is a symbol"],
        [Number.NaN, "", "is not a finite number"],
        [Number.POSITIVE_INFINITY, "", "is not a finite number"],
        [Number.NEGATIVE_INFINITY, "", "is not a finite number"],
        [new Date(0), "", "is not a plain object or a list"],
        [new Map(), "", "is not a plain object or a list"],
        [new Uint8Array(1), "", "is not a plain object or a list"],
        [runInNewContext("({ a: 1 })"), "", "is not a plain object or a list"],
        [{ a: { b: [1, undefined] } }, "/a/b/1", "is undefined"],
        [{ a: [{ f: () => 1 }] }, "/a/0/f", "is a function"],
        [[1, , 3], "/1", "is missing from a list that has a gap"],
        [{ get a() { return 1; } }, "/a", "is an accessor"],
        [{ list: Object.defineProperty([0], "0", { get: () => 1, enumerable: true }) }, "/list/0", "is an accessor"],
        [cycle, "/next/back", "contains itself"],
        [{ "a/b": { "c~d": () => 1 } }, "/a~1b/c~0d", "is a function"],
        [new Proxy({}, { ownKeys() { throw new Error("no"); } }), "", "cannot be read"],
        [{ inner: new Proxy([], { get() { throw new Error("no"); } }) }, "", "cannot be read"],
    ];
    for (const [value, path, reason] of cases) {
        assert.deepEqual(refusal(value), { path, reason }, `${path} ${reason}`);
    }
    const { proxy, revoke } = Proxy.revocable({}, {});
    revoke();
    assert.deepEqual(refusal(proxy), { path: "", reason: "cannot be read" });
});

test("a value that refers to the same object twice is not a value that contains itself", () => {
    const shared = [1, 2];
    const copy = /** @type {any} */ (copied({ a: shared, b: shared, c: [shared, shared] }));
    assert.deepEqual(copy, { a: [1, 2], b: [1, 2], c: [[1, 2], [1, 2]] });
    assert.notEqual(copy.a, copy.b, "each reference is its own copy");
});

test("an accessor is never called, not even to find out what it holds", () => {
    let called = 0;
    const value = { get a() { called += 1; return 1; } };
    refusal(value);
    assert.equal(dataOf(value, "a"), undefined);
    assert.equal(called, 0);
    assert.equal(dataOf({ a: 5 }, "a"), 5);
    assert.equal(dataOf({ a: 5 }, "b"), undefined);
    assert.equal(dataOf(Object.create({ a: 5 }), "a"), undefined, "only an own property");
});

test("what is not enumerable, a symbol key and a property of a list that is not an index are left out, as JSON leaves them out", () => {
    const value = { shown: 1, [Symbol("s")]: () => 1 };
    Object.defineProperty(value, "hidden", { value: () => 1, enumerable: false });
    const list = Object.assign([1, 2], { extra: () => 1 });
    assert.deepEqual(copied({ value, list }), { value: { shown: 1 }, list: [1, 2] });
});

test("nesting is copied down to 100 levels and refused below, in a list as in an object, and a list may not claim more values than are copied", () => {
    /** @param {number} levels @param {boolean} inList */
    const nested = (levels, inList) => {
        /** @type {any} */
        let value = "bottom";
        for (let level = 0; level < levels; level += 1) value = inList ? [value] : { next: value };
        return value;
    };
    for (const inList of [true, false]) {
        assert.equal(copyJson(nested(100, inList)).ok, true, `100 levels in ${inList ? "lists" : "objects"}`);
        assert.deepEqual(refusal(nested(101, inList))?.reason, "is nested deeper than 100 levels", `101 levels in ${inList ? "lists" : "objects"}`);
    }
    // The path says where the 101st level starts.
    assert.equal(refusal(nested(101, true))?.path, "/0".repeat(100));
    assert.equal(refusal(nested(101, false))?.path, "/next".repeat(100));
});

test("at most a million values are copied: a list of 999 999 numbers is, one of a million is not, and one that refers to itself many times over is refused at once", () => {
    // The list itself counts as a value, so the last list that fits holds 999 999.
    assert.equal(copyJson(new Array(999999).fill(0)).ok, true);
    assert.deepEqual(refusal(new Array(1000000).fill(0)), { path: "", reason: "is past the million values that are copied" });
    assert.deepEqual(refusal({ list: new Array(999999).fill(0) }), { path: "/list", reason: "is past the million values that are copied" }, "the object before it counts too");
    assert.equal(copyJson({ list: new Array(999998).fill(0) }).ok, true);

    /** @type {any} */
    let shared = [0];
    for (let level = 0; level < 60; level += 1) shared = [shared, shared];
    assert.equal(refusal(shared)?.reason, "is past the million values that are copied");
    /** @type {any[]} */
    const claims = [];
    claims.length = 4294967295;
    assert.equal(refusal(claims)?.reason, "is past the million values that are copied");
});

test("freeze freezes every object and list of the copy, and nothing is frozen without it", () => {
    const value = { a: [{ b: [1] }], c: {} };
    /** @param {any} found @returns {boolean} */
    const frozen = (found) => typeof found !== "object" || found === null || (Object.isFrozen(found) && Object.values(found).every(frozen));
    assert.equal(frozen(/** @type {any} */ (copyJson(value, { freeze: true })).value), true);
    assert.equal(frozen(/** @type {any} */ (copyJson(value, { freeze: false })).value), false);
    assert.equal(Object.isFrozen(/** @type {any} */ (copyJson(value)).value), false);
    assert.equal(Object.isFrozen(/** @type {any} */ (copyJson(value)).value.a), false);
    assert.equal(Object.isFrozen(value), false, "the original is not touched");
});
