import { test } from "node:test";
import assert from "node:assert/strict";
import { runInNewContext } from "node:vm";
import { serializeCheckResult } from "../src/index.js";
import { evaluate, observed, policyOf, resultOf } from "./helpers/evaluation.js";
import { validatorFor } from "./helpers/schema.js";

// The rules of the caller's own that `options.rules` takes: how they are named, what a result of
// one may hold, and what happens to the check when one of them does something else.

const errorsOf = validatorFor("check-result");

/**
 * Evaluates the default observation with the given rules and an empty policy.
 * @param {any[]} rules
 * @param {any} [policy]
 * @returns {any}
 */
function withRules(rules, policy = policyOf()) {
    return evaluate(observed(), policy, { rules });
}

/** The results of the rules of your own: those after the two validity ones and the policy's. */
const ownOf = (/** @type {any} */ check, /** @type {number} */ from = 2) => check.results.slice(from);

/** A result with the three required properties. */
const pass = (/** @type {object} */ more = {}) => /** @type {any} */ ({ code: "OWN", status: "pass", message: "m", ...more });

// ---------------------------------------------------------------------------------------------
// What a result of your own is

test("the results of the rules of your own follow the policy's, in the order given, each with the same shape as any other result", () => {
    const check = evaluate(observed(), policyOf({ expectKind: { value: "end-entity" } }), {
        rules: [
            () => ({ code: "SECOND", status: "fail", rule: { name: "second", value: ["x"] }, message: "two", actual: 1, expected: [2] }),
            () => ({ code: "FIRST", status: "warn", message: "one" }),
        ],
    });
    assert.deepEqual(check.results.map((/** @type {any} */ result) => result.code), ["NOT_YET_VALID", "EXPIRED", "TARGET_NOT_END_ENTITY", "SECOND", "FIRST"]);
    assert.deepEqual(check.results[3], { code: "SECOND", status: "fail", rule: { name: "second", value: ["x"] }, message: "two", actual: 1, expected: [2] });
    assert.deepEqual(check.results[4], { code: "FIRST", status: "warn", rule: { name: "rule-2" }, message: "one" });
    assert.deepEqual(check.summary, { status: "fail", pass: 3, warn: 1, fail: 1 });
    assert.deepEqual(errorsOf(check), []);
    assert.deepEqual(errorsOf(JSON.parse(serializeCheckResult(check))), []);
});

test("a result with no rule gets { name }, with the function's name or rule-<n>, counting from 1 by position, when it is anonymous", () => {
    function named() {
        return pass();
    }
    const arrow = () => pass();
    const methods = { method() { return pass(); } };
    const check = withRules([named, () => pass(), arrow, function () { return pass(); }, methods.method, class { static name = 5; }]);
    assert.deepEqual(ownOf(check).slice(0, 5).map((/** @type {any} */ result) => result.rule), [
        { name: "named" },
        { name: "rule-2" },
        { name: "arrow" },
        { name: "rule-4" },
        { name: "method" },
    ]);
    // `rule` that is missing, undefined or null is written as { name }.
    for (const rule of [undefined, null]) assert.deepEqual(withRules([function checkIt() { return pass({ rule }); }]).results[2], { code: "OWN", status: "pass", rule: { name: "checkIt" }, message: "m" });
    // A name the result gives wins over the function's.
    assert.deepEqual(withRules([function checkIt() { return pass({ rule: { name: "mine" } }); }]).results[2].rule, { name: "mine" });
});

test("the name of a bound function is the function's, an anonymous bound one is rule-<n>, and a name that is not text, or is a getter, is not used or called", () => {
    function original() {
        return pass();
    }
    const check = withRules([original.bind(null), original.bind(null).bind(null), (() => pass()).bind(null), (/** @type {any} */ (() => pass()))]);
    assert.deepEqual(ownOf(check).map((/** @type {any} */ result) => result.rule.name), ["original", "original", "rule-3", "rule-4"]);

    let calls = 0;
    const getter = () => pass();
    Object.defineProperty(getter, "name", {
        get: () => {
            calls += 1;
            return "asked";
        },
    });
    const numeric = () => pass();
    Object.defineProperty(numeric, "name", { value: 42 });
    const empty = () => pass();
    Object.defineProperty(empty, "name", { value: "" });
    const bound = () => pass();
    Object.defineProperty(bound, "name", { value: "bound " });
    const names = ownOf(withRules([getter, numeric, empty, bound])).map((/** @type {any} */ result) => result.rule.name);
    assert.deepEqual(names, ["rule-1", "rule-2", "rule-3", "rule-4"]);
    assert.equal(calls, 0);

    // A proxy of a function is a function, and asking it for its name may throw.
    const hostile = new Proxy(() => pass(), { getOwnPropertyDescriptor() { throw new Error("no"); } });
    assert.deepEqual(ownOf(withRules([hostile])).map((/** @type {any} */ result) => result.rule.name), ["rule-1"]);
});

test("a rule gets the observation and the timestamp the result records, and the observation is frozen all the way down", () => {
    /** @type {any[]} */
    const seen = [];
    const check = evaluate(observed(), policyOf(), {
        now: new Date("2026-10-01T00:00:00.700Z"),
        rules: [(/** @type {any} */ observation, /** @type {any} */ now) => {
            seen.push({ observation, now });
            return pass();
        }],
    });
    assert.equal(seen.length, 1);
    assert.equal(seen[0].now, "2026-10-01T00:00:00Z");
    assert.equal(seen[0].now, check.now);
    assert.deepEqual(seen[0].observation, check.observation);
    assert.notEqual(seen[0].observation, check.observation);

    /**
     * @param {any} value
     * @returns {boolean}
     */
    const frozen = (value) => Object.isFrozen(value) && Object.values(value).every((item) => typeof item !== "object" || item === null || frozen(item));
    assert.equal(frozen(seen[0].observation), true);
    assert.equal(Object.isFrozen(check.observation), false, "the observation in the result is the caller's to change");
    assert.equal(Object.isFrozen(check), false);
});

// ---------------------------------------------------------------------------------------------
// What stands in for a result that is not one

test("a rule that throws gives RULE_ERROR with status fail under its name, the check goes on, and the message does not repeat the text of the error", () => {
    const secret = "SECRET-TEXT-IN-THE-ERROR";
    const check = withRules([
        function broken() {
            throw new Error(secret);
        },
        () => pass(),
        function brokenToo() {
            throw secret;
        },
        function brokenAgain() {
            throw { message: secret, toString: () => secret };
        },
        function brokenNull() {
            throw null;
        },
    ]);
    assert.deepEqual(ownOf(check).map((/** @type {any} */ result) => `${result.code} ${result.status} ${result.rule.name}`), [
        "RULE_ERROR fail broken", "OWN pass rule-2", "RULE_ERROR fail brokenToo", "RULE_ERROR fail brokenAgain", "RULE_ERROR fail brokenNull",
    ]);
    assert.ok(!JSON.stringify(check).includes(secret));
    assert.deepEqual(ownOf(check)[0], { code: "RULE_ERROR", status: "fail", rule: { name: "broken" }, message: "the rule threw an error instead of giving a result" });
    assert.deepEqual(Object.keys(ownOf(check)[0]), ["code", "status", "rule", "message"]);
    assert.equal(check.summary.status, "fail");
    assert.deepEqual(errorsOf(check), []);
});

test("a rule that returns something that is not a result gives RULE_ERROR, and says which thing was missing", () => {
    const notResults = [
        undefined, null, "text", 5, true, 10n, Symbol("s"), [], [pass()], () => pass(), new Map(), new Date(0),
        {}, { code: "X" }, { status: "pass", message: "m" }, { code: "X", status: "pass" }, { code: "X", message: "m" },
        // The code: capital letters, digits and underscores, starting with a letter.
        pass({ code: "" }), pass({ code: "lower" }), pass({ code: "Mixed" }), pass({ code: "1ABC" }), pass({ code: "_ABC" }), pass({ code: "A-B" }), pass({ code: "A B" }), pass({ code: "A\n" }), pass({ code: "É" }), pass({ code: 5 }), pass({ code: null }), pass({ code: ["A"] }),
        // The status: the three words.
        pass({ status: "PASS" }), pass({ status: "ok" }), pass({ status: "" }), pass({ status: null }), pass({ status: true }), pass({ status: ["pass"] }),
        // The message: a string.
        pass({ message: 5 }), pass({ message: null }), pass({ message: undefined }), pass({ message: ["m"] }), pass({ message: new String("m") }),
        // `rule` that is not an object with a name.
        pass({ rule: "name" }), pass({ rule: 5 }), pass({ rule: [] }), pass({ rule: {} }), pass({ rule: { name: "" } }), pass({ rule: { name: 5 } }), pass({ rule: { name: null } }), pass({ rule: { value: 1 } }),
    ];
    const check = withRules(notResults.map((returned) => () => returned));
    assert.equal(ownOf(check).length, notResults.length);
    ownOf(check).forEach((/** @type {any} */ result, /** @type {number} */ position) => {
        assert.deepEqual(Object.keys(result), ["code", "status", "rule", "message"], `case ${position}`);
        assert.equal(result.code, "RULE_ERROR", `case ${position}`);
        assert.equal(result.status, "fail");
        assert.deepEqual(result.rule, { name: `rule-${position + 1}` });
        assert.match(result.message, /^the rule did not return a result: /);
    });
    assert.deepEqual(errorsOf(check), []);

    // Not an object with a code is said first, whether it has none or is a list.
    for (const position of [notResults.indexOf(undefined), notResults.findIndex((item) => Array.isArray(item) && item.length === 0), notResults.findIndex((item) => Array.isArray(item) && item.length === 1)]) {
        assert.equal(ownOf(check)[position].message, "the rule did not return a result: it must be an object with a code, a status and a message", `case ${position}`);
    }
    // A function is not an object that has a rule name, although it has a name, and nor is a list that has one.
    const named = ownOf(withRules([() => pass({ rule: function inner() {} }), () => pass({ rule: Object.assign([], { name: "listed" }) }), () => pass({ rule: function fn() {} })]));
    assert.deepEqual(named.map((/** @type {any} */ result) => result.message), Array(3).fill("the rule did not return a result: its rule must be an object with a name"));

    const messages = new Set(ownOf(check).map((/** @type {any} */ result) => result.message));
    assert.deepEqual([...messages].sort(), [
        "the rule did not return a result: it must be an object with a code, a status and a message",
        "the rule did not return a result: its code must be capital letters, digits and underscores, starting with a letter",
        "the rule did not return a result: its message must be a string",
        "the rule did not return a result: its rule must be an object with a name",
        "the rule did not return a result: its status must be pass, fail or warn",
    ]);
});

test("a rule that is a class, or a generator, or a proxy that throws when called, gives RULE_ERROR, and so does one that needs a this", () => {
    const methods = {
        needsThis() {
            return /** @type {any} */ (this).value;
        },
    };
    const check = withRules([
        class Rule {},
        function* generator() {
            yield pass();
        },
        new Proxy(() => pass(), { apply() { throw new Error("no"); } }),
        methods.needsThis,
    ]);
    assert.deepEqual(ownOf(check).map((/** @type {any} */ result) => `${result.code} ${result.rule.name}`), ["RULE_ERROR Rule", "RULE_ERROR generator", "RULE_ERROR rule-3", "RULE_ERROR needsThis"]);
    assert.deepEqual(errorsOf(check), []);
});

test("the codes POLICY_EMPTY and RULE_ERROR are the library's own, so a rule that returns one gets RULE_ERROR, and any other code that has the form is kept, a library code included", () => {
    const check = withRules([() => pass({ code: "POLICY_EMPTY", status: "warn", rule: null }), () => pass({ code: "RULE_ERROR" }), () => pass({ code: "POLICY_EMPTY_2" }), () => pass({ code: "A" })]);
    assert.deepEqual(ownOf(check).map((/** @type {any} */ result) => `${result.code} ${result.status}`), ["RULE_ERROR fail", "RULE_ERROR fail", "POLICY_EMPTY_2 pass", "A pass"]);
    assert.match(ownOf(check)[0].message, /its code is one POLICY_EMPTY and RULE_ERROR keep for the library/);
    assert.deepEqual(errorsOf(check), []);
});

test("a rule of your own may give the code of a rule of the library, and its result keeps that code and its own rule.name", () => {
    const check = evaluate(observed(), policyOf(), {
        rules: [
            function mine() {
                return { code: "EXPIRED", status: "fail", message: "my own idea of expired", actual: "yesterday" };
            },
            function yours() {
                return { code: "TARGET_NOT_END_ENTITY", status: "pass", rule: { name: "yours" }, message: "m" };
            },
        ],
    });
    assert.deepEqual(check.results.map((/** @type {any} */ result) => `${result.code} ${result.status} ${result.rule.name}`), [
        "NOT_YET_VALID pass validityStarted", "EXPIRED pass validityNotEnded", "EXPIRED fail mine", "TARGET_NOT_END_ENTITY pass yours",
    ]);
    assert.deepEqual(errorsOf(check), []);
    assert.equal(check.summary.status, "fail");
});

test("a result of your own is copied as the five properties of a result: the rest, an undefined and a property that is not its own are left out", () => {
    class Found {
        code = "CLASSY";
        status = "pass";
        message = "an instance with own data properties is a result";
        get actual() {
            return "an accessor is never called";
        }
    }
    const inherited = Object.create({ code: "INHERITED", status: "pass", message: "m" });
    const check = withRules([
        () => pass({ code: "EXTRA", extra: 1, severity: "warn", toJSON: () => "no" }),
        () => pass({ actual: undefined, expected: undefined, rule: undefined }),
        () => pass({ actual: null, expected: null }),
        () => pass({ rule: { name: "n", value: undefined, other: 1 } }),
        () => new Found(),
        () => inherited,
        () => Object.freeze(pass({ actual: Object.freeze([1]) })),
        () => runInNewContext("({ code: 'OTHER_REALM', status: 'pass', message: 'm', actual: [1, 'a', [null]] })"),
        () => Object.assign(Object.create(null), pass({ code: "NO_PROTOTYPE" })),
    ]);
    const [extra, nothing, nulls, noValue, classy, fromPrototype, frozen, foreign, bare] = ownOf(check);
    assert.deepEqual(extra, { code: "EXTRA", status: "pass", rule: { name: "rule-1" }, message: "m" });
    assert.deepEqual(nothing, { code: "OWN", status: "pass", rule: { name: "rule-2" }, message: "m" });
    assert.deepEqual(nulls, { code: "OWN", status: "pass", rule: { name: "rule-3" }, message: "m", actual: null, expected: null });
    assert.deepEqual(noValue.rule, { name: "n" });
    assert.deepEqual(classy, { code: "CLASSY", status: "pass", rule: { name: "rule-5" }, message: "an instance with own data properties is a result" });
    assert.equal(fromPrototype.code, "RULE_ERROR", "a property it only inherits is not read");
    assert.deepEqual(frozen.actual, [1]);
    assert.equal(Object.isFrozen(frozen.actual), false, "and the copy is not frozen");
    assert.deepEqual(foreign, { code: "OTHER_REALM", status: "pass", rule: { name: "rule-8" }, message: "m", actual: [1, "a", [null]] });
    assert.equal(Object.getPrototypeOf(foreign.actual), Array.prototype, "a list from another realm is copied into this one");
    assert.deepEqual(bare, { code: "NO_PROTOTYPE", status: "pass", rule: { name: "rule-9" }, message: "m" });
    assert.deepEqual(errorsOf(check), []);
});

test("a plain object of another realm is not a plain object of this one, as policyProblems reads it, so it cannot be an actual", () => {
    const foreign = runInNewContext("({ a: 1 })");
    assert.notEqual(Object.getPrototypeOf(foreign), Object.prototype);
    assert.equal(ownOf(withRules([() => pass({ actual: foreign })]))[0].code, "RULE_ERROR");
    assert.equal(ownOf(withRules([() => pass({ actual: [foreign] })]))[0].code, "RULE_ERROR");
});

test("an accessor in a result is never called: a result that has one is refused, whichever property it is on", () => {
    let called = 0;
    const getter = () => {
        called += 1;
        return "x";
    };
    const check = withRules([
        () => ({ get code() { return getter(); }, status: "pass", message: "m" }),
        () => ({ code: "A", get status() { return getter(); }, message: "m" }),
        () => ({ code: "A", status: "pass", get message() { return getter(); } }),
        () => ({ code: "A", status: "pass", message: "m", get actual() { return getter(); } }),
        () => ({ code: "A", status: "pass", message: "m", get expected() { return getter(); } }),
        () => ({ code: "A", status: "pass", message: "m", get rule() { return getter(); } }),
        () => ({ code: "A", status: "pass", message: "m", rule: { get name() { return getter(); } } }),
        () => ({ code: "A", status: "pass", message: "m", rule: { name: "n", get value() { return getter(); } } }),
    ]);
    assert.equal(called, 0);
    assert.deepEqual(ownOf(check).map((/** @type {any} */ result) => result.code), Array(8).fill("RULE_ERROR"));
    assert.ok(ownOf(check).slice(3).every((/** @type {any} */ result) => result.message === "the rule did not return a result: a property of it is an accessor, which is never called"));
    assert.deepEqual(errorsOf(check), []);
});

// ---------------------------------------------------------------------------------------------
// actual, expected and a rule's value are JSON

test("an actual, an expected or a rule value that JSON cannot hold gives RULE_ERROR and not an output that cannot be written or that loses what the rule said", () => {
    /** @type {any} */
    const cycle = { a: 1 };
    cycle.self = cycle;
    /** @type {any[]} */
    const list = [];
    list.push(list);
    const sparse = [1, , 3];
    const unwritable = [
        10n, Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, () => 1, Symbol("s"), new Date(0), new Map(), new Set(), /x/, new Uint8Array(2), new (class Own { x = 1; })(),
        { a: () => 1 }, { a: undefined }, { a: 10n }, { a: Number.NaN }, [Number.NaN], [undefined], [() => 1], sparse, cycle, list, { deep: { deeper: [cycle] } },
        { get a() { return 1; } }, new Proxy({}, { ownKeys() { throw new Error("no"); } }), new Proxy([], { get() { throw new Error("no"); } }),
    ];
    for (const place of ["actual", "expected", "rule.value"]) {
        const check = withRules(unwritable.map((value) => () => (place === "rule.value" ? pass({ rule: { name: "n", value } }) : pass({ [place]: value }))));
        ownOf(check).forEach((/** @type {any} */ result, /** @type {number} */ position) => {
            assert.equal(result.code, "RULE_ERROR", `${place} case ${position}`);
            assert.equal(result.message, `the rule did not return a result: its ${place} cannot be written as JSON`);
        });
        assert.deepEqual(errorsOf(check), []);
        assert.doesNotThrow(() => serializeCheckResult(check));
    }
});

test("an actual that JSON can hold is copied: nulls, numbers, strings, booleans, lists and plain objects, nested up to 100 levels, and not one level more", () => {
    /** @param {number} levels */
    const nested = (levels) => {
        /** @type {any} */
        let value = "bottom";
        for (let level = 0; level < levels; level += 1) value = level % 2 === 0 ? [value] : { next: value };
        return value;
    };
    const holds = JSON.parse('{ "n": null, "t": true, "f": false, "s": "text", "i": 1, "d": -0.5, "big": 1e300, "list": [1, "a", null, [], {}], "nest": { "a": { "b": { "c": [] } } }, "": 0, "__proto__": 1 }');
    const check = withRules([() => pass({ actual: holds }), () => pass({ actual: nested(100) }), () => pass({ actual: nested(101) }), () => pass({ expected: [nested(99)] }), () => pass({ expected: [nested(100)] })]);
    const [plain, hundred, over, ninetyNine, overInList] = ownOf(check);
    assert.deepEqual(plain.actual, holds);
    assert.notEqual(plain.actual, holds, "a copy");
    assert.deepEqual(hundred.actual, nested(100));
    assert.equal(over.code, "RULE_ERROR");
    assert.equal(ninetyNine.code, "OWN");
    assert.equal(overInList.code, "RULE_ERROR");
    // Even the deepest of them is written, and validates.
    assert.doesNotThrow(() => serializeCheckResult(check));
    assert.deepEqual(errorsOf(check), []);
    // The key `__proto__` is an own key of the copy and not its prototype.
    assert.equal(Object.getPrototypeOf(plain.actual), Object.prototype);
    assert.deepEqual(Object.keys(plain.actual).includes("__proto__"), true);
});

test("an actual that refers to the same list many times over is refused, not copied until memory runs out", () => {
    /** @type {any} */
    let shared = [0];
    for (let level = 0; level < 60; level += 1) shared = [shared, shared];
    const check = withRules([() => pass({ actual: shared }), () => pass({ actual: Array.from({ length: 100000 }, (_, index) => index) })]);
    assert.equal(ownOf(check)[0].code, "RULE_ERROR");
    assert.equal(ownOf(check)[1].code, "OWN", "a long list is not a shared one");
    // A list that claims four billion items is refused before its keys are listed.
    /** @type {any[]} */
    const sparse = [];
    sparse.length = 4294967295;
    assert.equal(ownOf(withRules([() => pass({ actual: sparse })]))[0].code, "RULE_ERROR");
});

// ---------------------------------------------------------------------------------------------
// A rule that answers later, and one that changes what it was given

test("a rule that returns a promise gets RULE_ERROR, and a rejection nobody waits for does not end the process", async () => {
    /** @type {unknown[]} */
    const unhandled = [];
    const listen = (/** @type {unknown} */ reason) => void unhandled.push(reason);
    process.on("unhandledRejection", listen);
    try {
        const check = withRules([
            async function late() {
                throw new Error("rejected");
            },
            () => Promise.resolve(pass()),
            () => Promise.reject(new Error("rejected too")),
            () => runInNewContext("Promise.reject(new Error('from another realm'))"),
            // A promise with a `then` of its own, which must not run.
            () => {
                const promise = Promise.reject(new Error("sneaky"));
                promise.then = () => {
                    throw new Error("then ran");
                };
                return promise;
            },
            () => pass(),
        ]);
        assert.deepEqual(ownOf(check).map((/** @type {any} */ result) => `${result.code} ${result.rule.name}`), [
            "RULE_ERROR late", "RULE_ERROR rule-2", "RULE_ERROR rule-3", "RULE_ERROR rule-4", "RULE_ERROR rule-5", "OWN rule-6",
        ]);
        assert.equal(ownOf(check)[0].message, "the rule returned a promise, and a rule must answer at once");
        // Rejections are reported when the microtasks and the next turn of the loop have run.
        await new Promise((resolve) => setImmediate(resolve));
        await new Promise((resolve) => setImmediate(resolve));
        assert.deepEqual(unhandled, []);
    } finally {
        process.off("unhandledRejection", listen);
    }
});

test("a promise whose then cannot be called, and a result that cannot be read, are RULE_ERROR and not a crash", () => {
    // `then` asks the promise's constructor for the species of the promise it returns, and a species that is not a constructor throws.
    const awkward = Promise.resolve(1);
    Object.defineProperty(awkward, "constructor", { value: { [Symbol.species]: 5 } });
    assert.throws(() => Promise.prototype.then.call(awkward, undefined, () => {}), TypeError, "the case this test needs");
    const unreadable = new Proxy({ code: "A", status: "pass", message: "m" }, { getOwnPropertyDescriptor() { throw new Error("secret text"); } });
    const check = withRules([() => awkward, () => unreadable, () => ({ code: "A", status: "pass", message: "m", actual: unreadable })]);
    assert.deepEqual(ownOf(check).map((/** @type {any} */ result) => `${result.code} ${result.message}`), [
        "RULE_ERROR the rule returned a promise, and a rule must answer at once",
        "RULE_ERROR the result could not be read",
        "RULE_ERROR the rule did not return a result: its actual cannot be written as JSON",
    ]);
    assert.ok(!JSON.stringify(check).includes("secret text"));
});

test("an actual of 999 999 values is written and one of a million is not, so a rule can show a long list and cannot make one that is too long to copy", () => {
    const long = (/** @type {number} */ length) => withRules([() => pass({ actual: new Array(length).fill(0) })]).results[2];
    assert.equal(long(999999).code, "OWN");
    assert.equal(long(999999).actual.length, 999999);
    assert.equal(long(1000000).code, "RULE_ERROR");
});

test("a rule that changes the observation it was given changes nothing: it throws in strict code and has no effect in sloppy code, and neither reaches the next rule or the result", () => {
    const observation = observed();
    const before = structuredClone(observation);
    const sloppy = new Function("observation", "observation.certificates[0].sha256 = 'x'; observation.target = 7; delete observation.contract; return { code: 'SLOPPY', status: 'pass', message: 'ran' };");
    /** @type {any[]} */
    const later = [];
    const check = evaluate(observation, policyOf({ expectKind: { value: "end-entity" } }), {
        rules: [
            function strict(/** @type {any} */ given) {
                given.certificates[0].kind = "ca";
                return pass();
            },
            function addsItem(/** @type {any} */ given) {
                given.certificates.push({});
                return pass();
            },
            function deletes(/** @type {any} */ given) {
                delete given.warnings;
                return pass();
            },
            function defines(/** @type {any} */ given) {
                Object.defineProperty(given, "x", { value: 1 });
                return pass();
            },
            function reparents(/** @type {any} */ given) {
                Object.setPrototypeOf(given, null);
                return pass();
            },
            /** @type {any} */ (sloppy),
            function sees(/** @type {any} */ given) {
                later.push(structuredClone(given));
                return pass();
            },
        ],
    });
    assert.deepEqual(ownOf(check, 3).map((/** @type {any} */ result) => `${result.code} ${result.rule.name}`), [
        "RULE_ERROR strict", "RULE_ERROR addsItem", "RULE_ERROR deletes", "RULE_ERROR defines", "RULE_ERROR reparents", "SLOPPY anonymous", "OWN sees",
    ]);
    assert.deepEqual(later, [before], "the next rule sees what the caller gave");
    assert.deepEqual(observation, before, "and so does the caller");
    assert.deepEqual(check.observation, before, "and so does the result");
    assert.equal(resultOf(check, "expectKind").status, "pass");
});

test("a rule that changes the list of rules, or that evaluates again, changes nothing for this evaluation, and the same observation is given to every rule", () => {
    /** @type {any[]} */
    const rules = [];
    /** @type {any[]} */
    const given = [];
    rules.push(
        () => {
            rules.push(() => pass({ code: "ADDED" }));
            rules.splice(0, 1);
            return pass({ code: "FIRST" });
        },
        (/** @type {any} */ observation) => {
            given.push(observation);
            const inner = evaluate(observation, policyOf({ expectKind: { value: "end-entity" } }), { rules: [(/** @type {any} */ again) => { given.push(again); return pass({ code: "INNER" }); }] });
            return pass({ code: "SECOND", actual: inner.summary });
        },
        (/** @type {any} */ observation) => {
            given.push(observation);
            return pass({ code: "THIRD" });
        },
    );
    const options = { rules };
    const check = evaluate(observed(), policyOf(), options);
    assert.deepEqual(ownOf(check).map((/** @type {any} */ result) => result.code), ["FIRST", "SECOND", "THIRD"]);
    assert.deepEqual(ownOf(check)[1].actual, { status: "pass", pass: 4, warn: 0, fail: 0 });
    assert.equal(rules.length, 3, "the list is the caller's: one was removed and one added");
    assert.equal(given.length, 3);
    assert.equal(given[0], given[2], "the second and the third rule get the same frozen copy");
    assert.notEqual(given[1], given[0], "and a nested evaluation gets its own");
});

test("options.rules and options.now are each read once, and a list of rules is read before any rule runs", () => {
    /** @type {string[]} */
    const reads = [];
    const options = {
        get now() {
            reads.push("now");
            return "2026-10-01T00:00:00Z";
        },
        get rules() {
            reads.push("rules");
            return [() => pass()];
        },
    };
    const check = evaluate(observed(), policyOf(), options);
    assert.deepEqual([...reads].sort(), ["now", "rules"]);
    assert.equal(check.now, "2026-10-01T00:00:00Z");
    assert.equal(ownOf(check).length, 1);
});
