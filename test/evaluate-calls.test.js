import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as library from "../src/index.js";
import { PolicyError, entryOfCode, inspect, policyProblems, serializeCheckResult } from "../src/index.js";
import { ENTRIES } from "../src/policy.js";
import { AT, evaluate, fixture, observed, policyOf, shifted } from "./helpers/evaluation.js";
import { validatorFor } from "./helpers/schema.js";

// The call: what it refuses and how, that it changes nothing it was given, and the function that
// maps a code to its entry.

const errorsOf = validatorFor("check-result");
const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");

/**
 * What a call throws.
 * @param {() => unknown} call
 * @returns {any}
 */
function thrown(call) {
    try {
        call();
    } catch (error) {
        return error;
    }
    assert.fail("it did not throw");
}

// ---------------------------------------------------------------------------------------------
// PolicyError

test("PolicyError is exported from the entry point, is an Error, and carries the problems policyProblems listed in problems", () => {
    assert.equal(typeof library.PolicyError, "function");
    /** @type {any[]} */
    const wrong = [
        null, undefined, 5, "text", [], {}, { contract: 2 }, { contract: 1, expiresWithin: { value: "30" } }, { contract: 1, expectEku: { value: [] } },
        { contract: 1, expectFingerprint: { value: "ABC" } }, { contract: 1, validityStarted: null }, { contract: 1, maxLifetimeUsed: { value: 2 } },
        { contract: 1, expectSan: { value: ["a b"] }, rejectEku: { value: [5] }, expiresWithin: { severity: "loud" } },
        // What JSON cannot hold, which a function put in a policy for a rule of your own is.
        { contract: 1, own: () => 1 }, { contract: 1, expiresWithin: { value: "30d", check: () => 1 } }, { contract: 1, n: 10n },
        { contract: 1, get expiresWithin() { return { value: "30d" }; } },
    ];
    const cycle = { contract: 1 };
    Object.assign(cycle, { cycle });
    wrong.push(cycle);

    for (const [position, policy] of wrong.entries()) {
        const error = thrown(() => evaluate(observed(), policy));
        assert.ok(error instanceof PolicyError, `wrong policy number ${position}`);
        assert.ok(error instanceof Error);
        assert.ok(!(error instanceof TypeError));
        assert.equal(error.name, "PolicyError");
        assert.deepEqual(error.problems, policyProblems(policy));
        assert.ok(error.problems.length >= 1);
        const count = error.problems.length;
        assert.equal(error.message, `the policy is not valid: ${count} problem${count === 1 ? "" : "s"}`);
        for (const problem of error.problems) assert.deepEqual(Object.keys(problem), ["path", "message"]);
    }
});

test("the message of a PolicyError says how many problems there are and never quotes a value of the policy, nor does a problem", () => {
    const secrets = ["hunter2-secret", "-----BEGIN PRIVATE KEY-----", "correct horse battery staple"];
    const policy = {
        contract: 1,
        expiresWithin: { value: secrets[0] },
        expectSan: { value: [secrets[1], "ok.example.com"] },
        expectEku: { value: [secrets[2]] },
        matchesPrivateKey: { passphrase: secrets[0], key: secrets[1], value: secrets[2], severity: "warn" },
        [secrets[0]]: { value: secrets[1] },
    };
    const error = thrown(() => evaluate(observed(), policy));
    assert.ok(error instanceof PolicyError);
    assert.match(error.message, /^the policy is not valid: \d+ problems$/);
    const shown = JSON.stringify([error.message, error.problems, String(error.stack).split("\n")[0]]);
    for (const secret of secrets) assert.ok(!shown.includes(secret), secret);
});

test("a policy that lists matchesPrivateKey is refused with one problem at /matchesPrivateKey, because evaluating it needs a private key that evaluate is not given", () => {
    for (const entry of [{}, { severity: "warn" }, { severity: "fail", passphrase: "s3cret", key: "-----BEGIN PRIVATE KEY-----" }]) {
        const error = thrown(() => evaluate(observed(), policyOf({ matchesPrivateKey: entry })));
        assert.ok(error instanceof PolicyError);
        assert.equal(error.problems.length, 1);
        assert.equal(error.problems[0].path, "/matchesPrivateKey");
        assert.equal(error.problems[0].message, "needs a private key, and none is given");
        assert.equal(error.message, "the policy is not valid: 1 problem");
        const shown = JSON.stringify([error.message, error.problems]);
        assert.ok(!shown.includes("s3cret") && !shown.includes("PRIVATE KEY-----"));
    }
    // The other entries of the policy do not change it, and neither does the instant or any rule.
    const others = policyOf({ expiresWithin: { value: "30d" }, matchesPrivateKey: {}, expectKind: { value: "end-entity" } });
    assert.deepEqual(thrown(() => evaluate(observed(), others, { now: AT, rules: [() => ({ code: "A", status: "pass", message: "m" })] })).problems.map((/** @type {any} */ problem) => problem.path), ["/matchesPrivateKey"]);
    // It is listed with the other problems of the same policy, and not twice when the entry itself is wrong.
    const both = thrown(() => evaluate(observed(), policyOf({ expiresWithin: { value: "30" }, matchesPrivateKey: {} })));
    assert.deepEqual(both.problems.map((/** @type {any} */ problem) => problem.path), [...policyProblems(policyOf({ expiresWithin: { value: "30" } })).map((problem) => problem.path), "/matchesPrivateKey"]);
    const itself = thrown(() => evaluate(observed(), policyOf({ matchesPrivateKey: null })));
    assert.deepEqual(itself.problems, policyProblems(policyOf({ matchesPrivateKey: null })));
    assert.deepEqual(itself.problems.map((/** @type {any} */ problem) => problem.path), ["/matchesPrivateKey"]);
    // A policy that lists it as a property that is not an entry's is still listing it.
    assert.equal(thrown(() => evaluate(observed(), JSON.parse('{"contract":1,"matchesPrivateKey":{}}'))).problems.length, 1);
});

test("a PolicyError built by hand keeps a copy of the problems it is given, with a path and a message and nothing else", () => {
    const given = [{ path: "/a", message: "one", extra: 1 }, { path: "", message: "two" }];
    const error = new PolicyError(given);
    given[0].message = "changed";
    given.push({ path: "/c", message: "three" });
    assert.deepEqual(error.problems, [{ path: "/a", message: "one" }, { path: "", message: "two" }]);
    assert.equal(error.message, "the policy is not valid: 2 problems");
    assert.equal(new PolicyError([given[1]]).message, "the policy is not valid: 1 problem");
    assert.equal(error.name, "PolicyError");
});

test("a policy that is not a plain object is a problem of its own and is not read for matchesPrivateKey", () => {
    class Own {
        matchesPrivateKey = {};
        contract = 1;
    }
    const error = thrown(() => evaluate(observed(), new Own()));
    assert.deepEqual(error.problems, [{ path: "", message: "the policy must be a JSON object" }]);
    for (const given of [[], "matchesPrivateKey", null]) {
        assert.deepEqual(thrown(() => evaluate(observed(), given)).problems, policyProblems(given));
    }
});

test("the problems of a PolicyError are its own copies, so changing them changes nothing the next error says", () => {
    const policy = policyOf({ matchesPrivateKey: {} });
    const first = thrown(() => evaluate(observed(), policy));
    first.problems[0].message = "changed";
    first.problems.push({ path: "/x", message: "added" });
    const second = thrown(() => evaluate(observed(), policy));
    assert.equal(second.problems.length, 1);
    assert.notEqual(second.problems[0].message, "changed");
    assert.deepEqual(policyProblems(policy), [], "and policyProblems still says the policy is valid");
});

test("a policy that answers differently each time it is read is checked on what is read, so the rules never decide on a value policyProblems did not accept", () => {
    /** @param {number} flipAfter */
    const policy = (flipAfter) => {
        let reads = 0;
        const entry = new Proxy({ value: "30d" }, {
            getOwnPropertyDescriptor(target, key) {
                if (key === "value") {
                    reads += 1;
                    return reads > flipAfter ? { value: "30", writable: true, enumerable: true, configurable: true } : Reflect.getOwnPropertyDescriptor(target, key);
                }
                return Reflect.getOwnPropertyDescriptor(target, key);
            },
        });
        return { policy: { contract: 1, expiresWithin: entry }, reads: () => reads };
    };
    const counted = policy(Number.POSITIVE_INFINITY);
    assert.deepEqual(policyProblems(counted.policy), []);
    const accepted = counted.reads();
    assert.ok(accepted >= 1);
    // Valid for every read policyProblems makes, and wrong from the next one on: the read evaluate makes.
    const error = thrown(() => evaluate(observed(), policy(accepted).policy));
    assert.ok(error instanceof PolicyError);
    assert.deepEqual(error.problems.map((/** @type {any} */ problem) => problem.path), ["/expiresWithin/value"]);
    // And an entry that is the same each time evaluates.
    assert.equal(evaluate(observed(), policy(Number.POSITIVE_INFINITY).policy).results.length, 3);
    // A policy that cannot be read at all, such as a revoked proxy, is a problem and not a crash.
    const { proxy, revoke } = Proxy.revocable({}, {});
    revoke();
    assert.ok(thrown(() => evaluate(observed(), proxy)) instanceof PolicyError);
});

test("a policy that cannot be read the second time, because what it holds is no longer JSON or it throws, is a PolicyError that says it cannot be read", () => {
    /**
     * An entry that is valid for the reads policyProblems makes and then answers `after` for `value`.
     * @param {() => unknown} after
     * @param {number} flipAfter
     */
    const policy = (after, flipAfter) => {
        let reads = 0;
        const entry = new Proxy({ value: "30d" }, {
            getOwnPropertyDescriptor(target, key) {
                if (key === "value") {
                    reads += 1;
                    if (reads > flipAfter) return { value: after(), writable: true, enumerable: true, configurable: true };
                }
                return Reflect.getOwnPropertyDescriptor(target, key);
            },
        });
        return { policy: { contract: 1, expiresWithin: entry }, reads: () => reads };
    };
    const counted = policy(() => "30d", Number.POSITIVE_INFINITY);
    policyProblems(counted.policy);
    const accepted = counted.reads();

    for (const after of [() => () => 1, () => 10n, () => { throw new Error("secret text"); }]) {
        const error = thrown(() => evaluate(observed(), policy(after, accepted).policy));
        assert.ok(error instanceof PolicyError);
        assert.deepEqual(error.problems, [{ path: "", message: "the policy cannot be read as a JSON object" }]);
        assert.ok(!error.message.includes("secret text") && !JSON.stringify(error.problems).includes("secret text"));
    }
});

test("an observation and a policy built without a prototype are read like any other", () => {
    /**
     * @param {any} value
     * @returns {any}
     */
    const bare = (value) => {
        if (typeof value !== "object" || value === null) return value;
        return Array.isArray(value) ? value.map(bare) : Object.assign(Object.create(null), Object.fromEntries(Object.entries(value).map(([key, item]) => [key, bare(item)])));
    };
    const observation = observed();
    const policy = policyOf({ expectSan: { value: ["a.example.com"] }, expectKind: { value: "end-entity" } });
    const plain = evaluate(observation, policy);
    const withoutPrototype = evaluate(bare(observation), bare(policy));
    assert.deepEqual(withoutPrototype, plain);
    assert.equal(Object.getPrototypeOf(withoutPrototype.observation), Object.prototype, "and the result is made of ordinary objects");
});

test("evaluate never throws because a rule failed: every rule failing at once is a result", () => {
    const failing = policyOf({
        expiresWithin: { value: "999999d" }, maxLifetimeUsed: { value: 0 }, expectEku: { value: ["codeSigning"] }, ekuAllows: { value: ["codeSigning"] }, rejectEku: { value: ["serverAuth"] },
        expectSan: { value: ["nobody.example"] }, expectFingerprint: { value: "0".repeat(64) }, expectKind: { value: "end-entity" },
    });
    const check = evaluate(observed({ kind: "ca", eku: ["serverAuth"] }, AT), failing, { now: shifted("2026-10-30T00:00:00Z", 1) });
    assert.equal(check.summary.status, "fail");
    assert.equal(check.summary.pass, 1);
    assert.equal(check.summary.fail, check.results.length - 1);
    assert.deepEqual(errorsOf(check), []);
});

// ---------------------------------------------------------------------------------------------
// A wrong call is a TypeError

test("an observation the rules cannot read is a TypeError that names what is wrong, and it is reported before the policy is", () => {
    /** @type {[string, (observation: any) => unknown][]} */
    const broken = [
        ["observation.contract", (o) => { o.contract = 2; }],
        ["observation.contract", (o) => { delete o.contract; }],
        ["observation.observation.at", (o) => { o.observation.at = "2026-09-15T14:02:11.5Z"; }],
        ["observation.observation.at", (o) => { o.observation.at = 5; }],
        ["observation.observation.at", (o) => { delete o.observation; }],
        ["observation.observation.at", (o) => { o.observation = null; }],
        ["observation.target", (o) => { o.target = 1; }],
        ["observation.target", (o) => { o.target = -1; }],
        ["observation.target", (o) => { o.target = 0.5; }],
        ["observation.target", (o) => { o.target = "0"; }],
        ["observation.target", (o) => { delete o.target; }],
        ["observation.target", (o) => { o.certificates = {}; }],
        ["observation.target", (o) => { o.certificates = [null]; }],
        ["observation.target", (o) => { o.certificates = [[]]; }],
        ["observation.target", (o) => { o.certificates = { 0: o.certificates[0] }; }],
        ["notBefore", (o) => { o.certificates[0].notBefore = "2026-02-30T00:00:00Z"; }],
        ["notBefore", (o) => { delete o.certificates[0].notBefore; }],
        ["notBefore", (o) => { o.certificates[0].notBefore = new Date(0); }],
        ["notAfter", (o) => { o.certificates[0].notAfter = "2026-10-30"; }],
        ["notAfter", (o) => { o.certificates[0].notAfter = null; }],
        [".kind", (o) => { o.certificates[0].kind = 5; }],
        [".sha256", (o) => { o.certificates[0].sha256 = null; }],
        [".eku", (o) => { delete o.certificates[0].eku; }],
        [".eku", (o) => { o.certificates[0].eku = "serverAuth"; }],
        [".eku", (o) => { o.certificates[0].eku = [5]; }],
        [".san", (o) => { o.certificates[0].san = null; }],
        [".san", (o) => { o.certificates[0].san = { dns: [], ip: "1.2.3.4" }; }],
        [".san", (o) => { o.certificates[0].san = { dns: [1], ip: [] }; }],
        [".san", (o) => { delete o.certificates[0].san.dns; }],
        [".san", (o) => { delete o.certificates[0].san.ip; }],
    ];
    for (const [named, damage] of broken) {
        const observation = observed();
        damage(observation);
        const error = thrown(() => evaluate(observation, { contract: 2 }));
        assert.ok(error instanceof TypeError, `${named}: ${error}`);
        assert.ok(error.message.includes(named), `${named} is in "${error.message}"`);
    }
    // A timestamp the contract does not write is said in the observation's words, and not in an argument's.
    for (const [field, change] of /** @type {[string, (o: any) => unknown][]} */ ([
        ["observation.observation.at", (o) => { o.observation.at = "2026-09-15T14:02:11.5Z"; }],
        ["observation.certificates[0].notBefore", (o) => { o.certificates[0].notBefore = "2026-02-30T00:00:00Z"; }],
        ["observation.certificates[0].notAfter", (o) => { o.certificates[0].notAfter = 5; }],
    ])) {
        const observation = observed();
        change(observation);
        assert.throws(() => evaluate(observation, policyOf()), (error) => error instanceof TypeError && error.message === `${field} must be a timestamp such as 2026-09-15T14:02:11Z`, field);
    }
    for (const observation of [null, undefined, 5, "text", true, [], () => 1, Symbol("o"), 10n]) {
        assert.throws(() => evaluate(observation, policyOf()), (error) => error instanceof TypeError && error.message === "observation must be an object");
    }
    // The properties the rules do not read are not checked: the schema is the place that says whether an observation is well formed.
    const odd = observed();
    odd.format = "not-x509";
    odd.warnings = "none";
    odd.certificates[0].subject = null;
    assert.doesNotThrow(() => evaluate(odd, policyOf()));
});

test("an observation that holds something JSON cannot is a TypeError that says where, and no accessor of it is called", () => {
    let called = 0;
    /** @type {any} */
    const cycle = {};
    cycle.cycle = cycle;
    /** @type {[string, (o: any) => unknown][]} */
    const damage = [
        ["/observation/source/own", (o) => { o.observation.source.own = () => 1; }],
        ["/observation/source/own", (o) => { o.observation.source.own = undefined; }],
        ["/observation/source/own", (o) => { o.observation.source.own = 10n; }],
        ["/observation/source/own", (o) => { o.observation.source.own = Number.NaN; }],
        ["/observation/source/own", (o) => { o.observation.source.own = new Date(0); }],
        ["/observation/source/own", (o) => { o.observation.source.own = cycle; }],
        ["/warnings/0", (o) => { o.warnings = [Symbol("w")]; }],
        ["/certificates/0/issuedBy/1", (o) => { o.certificates[0].issuedBy = [0, , 2]; }],
        ["/observation/source/get", (o) => { Object.defineProperty(o.observation.source, "get", { enumerable: true, get() { called += 1; return 1; } }); }],
    ];
    for (const [where, change] of damage) {
        const observation = observed();
        change(observation);
        const error = thrown(() => evaluate(observation, policyOf()));
        assert.ok(error instanceof TypeError, where);
        assert.ok(error.message.includes(where) || where.endsWith("/1"), `${where} is in "${error.message}"`);
        assert.match(error.message, /^observation holds something JSON cannot, at /);
    }
    assert.equal(called, 0);

    // What is not an object JSON can hold at the very top is said to be at the top.
    class Own {
        contract = 1;
    }
    for (const given of [new Own(), new Date(0), new Map(), Object.create({})]) {
        assert.equal(thrown(() => evaluate(given, policyOf())).message, "observation holds something JSON cannot, at the top: it is not a plain object or a list");
    }
    assert.equal(thrown(() => evaluate(new Proxy({}, { ownKeys() { throw new Error("no"); } }), policyOf())).message, "observation holds something JSON cannot, at the top: it cannot be read");

    // A value nested deeper than 100 levels is refused, and so is a proxy that throws.
    const deep = observed();
    /** @type {any} */
    let level = "bottom";
    for (let i = 0; i < 101; i += 1) level = [level];
    deep.observation.source.deep = level;
    assert.match(thrown(() => evaluate(deep, policyOf())).message, /is nested deeper than 100 levels/);
    const hostile = observed();
    hostile.observation.source.hostile = new Proxy({}, { ownKeys() { throw new Error("no"); } });
    assert.match(thrown(() => evaluate(hostile, policyOf())).message, /cannot be read/);
    // More than a million values is refused before it is copied, and a list that claims more is refused before its keys are listed.
    const large = observed();
    large.observation.source.large = new Array(1000001).fill(0);
    assert.match(thrown(() => evaluate(large, policyOf())).message, /is past the million values that are copied/);
    const claims = observed();
    claims.observation.source.claims = [];
    claims.observation.source.claims.length = 4294967295;
    assert.match(thrown(() => evaluate(claims, policyOf())).message, /is past the million values/);
    // Properties the contract does not know are tolerated, as long as they are JSON, and are kept.
    const known = observed();
    known.observation.source.own = { nested: [1, "two", null] };
    assert.deepEqual(evaluate(known, policyOf()).observation.observation.source.own, { nested: [1, "two", null] });
});

test("options that are not an object, a list of rules that is not a list of functions, and a policy checked after both, are reported as the call's mistakes", () => {
    for (const options of [null, 5, "now", true, 10n, Symbol("o")]) {
        assert.throws(() => evaluate(observed(), policyOf(), options), (error) => error instanceof TypeError && error.message === "options must be an object");
    }
    for (const rules of [null, 5, "rule", {}, () => 1, new Set([() => 1]), { length: 1, 0: () => 1 }]) {
        assert.throws(() => evaluate(observed(), policyOf(), { rules }), (error) => error instanceof TypeError && error.message === "options.rules must be a list of functions");
    }
    for (const [position, item] of /** @type {[number, unknown][]} */ ([[0, null], [0, "rule"], [0, {}], [0, undefined], [1, 5], [2, { call: () => 1 }]])) {
        const rules = [() => ({}), () => ({}), () => ({})];
        rules[position] = /** @type {any} */ (item);
        assert.throws(() => evaluate(observed(), policyOf(), { rules }), (error) => error instanceof TypeError && error.message === `options.rules[${position}] must be a function`);
    }
    assert.throws(() => evaluate(observed(), policyOf(), { rules: [() => ({}), , () => ({})] }), /options\.rules\[1\] must be a function/);
    // A wrong call is reported before a problem of the policy, whatever the order of the arguments.
    assert.throws(() => evaluate(observed(), { contract: 2 }, { now: "yesterday" }), TypeError);
    assert.throws(() => evaluate(observed(), { contract: 2 }, { rules: "none" }), TypeError);
    assert.throws(() => evaluate(5, { contract: 2 }), TypeError);
    assert.throws(() => evaluate(observed(), { contract: 2 }), PolicyError);
});

// ---------------------------------------------------------------------------------------------
// It changes nothing it was given

/**
 * Freezes a value and everything it holds.
 * @param {any} value
 * @returns {any}
 */
function freezeDeep(value) {
    if (typeof value === "object" && value !== null && !Object.isFrozen(value)) {
        Object.freeze(value);
        for (const item of Object.values(value)) freezeDeep(item);
    }
    return value;
}

test("evaluate does not modify its arguments, even when they are frozen all the way down, and the result it returns is the caller's own to change", () => {
    const observation = observed();
    const policy = policyOf({ expiresWithin: { value: "30d" }, expectEku: { value: ["serverAuth"] }, expectSan: { value: ["a.example.com"] } });
    const options = { now: "2026-10-01T00:00:00Z", rules: [() => ({ code: "A", status: "pass", message: "m", actual: [1] })] };
    const before = structuredClone([observation, policy, options.now]);
    freezeDeep(observation);
    freezeDeep(policy);
    freezeDeep(options);

    const check = evaluate(observation, policy, options);
    assert.deepEqual([observation, policy, options.now], before);
    assert.ok(Object.isFrozen(observation) && Object.isFrozen(policy) && Object.isFrozen(options) && Object.isFrozen(options.rules));
    assert.equal(Object.isFrozen(check), false);
    assert.equal(Object.isFrozen(check.observation), false);
    assert.equal(Object.isFrozen(check.policy), false);
    assert.equal(Object.isFrozen(check.results), false);
    assert.equal(Object.isFrozen(check.results[3].rule.value), false);
    check.results.push("anything");
    check.observation.certificates[0].eku.push("changed");
    check.policy.expiresWithin.value = "1d";
    assert.deepEqual([observation, policy], [before[0], before[1]], "changing the result changes nothing the caller holds");

    // Nothing in the result is the caller's object.
    const again = evaluate(observation, policy, options);
    assert.notEqual(again.observation, observation);
    assert.notEqual(again.observation.certificates[0], observation.certificates[0]);
    assert.notEqual(again.observation.certificates[0].san, observation.certificates[0].san);
    assert.notEqual(again.policy.expectSan.value, policy.expectSan.value);
    assert.notEqual(again.results, check.results);
    assert.deepEqual(again.observation, before[0]);
});

test("the same arguments always give equal results, whatever the clock, and equal copies of the arguments give the same bytes", () => {
    const observation = observed({}, "2001-02-03T04:05:06Z");
    const policy = policyOf({ expiresWithin: { value: "30d" }, maxLifetimeUsed: { value: 0.57 }, expectSan: { value: ["B.example.com", "2001:0db8::1"] } });
    const rules = [function own() { return { code: "OWN", status: "warn", message: "m", actual: { a: [1, 2] } }; }];
    const first = evaluate(observation, policy, { rules });
    assert.equal(first.now, "2001-02-03T04:05:06Z", "the observation's at, and not the clock");
    const second = evaluate(structuredClone(observation), structuredClone(policy), { rules: [...rules] });
    assert.deepEqual(second, first);
    assert.equal(serializeCheckResult(second), serializeCheckResult(first));
    // The order the keys were written in does not change the result.
    const shuffled = JSON.parse(JSON.stringify(policy, Object.keys({ ...policy, expectSan: 1, value: 1, severity: 1 }).reverse()));
    assert.equal(serializeCheckResult(evaluate(observation, shuffled, { rules })), serializeCheckResult(first));
});

test("a key named __proto__ in the observation is an own key of the copy and changes no prototype", () => {
    const observation = observed();
    Object.defineProperty(observation.observation.source, "__proto__", { value: { polluted: true }, enumerable: true, writable: true, configurable: true });
    const check = evaluate(observation, policyOf());
    assert.equal(Object.hasOwn(check.observation.observation.source, "__proto__"), true);
    assert.equal(Object.getPrototypeOf(check.observation.observation.source), Object.prototype);
    assert.equal(/** @type {any} */ ({}).polluted, undefined);
    assert.equal(/** @type {any} */ (check.observation.observation.source).polluted, undefined);
    assert.deepEqual(errorsOf(check), []);
});

// ---------------------------------------------------------------------------------------------
// entryOfCode

test("entryOfCode gives the entry that produces a reason code, validityNotEnded for EXPIRED and matchesPrivateKey for both key codes, and null for a code that has no entry", () => {
    assert.equal(typeof library.entryOfCode, "function");
    assert.equal(entryOfCode("EXPIRED"), "validityNotEnded");
    assert.equal(entryOfCode("NOT_YET_VALID"), "validityStarted");
    assert.equal(entryOfCode("EXPIRES_SOON"), "expiresWithin");
    assert.equal(entryOfCode("LIFETIME_USED_EXCEEDED"), "maxLifetimeUsed");
    assert.equal(entryOfCode("EKU_MISSING"), "expectEku");
    assert.equal(entryOfCode("EKU_NOT_PERMITTED"), "ekuAllows");
    assert.equal(entryOfCode("EKU_FORBIDDEN"), "rejectEku");
    assert.equal(entryOfCode("SAN_MISSING"), "expectSan");
    assert.equal(entryOfCode("FINGERPRINT_MISMATCH"), "expectFingerprint");
    assert.equal(entryOfCode("TARGET_NOT_END_ENTITY"), "expectKind");
    assert.equal(entryOfCode("KEY_MISMATCH"), "matchesPrivateKey");
    assert.equal(entryOfCode("KEY_UNREADABLE"), "matchesPrivateKey");

    for (const code of ["POLICY_EMPTY", "RULE_ERROR", "TLS13_REQUIRED", "ISSUER_NOT_ALLOWED", "", "expired", "Expired", " EXPIRED", "EXPIRED ", "__proto__", "constructor", "toString", "hasOwnProperty", "A"]) {
        assert.equal(entryOfCode(code), null, JSON.stringify(code));
    }
    for (const notText of [undefined, null, 5, true, {}, ["EXPIRED"], { toString: () => "EXPIRED" }, Symbol("EXPIRED"), 10n, () => "EXPIRED", new String("EXPIRED")]) {
        assert.equal(entryOfCode(notText), null);
    }
});

test("every result of a policy rule leads back to its own entry through entryOfCode, and the README's table says the same entry for each code", () => {
    const check = evaluate(observed(), policyOf({
        expiresWithin: { value: "1d" }, maxLifetimeUsed: { value: 0.5 }, expectEku: { value: ["serverAuth"] }, ekuAllows: { value: ["serverAuth"] }, rejectEku: { value: ["codeSigning"] },
        expectSan: { value: ["a.example.com"] }, expectFingerprint: { value: "0".repeat(64) }, expectKind: { value: "end-entity" },
    }));
    assert.equal(check.results.length, 10);
    for (const result of check.results) assert.equal(entryOfCode(result.code), result.rule.name, result.code);
    assert.deepEqual(check.results.map((/** @type {any} */ result) => entryOfCode(result.code)), ENTRIES.filter(([entry]) => entry !== "matchesPrivateKey").map(([entry]) => entry));

    const table = readme.split("\n").filter((line) => /^\| `[A-Z_]+` \| (`\w+`|none) \|/.test(line)).map((line) => line.split("|").slice(1, 3).map((cell) => cell.trim().replaceAll("`", "")));
    assert.equal(table.length, 14);
    for (const [code, entry] of table) assert.equal(entryOfCode(code), entry === "none" ? null : entry, code);
});

test("the README documents evaluate, its options, PolicyError and entryOfCode, and no longer says the package does not evaluate a policy", () => {
    const text = readme.replace(/\s+/g, " ").replaceAll("`", "");
    assert.doesNotMatch(text, /it does not evaluate a policy/);
    assert.match(text, /evaluates a policy against an observation and writes the check result/);
    assert.match(text, /evaluate\(observation, policy, options\)/);
    assert.match(text, /options\.now is a Date or a timestamp in the form the contract writes, and it defaults to the observation's at/);
    assert.match(text, /A now that is not an instant, or that falls outside the years 0 to 9999, which the result could not write, is a TypeError/);
    assert.match(text, /options\.rules is a list of functions \(observation, now\) => result/);
    assert.match(text, /The name is the function's own, or rule-<n>, counting from 1 by position/);
    assert.match(text, /Only POLICY_EMPTY, which exists with rule: null, and RULE_ERROR are the library's alone/);
    assert.match(text, /its rule.name says which rule produced a result/);
    assert.match(text, /gets a RULE_ERROR result with status fail under its name, and the check goes on/);
    assert.match(text, /never repeats the text of the error the rule threw/);
    assert.match(text, /evaluate never throws because a rule failed\. It throws PolicyError when the policy is not valid/);
    assert.match(text, /problem has the path \/matchesPrivateKey/);
    assert.match(text, /The message says how many problems there are and never quotes a value of the policy/);
    assert.match(text, /Nothing the caller passed is modified, and nothing in the result is shared with it/);
    assert.match(text, /The messages of a result can hold text that comes from a certificate .*the library does not escape it: whoever prints it does/);
    assert.match(text, /entryOfCode\(code\) gives the entry of the policy that produces a reason code/);
    assert.match(text, /It answers for the library's codes\. A rule of your own may give one of them too, so a program that has results from both looks at rule\.name before asking for the entry/);
});

test("the example in the README runs against a certificate and prints a check result that validates", () => {
    const section = readme.slice(readme.indexOf("### Evaluating a policy"));
    const block = /```js\n([\s\S]*?)```/.exec(section)?.[1] ?? assert.fail("the README has no example of evaluate");
    assert.match(block, /^import \{ evaluate, inspect, serializeCheckResult \} from "certdrift";$/m);
    /** @type {unknown[][]} */
    const printed = [];
    const run = new Function("evaluate", "inspect", "serializeCheckResult", "pem", "console", block.replace(/^import .*$/m, ""));
    run(evaluate, inspect, serializeCheckResult, fixture("leaf-p256.pem"), { log: (/** @type {unknown[]} */ ...shown) => printed.push(shown) });
    assert.equal(printed.length, 1);
    assert.match(String(printed[0][0]), /^(pass|warn|fail)$/);
    const written = JSON.parse(String(printed[0][1]));
    assert.deepEqual(errorsOf(written), []);
    assert.ok(written.results.some((/** @type {any} */ result) => result.code === "ISSUER_NOT_ALLOWED" && result.rule.name === "issuerAllowed"));
});
