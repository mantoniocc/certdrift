import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { runInNewContext } from "node:vm";
import * as library from "../src/index.js";
import { AmbiguousTargetError, inspect, outsideValidity, policyProblems, serializeCheckResult } from "../src/index.js";
import { ENTRIES } from "../src/policy.js";
import { EXTENDED_KEY_USAGE_OIDS } from "../src/usage.js";
import { EMPTY_EKU_EXTENSION, UNDECODABLE_EKU_EXTENSION } from "./helpers/certificates.js";
import { AT, evaluate, fixture, observed, policyOf, resultOf, shifted } from "./helpers/evaluation.js";
import { checked } from "./helpers/rules.js";
import { validatorFor } from "./helpers/schema.js";

// `evaluate` against the README's table of reason codes. Every instant is built from the dates a
// test gives, none reads the clock, and none depends on a fixture's exact bytes.

const errorsOf = validatorFor("check-result");

const START = "2026-03-01T10:00:00Z";
const END = "2026-06-01T10:00:00Z";

/**
 * Evaluates an observation whose target has the given fields.
 * @param {Record<string, unknown>} fields
 * @param {Record<string, unknown>} entries
 * @param {any} [options]
 * @returns {any}
 */
function run(fields, entries, options) {
    return evaluate(observed(fields), policyOf(entries), options);
}

/** @param {any} check */
function statuses(check) {
    return check.results.map((/** @type {any} */ result) => `${result.code} ${result.status}`);
}

// ---------------------------------------------------------------------------------------------
// The result

test("evaluate is exported from the entry point and returns contract, now, summary, results, policy and observation, which validate and serializeCheckResult writes", () => {
    assert.equal(typeof library.evaluate, "function");
    const observation = observed({}, AT);
    const check = evaluate(observation, policyOf({ expiresWithin: { value: "30d" } }));
    assert.deepEqual(Object.keys(check).sort(), ["contract", "now", "observation", "policy", "results", "summary"]);
    assert.equal(check.contract, 1);
    assert.deepEqual(errorsOf(check), []);

    const text = serializeCheckResult(check);
    assert.deepEqual(errorsOf(JSON.parse(text)), []);
    assert.equal(serializeCheckResult(JSON.parse(text)), text, "the text is what the serializer writes for what it reads back");
    assert.deepEqual(check.observation, observation, "the observation is the one that was checked");
    assert.notEqual(check.observation, observation, "and a copy of it");
});

test("results come one per rule in the README's order: the two validity ones always, then the rules of your own as given, then POLICY_EMPTY only when nothing else applies", () => {
    /** @param {string} name @param {string} code */
    const own = (name, code) => ({ [name]: () => ({ code, status: "pass", message: "m" }) })[name];
    const every = {
        // The keys are not in the README's order, and the order of the results must not follow them.
        expectKind: { value: "end-entity" },
        expectFingerprint: { value: "0".repeat(64) },
        expectSan: { value: ["a.example.com"] },
        rejectEku: { value: ["codeSigning"] },
        ekuAllows: { value: ["serverAuth"] },
        expectEku: { value: ["serverAuth"] },
        maxLifetimeUsed: { value: 0.5 },
        expiresWithin: { value: "1d" },
        validityNotEnded: {},
        validityStarted: {},
    };
    const rules = [own("second", "OWN_B"), own("first", "OWN_A")];
    const check = run({}, every, { rules });
    assert.deepEqual(check.results.map((/** @type {any} */ result) => result.code), [
        "NOT_YET_VALID", "EXPIRED", "EXPIRES_SOON", "LIFETIME_USED_EXCEEDED", "EKU_MISSING", "EKU_NOT_PERMITTED", "EKU_FORBIDDEN",
        "SAN_MISSING", "FINGERPRINT_MISMATCH", "TARGET_NOT_END_ENTITY", "OWN_B", "OWN_A",
    ]);
    assert.deepEqual(check.results.map((/** @type {any} */ result) => result.rule.name), [
        "validityStarted", "validityNotEnded", "expiresWithin", "maxLifetimeUsed", "expectEku", "ekuAllows", "rejectEku", "expectSan", "expectFingerprint", "expectKind", "second", "first",
    ]);
    assert.deepEqual(ENTRIES.map(([entry]) => entry).filter((entry) => entry !== "matchesPrivateKey"), check.results.slice(0, 10).map((/** @type {any} */ result) => result.rule.name), "the order of the policy table");

    // The two validity entries are there with or without being listed, and first.
    assert.deepEqual(statuses(run({}, {})).slice(0, 2), ["NOT_YET_VALID pass", "EXPIRED pass"]);
    assert.deepEqual(statuses(run({}, { validityNotEnded: {} })).slice(0, 2), ["NOT_YET_VALID pass", "EXPIRED pass"]);
    assert.deepEqual(statuses(run({}, { expectKind: { value: "end-entity" } })), ["NOT_YET_VALID pass", "EXPIRED pass", "TARGET_NOT_END_ENTITY pass"]);
});

test("POLICY_EMPTY is the last result, a warning with no rule, and exists only when the policy lists nothing besides the validity entries and no rule of your own was given", () => {
    const empty = run({}, {});
    assert.deepEqual(statuses(empty), ["NOT_YET_VALID pass", "EXPIRED pass", "POLICY_EMPTY warn"]);
    assert.equal(empty.results[2].rule, null);
    assert.deepEqual(Object.keys(empty.results[2]).sort(), ["code", "message", "rule", "status"]);
    assert.equal(empty.summary.status, "warn");
    assert.deepEqual(errorsOf(empty), []);

    // Listing the two validity entries, even to lower their severity, adds no rule.
    assert.equal(run({}, { validityStarted: { severity: "warn" }, validityNotEnded: {} }).results.at(-1).code, "POLICY_EMPTY");
    // A rule of your own is something to check, whether or not it holds, and so is any other entry.
    assert.deepEqual(statuses(run({}, {}, { rules: [() => ({ code: "OWN", status: "pass", message: "m" })] })).at(-1), "OWN pass");
    assert.ok(!statuses(run({}, { expectKind: { value: "end-entity" } })).includes("POLICY_EMPTY warn"));
    // An empty list of rules is no rule.
    assert.equal(run({}, {}, { rules: [] }).results.at(-1).code, "POLICY_EMPTY");
    assert.equal(run({}, {}, { rules: undefined }).results.at(-1).code, "POLICY_EMPTY");
});

test("the applied policy has the contract, the entries this version knows with their severity written out, the two validity entries always, and nothing this version does not know", () => {
    const given = {
        contract: 1,
        // Out of the table's order, with a property that is not this version's in each place.
        expiresWithin: { value: "30d", severity: "warn", note: "put here by mistake", nested: { deep: [1] } },
        validityNotEnded: { severity: "warn", value: "ignored" },
        expectSan: { value: ["B.example.com", "a.example.com"] },
        passphrase: "hunter2-never-repeated",
        expectSAN: { value: ["misspelled.example.com"] },
    };
    const before = structuredClone(given);
    const check = evaluate(observed(), /** @type {any} */ (given));
    assert.deepEqual(check.policy, {
        contract: 1,
        validityStarted: { severity: "fail" },
        validityNotEnded: { severity: "warn" },
        expiresWithin: { value: "30d", severity: "warn" },
        expectSan: { value: ["B.example.com", "a.example.com"], severity: "fail" },
    });
    assert.deepEqual(Object.keys(check.policy), ["contract", "validityStarted", "validityNotEnded", "expiresWithin", "expectSan"]);
    assert.deepEqual(given, before, "the policy is not modified");
    const text = serializeCheckResult(check);
    for (const secret of ["hunter2-never-repeated", "put here by mistake", "misspelled", "ignored"]) assert.ok(!text.includes(secret), secret);
    assert.deepEqual(errorsOf(check), []);

    // A rule is the entry's name and the value as written, and a rule with no value has none.
    assert.deepEqual(resultOf(check, "expiresWithin").rule, { name: "expiresWithin", value: "30d" });
    assert.deepEqual(resultOf(check, "validityNotEnded").rule, { name: "validityNotEnded" });
    assert.deepEqual(resultOf(check, "expectSan").rule.value, ["B.example.com", "a.example.com"]);
});

test("nothing in the result is shared with the policy: changing one of the places a value is written changes none of the others", () => {
    const given = policyOf({ expectEku: { value: ["serverAuth"] } });
    const check = evaluate(observed(), given);
    check.policy.expectEku.value.push("clientAuth");
    assert.deepEqual(resultOf(check, "expectEku").rule.value, ["serverAuth"]);
    assert.deepEqual(given.expectEku.value, ["serverAuth"]);
    resultOf(check, "expectEku").rule.value.push("codeSigning");
    assert.deepEqual(given.expectEku.value, ["serverAuth"]);
    assert.deepEqual(resultOf(check, "expectEku").expected, ["serverAuth"]);
    // And what a rule found is not the observation's own list.
    resultOf(check, "expectEku").actual.push("x");
    assert.ok(!check.observation.certificates[0].eku.includes("x"));
});

// ---------------------------------------------------------------------------------------------
// The verdict

test("summary.status is fail when any result fails, otherwise warn when any warns, otherwise pass, the counts are by status, and a rule with severity warn reports warn when it does not hold and never makes the check fail", () => {
    const past = shifted(END, 1);
    const fields = { notBefore: START, notAfter: END };

    const passing = run(fields, { expectKind: { value: "end-entity" } }, { now: shifted(START, 5) });
    assert.deepEqual(passing.summary, { status: "pass", pass: 3, warn: 0, fail: 0 });

    const warning = run(fields, { validityNotEnded: { severity: "warn" } }, { now: past });
    assert.deepEqual(statuses(warning), ["NOT_YET_VALID pass", "EXPIRED warn", "POLICY_EMPTY warn"]);
    assert.deepEqual(warning.summary, { status: "warn", pass: 1, warn: 2, fail: 0 });

    const failing = run(fields, { expiresWithin: { value: "1d", severity: "warn" } }, { now: past });
    assert.deepEqual(statuses(failing), ["NOT_YET_VALID pass", "EXPIRED fail", "EXPIRES_SOON warn"]);
    assert.deepEqual(failing.summary, { status: "fail", pass: 1, warn: 1, fail: 1 });

    // Every rule of the policy lowered to a warning gives a check that does not fail.
    /** @type {Record<string, unknown>} */
    const lowered = {};
    for (const [entry, kind] of ENTRIES) {
        if (entry === "matchesPrivateKey") continue;
        Object.assign(lowered, { [entry]: { ...(kind === "none" ? {} : { value: { duration: "1d", fraction: 0, usages: ["codeSigning"], names: ["nobody.example"], sha256: "0".repeat(64), "end-entity": "end-entity" }[kind] }), severity: "warn" } });
    }
    const never = run({ ...fields, kind: "ca", eku: [] }, lowered, { now: past });
    assert.notEqual(never.summary.status, "fail");
    assert.equal(never.summary.fail, 0);
    assert.ok(never.summary.warn >= 8, `${never.summary.warn} warnings`);
    for (const result of never.results) assert.notEqual(result.status, "fail", result.code);
    assert.deepEqual(errorsOf(never), []);
});

// ---------------------------------------------------------------------------------------------
// The instant

test("options.now is a Date or a timestamp in the contract's form, defaults to the observation's at, is recorded cut to the whole second, and leaves the observation's at as it was", () => {
    const observation = observed({}, "2026-09-15T14:02:11Z");
    const before = structuredClone(observation);

    assert.equal(evaluate(observation, policyOf()).now, "2026-09-15T14:02:11Z", "the observation's at, by default");
    assert.equal(evaluate(observation, policyOf(), {}).now, "2026-09-15T14:02:11Z");
    assert.equal(evaluate(observation, policyOf(), { now: undefined }).now, "2026-09-15T14:02:11Z");
    assert.equal(evaluate(observation, policyOf(), { now: "2026-10-20T00:00:00Z" }).now, "2026-10-20T00:00:00Z");
    assert.equal(evaluate(observation, policyOf(), { now: new Date("2026-10-20T00:00:00Z") }).now, "2026-10-20T00:00:00Z");
    // Cut, not rounded: 0.999 s is still the second before.
    assert.equal(evaluate(observation, policyOf(), { now: new Date("2026-10-20T00:00:00.999Z") }).now, "2026-10-20T00:00:00Z");

    const other = evaluate(observation, policyOf(), { now: "2026-10-20T00:00:00Z" });
    assert.equal(other.observation.observation.at, "2026-09-15T14:02:11Z", "the result's observation keeps its at");
    assert.deepEqual(observation, before, "and so does the one that was given");
    assert.deepEqual(errorsOf(other), []);
    // The expected of the validity rules is the instant that was used.
    assert.equal(resultOf(other, "validityNotEnded").expected, "2026-10-20T00:00:00Z");
});

test("an instant before 1970 is cut down to the second before, not moved forward to the next one", () => {
    // `Math.trunc` would turn -0.5 s into 1970-01-01T00:00:00Z.
    const check = evaluate(observed(), policyOf(), { now: new Date(-500) });
    assert.equal(check.now, "1969-12-31T23:59:59Z");
    assert.equal(evaluate(observed(), policyOf(), { now: new Date(-1000) }).now, "1969-12-31T23:59:59Z");
    assert.equal(evaluate(observed(), policyOf(), { now: new Date(-1001) }).now, "1969-12-31T23:59:58Z");
    assert.equal(evaluate(observed(), policyOf(), { now: new Date(-1) }).now, "1969-12-31T23:59:59Z");
    assert.equal(evaluate(observed(), policyOf(), { now: new Date(0) }).now, "1970-01-01T00:00:00Z");
});

test("a now that is not an instant is a TypeError that names options.now, and so is one outside the years 0 to 9999, which the result could not write", () => {
    const wrong = [
        null, "", "now", "2026-02-30T00:00:00Z", "2026-09-15T24:00:00Z", "2026-09-15T14:02:11", "2026-09-15T14:02:11+00:00",
        "2026-09-15T14:02:11.5Z", " 2026-09-15T14:02:11Z", "2026-09-15", 1789480931, 1789480931000, true, {}, [], () => 0, Symbol("now"), 10n,
        new Date(Number.NaN), new Proxy(new Date(0), {}), { getTime: () => 0 },
        // One second outside either end of the years 0 to 9999, as a Date.
        new Date(Date.UTC(10000, 0, 1)), new Date(-62167219201000), new Date(8.64e15),
    ];
    for (const [position, now] of wrong.entries()) {
        assert.throws(() => evaluate(observed(), policyOf(), /** @type {any} */ ({ now })), (error) => error instanceof TypeError && /options\.now/.test(error.message), `wrong now number ${position}`);
    }
    // The ends themselves are instants, and a fraction past the last whole second is cut away.
    assert.equal(evaluate(observed(), policyOf(), { now: "0000-01-01T00:00:00Z" }).now, "0000-01-01T00:00:00Z");
    assert.equal(evaluate(observed(), policyOf(), { now: "9999-12-31T23:59:59Z" }).now, "9999-12-31T23:59:59Z");
    assert.equal(evaluate(observed(), policyOf(), { now: new Date("9999-12-31T23:59:59.999Z") }).now, "9999-12-31T23:59:59Z");
    assert.throws(() => evaluate(observed(), policyOf(), { now: new Date("9999-12-31T23:59:59Z").getTime() + 1000 }), TypeError);
    assert.throws(() => evaluate(observed(), policyOf(), { now: /** @type {any} */ (new Date(Date.UTC(10000, 0, 1))) }), /between the years 0 and 9999/);

    // `inspect()` gives its own `at` the same limit, and says it the same way.
    assert.throws(() => inspect(fixture("leaf-p256.pem"), { at: new Date(Date.UTC(10000, 0, 1)) }), /options\.at must fall between the years 0 and 9999/);
});

test("a Date from another realm or of a subclass is an instant, and an object that only has the methods of one is not", () => {
    const foreign = runInNewContext("new Date('2026-10-20T00:00:00.500Z')");
    assert.equal(evaluate(observed(), policyOf(), { now: foreign }).now, "2026-10-20T00:00:00Z");
    class Later extends Date {
        getTime() {
            return /** @type {any} */ ("not a number");
        }
    }
    // The engine's own time is read, not the answer of a method the subclass wrote.
    assert.equal(evaluate(observed(), policyOf(), { now: new Later("2026-10-20T00:00:00Z") }).now, "2026-10-20T00:00:00Z");
});

// ---------------------------------------------------------------------------------------------
// The time rules

test("the time rules use the certificate's original notBefore and notAfter and never the rounded derived values, and their messages use the words outsideValidity gives", () => {
    // derived says there are 9999 days left and 0.5 of the lifetime is used, whatever the dates say.
    const lying = { derived: { daysRemaining: 9999, lifetimeFraction: 0.5 } };
    const fields = { ...lying, notBefore: START, notAfter: END };

    // An hour past the end: derived.daysRemaining would round to 0, and the certificate has expired.
    const ended = run(fields, { expiresWithin: { value: "1d" }, maxLifetimeUsed: { value: 0.9 } }, { now: shifted(END, 3600) });
    assert.deepEqual(statuses(ended), ["NOT_YET_VALID pass", "EXPIRED fail", "EXPIRES_SOON fail", "LIFETIME_USED_EXCEEDED fail"]);
    assert.match(resultOf(ended, "validityNotEnded").message, new RegExp(outsideValidity(START, END, shifted(END, 3600))[0]));
    assert.equal(resultOf(ended, "validityNotEnded").actual, END);
    assert.equal(resultOf(ended, "validityNotEnded").expected, shifted(END, 3600));

    const early = run(fields, {}, { now: shifted(START, -1) });
    assert.deepEqual(statuses(early).slice(0, 2), ["NOT_YET_VALID fail", "EXPIRED pass"]);
    assert.match(resultOf(early, "validityStarted").message, new RegExp(outsideValidity(START, END, shifted(START, -1))[0]));
    assert.equal(resultOf(early, "validityStarted").actual, START);

    const inside = run(fields, {}, { now: shifted(START, 86400) });
    assert.doesNotMatch(resultOf(inside, "validityStarted").message, /not yet valid/);
    assert.doesNotMatch(resultOf(inside, "validityNotEnded").message, /expired/);
});

test("a now equal to notBefore or to notAfter passes, one second outside either end fails, and a validity of one second is that second", () => {
    for (const as of [(/** @type {string} */ text) => text, (/** @type {string} */ text) => new Date(text)]) {
        const at = (/** @type {number} */ offset, /** @type {string} */ from) => ({ now: as(shifted(from, offset)) });
        const fields = { notBefore: START, notAfter: END };
        assert.deepEqual(statuses(run(fields, {}, at(0, START))).slice(0, 2), ["NOT_YET_VALID pass", "EXPIRED pass"], "at notBefore");
        assert.deepEqual(statuses(run(fields, {}, at(0, END))).slice(0, 2), ["NOT_YET_VALID pass", "EXPIRED pass"], "at notAfter");
        assert.deepEqual(statuses(run(fields, {}, at(-1, START))).slice(0, 2), ["NOT_YET_VALID fail", "EXPIRED pass"], "a second before notBefore");
        assert.deepEqual(statuses(run(fields, {}, at(1, END))).slice(0, 2), ["NOT_YET_VALID pass", "EXPIRED fail"], "a second after notAfter");
        const second = { notBefore: START, notAfter: START };
        assert.deepEqual(statuses(run(second, {}, at(0, START))).slice(0, 2), ["NOT_YET_VALID pass", "EXPIRED pass"]);
        assert.deepEqual(statuses(run(second, {}, at(1, START))).slice(0, 2), ["NOT_YET_VALID pass", "EXPIRED fail"]);
    }
    // A validity that ends before it starts fails both rules between its dates, as the two codes are independent.
    const inverted = run({ notBefore: "2030-01-01T00:00:00Z", notAfter: "2020-01-01T00:00:00Z" }, {}, { now: "2025-01-01T00:00:00Z" });
    assert.deepEqual(statuses(inverted).slice(0, 2), ["NOT_YET_VALID fail", "EXPIRED fail"]);
});

test("expiresWithin compares whole seconds: 30d is 2 592 000 and 72h is 259 200, the threshold itself passes, one second less fails, and a certificate that has ended has negative time left and fails", () => {
    const now = "2026-09-15T14:02:11Z";
    for (const [value, threshold] of /** @type {[string, number][]} */ ([["30d", 2592000], ["72h", 259200], ["1d", 86400], ["1h", 3600], ["999999d", 86399913600], ["999999h", 3599996400]])) {
        const entry = { expiresWithin: { value } };
        const exact = run({ notAfter: shifted(now, threshold) }, entry, { now });
        assert.equal(resultOf(exact, "expiresWithin").status, "pass", `${value}: exactly the threshold`);
        assert.equal(resultOf(exact, "expiresWithin").actual, threshold);
        assert.equal(resultOf(exact, "expiresWithin").expected, threshold);

        const short = run({ notAfter: shifted(now, threshold - 1) }, entry, { now });
        assert.equal(resultOf(short, "expiresWithin").status, "fail", `${value}: one second less`);
        assert.equal(resultOf(short, "expiresWithin").actual, threshold - 1);

        const more = run({ notAfter: shifted(now, threshold + 1) }, entry, { now });
        assert.equal(resultOf(more, "expiresWithin").status, "pass", `${value}: one second more`);
    }
    // Whole seconds on both sides: the observation has no fractions, and the instant is cut.
    const cut = run({ notAfter: shifted(now, 3600) }, { expiresWithin: { value: "1h" } }, { now: new Date("2026-09-15T14:02:11.900Z") });
    assert.equal(resultOf(cut, "expiresWithin").actual, 3600);

    // Ended: the time left is negative, and the rule fails as well as validityNotEnded.
    const ended = run({ notAfter: shifted(now, -5) }, { expiresWithin: { value: "1h" } }, { now });
    assert.deepEqual(statuses(ended), ["NOT_YET_VALID pass", "EXPIRED fail", "EXPIRES_SOON fail"]);
    assert.equal(resultOf(ended, "expiresWithin").actual, -5);
    assert.equal(resultOf(ended, "expiresWithin").expected, 3600);
    assert.match(resultOf(ended, "expiresWithin").message, /already ended/);
    // The unit is read from the last character and the number from the rest.
    assert.equal(resultOf(run({}, { expiresWithin: { value: "72h" } }), "expiresWithin").expected, 259200);
});

test("the message of expiresWithin says the whole days or hours left, rounded down, and which side of the threshold it is on", () => {
    const now = "2026-09-15T14:02:11Z";
    /** @param {number} seconds @param {string} value */
    const message = (seconds, value) => resultOf(run({ notAfter: shifted(now, seconds) }, { expiresWithin: { value } }, { now }), "expiresWithin").message;
    assert.equal(message(86400 * 14, "14d"), "14 days are left, not below 14d");
    assert.equal(message(86400 * 14 - 1, "14d"), "13 days are left, below 14d");
    assert.equal(message(86400 * 1, "1d"), "1 day is left, not below 1d");
    assert.equal(message(3600 * 3 + 59, "72h"), "3 hours are left, below 72h");
    assert.equal(message(86400 - 1, "1d"), "0 days are left, below 1d");
    assert.equal(message(0, "1d"), "0 days are left, below 1d");
});

// ---------------------------------------------------------------------------------------------
// maxLifetimeUsed is decided exactly

/**
 * The result of maxLifetimeUsed for a validity of `duration` seconds, `used` of them gone.
 * @param {number} threshold
 * @param {number} duration
 * @param {number} used
 * @param {string} [from]
 * @returns {any}
 */
function lifetime(threshold, duration, used, from = duration > 2e11 ? "0000-01-01T00:00:00Z" : "1000-01-01T00:00:00Z") {
    const check = run({ notBefore: from, notAfter: shifted(from, duration) }, { maxLifetimeUsed: { value: threshold } }, { now: shifted(from, used) });
    return resultOf(check, "maxLifetimeUsed");
}

test("maxLifetimeUsed is decided exactly: a used fraction equal to 0.57, 0.29 or 0.07 passes and one second more fails", () => {
    // In floating point 0.57 * 100 is 56.99999999999999, so comparing the seconds used with the
    // threshold times the seconds the validity lasts would fail a certificate that is exactly at 57%.
    assert.notEqual(0.57 * 100, 57);
    assert.notEqual(0.29 * 100, 29);
    assert.notEqual(0.07 * 100, 7);
    assert.ok(0.57 * 1e10 < 5.7e9, "and the same for a long validity");

    for (const [threshold, hundredths] of /** @type {[number, number][]} */ ([[0.57, 57], [0.29, 29], [0.07, 7], [0.66, 66], [0.58, 58], [0.14, 14], [0.28, 28], [0.55, 55]])) {
        for (const duration of [100, 1e7, 1e10, 3.1e11]) {
            const exact = (duration / 100) * hundredths;
            const at = lifetime(threshold, duration, exact);
            assert.equal(at.status, "pass", `${threshold} of ${duration} s, exactly`);
            assert.equal(at.actual, exact / duration);
            assert.equal(at.expected, threshold);
            assert.equal(lifetime(threshold, duration, exact - 1).status, "pass", `${threshold} of ${duration} s, a second less`);
            assert.equal(lifetime(threshold, duration, exact + 1).status, "fail", `${threshold} of ${duration} s, a second more`);
        }
    }
});

test("maxLifetimeUsed reads a threshold written with an exponent exactly, and so are both ends, 0 and 1", () => {
    // `String(1e-7)` is "1e-7" and `String(5e-324)` is "5e-324": the digits come after the exponent is read.
    assert.equal(String(1e-7), "1e-7");
    assert.equal(String(5e-324), "5e-324");
    assert.equal(String(1.5e-7), "1.5e-7");
    assert.equal(String(0.000001), "0.000001");
    for (const [threshold, duration, exact] of /** @type {[number, number, number][]} */ ([[1e-7, 1e7, 1], [1.5e-7, 2e7, 3], [1e-6, 1e6, 1], [0.000001, 3e11, 3e5], [1e-7, 3.1e11, 31000]])) {
        assert.equal(lifetime(threshold, duration, exact).status, "pass", `${threshold} of ${duration} s, exactly`);
        assert.equal(lifetime(threshold, duration, exact + 1).status, "fail", `${threshold} of ${duration} s, a second more`);
        assert.equal(lifetime(threshold, duration, exact - 1).status, "pass", `${threshold} of ${duration} s, a second less`);
    }
    // The smallest positive number: of any validity that lasts a second, it allows no second.
    assert.equal(lifetime(5e-324, 3.1e11, 0).status, "pass");
    assert.equal(lifetime(5e-324, 3.1e11, 1).status, "fail");
    assert.equal(lifetime(5e-324, 1, 0).status, "pass");
    assert.equal(lifetime(5e-324, 1, 1).status, "fail");

    // 0 allows nothing used, and 1 allows all of it.
    assert.equal(lifetime(0, 1000, 0).status, "pass");
    assert.equal(lifetime(0, 1000, 1).status, "fail");
    assert.equal(lifetime(0, 1000, -1).status, "pass", "before the start nothing is used");
    assert.equal(lifetime(1, 1000, 1000).status, "pass");
    assert.equal(lifetime(1, 1000, 1001).status, "fail");
    assert.equal(lifetime(1, 3.1e11, 3.1e11).status, "pass");
    assert.equal(lifetime(1, 3.1e11, 3.1e11 + 1).status, "fail");
    assert.equal(lifetime(1, 1000, 0).actual, 0);
    assert.equal(lifetime(1, 1000, 1000).actual, 1);
    assert.equal(lifetime(1, 1000, 1500).actual, 1.5, "unrounded, and above 1 once the validity has ended");
    assert.equal(lifetime(0.5, 1000, -250).actual, -0.25, "and negative before it starts");
});

test("maxLifetimeUsed over the longest validity a certificate can have, from the year 0 to the year 9999, is exact", () => {
    const from = "0000-01-01T00:00:00Z";
    const duration = 3.1e11;
    for (const [threshold, exact] of /** @type {[number, number][]} */ ([[0.07, 2.17e10], [0.1234567, 38271577000], [0.9999999, 309999969000]])) {
        assert.equal(lifetime(threshold, duration, exact, from).status, "pass", `${threshold}`);
        assert.equal(lifetime(threshold, duration, exact + 1, from).status, "fail", `${threshold}, a second more`);
    }
});

test("maxLifetimeUsed with a validity that does not end after it starts has no fraction to show and is decided without a division: it fails once now is after notBefore", () => {
    const from = "2026-01-01T00:00:00Z";
    for (const threshold of [0, 0.5, 1]) {
        const none = lifetime(threshold, 0, 0, from);
        assert.equal(none.status, "pass", `${threshold}: at notBefore`);
        assert.equal(none.actual, null);
        assert.equal(none.expected, threshold);
        assert.equal(lifetime(threshold, 0, 1, from).status, "fail", `${threshold}: a second after`);
        assert.equal(lifetime(threshold, 0, 1, from).actual, null);
        assert.equal(lifetime(threshold, 0, -1, from).status, "pass", `${threshold}: before`);
    }
    // notAfter before notBefore: the definition read as written, now - notBefore not above threshold * (notAfter - notBefore).
    const inverted = (/** @type {number} */ used) => resultOf(run({ notBefore: shifted(from, 100), notAfter: from }, { maxLifetimeUsed: { value: 0.5 } }, { now: shifted(from, 100 + used) }), "maxLifetimeUsed");
    assert.equal(inverted(-50).status, "pass");
    assert.equal(inverted(-51).status, "pass");
    assert.equal(inverted(-49).status, "fail");
    assert.equal(inverted(0).status, "fail");
    assert.equal(inverted(0).actual, null);
});

test("a threshold of -0 is the threshold 0: it decides the same and writes the same bytes", () => {
    const negative = run({}, { maxLifetimeUsed: { value: -0 } });
    const positive = run({}, { maxLifetimeUsed: { value: 0 } });
    assert.equal(resultOf(negative, "maxLifetimeUsed").status, resultOf(positive, "maxLifetimeUsed").status);
    assert.equal(resultOf(negative, "maxLifetimeUsed").message, resultOf(positive, "maxLifetimeUsed").message);
    assert.equal(serializeCheckResult(negative), serializeCheckResult(positive));
    assert.deepEqual(errorsOf(negative), []);
});

test("the message of maxLifetimeUsed rounds the percentage the way the verdict went, so it never says 57% used, above 57%", () => {
    const message = (/** @type {number} */ threshold, /** @type {number} */ duration, /** @type {number} */ used) => lifetime(threshold, duration, used).message;
    assert.equal(message(0.57, 1e9, 5.7e8), "57% of the lifetime is used, within 57%");
    assert.equal(message(0.57, 1e9, 5.7e8 + 1), "58% of the lifetime is used, above 57%");
    assert.equal(message(0.57, 1e9, 5.7e8 - 1), "56% of the lifetime is used, within 57%");
    assert.equal(message(0.663, 1e9, 6.63e8), "66% of the lifetime is used, within 66.3%");
    assert.equal(message(0.663, 1e9, 6.63e8 + 1), "67% of the lifetime is used, above 66.3%");
    assert.equal(message(1e-7, 1e7, 1), "0% of the lifetime is used, within 0.00001%");
    assert.equal(message(1e-7, 1e7, 2), "1% of the lifetime is used, above 0.00001%");
    assert.equal(message(0, 1000, 0), "0% of the lifetime is used, within 0%");
    assert.equal(message(1, 1000, 1000), "100% of the lifetime is used, within 100%");
    assert.equal(message(0.5, 1000, -250), "-25% of the lifetime is used, within 50%");
    assert.equal(message(0.5, 1000, -251), "-26% of the lifetime is used, within 50%");
    assert.match(message(5e-324, 1, 0), /^0% of the lifetime is used, within 0\.0{321}5%$/);
    assert.match(lifetime(0.5, 0, 1).message, /does not end after it starts, and the rule does not hold for 50%/);
    assert.match(lifetime(0.5, 0, 0).message, /does not end after it starts, and the rule holds for 50%/);
});

// ---------------------------------------------------------------------------------------------
// Extended Key Usage

test("the Extended Key Usage rules tell eku null from [] and from a list: expectEku fails both null and [], ekuAllows passes null and fails [], rejectEku passes both", () => {
    const entries = { expectEku: { value: ["serverAuth"] }, ekuAllows: { value: ["serverAuth"] }, rejectEku: { value: ["serverAuth"] } };
    const row = (/** @type {string[] | null} */ eku) => statuses(run({ eku }, entries)).slice(2, 5);
    assert.deepEqual(row(null), ["EKU_MISSING fail", "EKU_NOT_PERMITTED pass", "EKU_FORBIDDEN pass"]);
    assert.deepEqual(row([]), ["EKU_MISSING fail", "EKU_NOT_PERMITTED fail", "EKU_FORBIDDEN pass"]);
    assert.deepEqual(row(["clientAuth"]), ["EKU_MISSING fail", "EKU_NOT_PERMITTED fail", "EKU_FORBIDDEN pass"]);
    assert.deepEqual(row(["serverAuth"]), ["EKU_MISSING pass", "EKU_NOT_PERMITTED pass", "EKU_FORBIDDEN fail"]);
    assert.deepEqual(row(["clientAuth", "serverAuth"]), ["EKU_MISSING pass", "EKU_NOT_PERMITTED pass", "EKU_FORBIDDEN fail"]);

    // What was found is what the observation holds: null stays null, and [] stays [].
    assert.equal(resultOf(run({ eku: null }, entries), "expectEku").actual, null);
    assert.deepEqual(resultOf(run({ eku: [] }, entries), "expectEku").actual, []);
    assert.deepEqual(resultOf(run({ eku: ["clientAuth"] }, entries), "ekuAllows").actual, ["clientAuth"]);
    for (const eku of [null, [], ["serverAuth"]]) assert.deepEqual(errorsOf(run({ eku }, entries)), []);

    // Several usages: all must be listed, and any one listed is enough for rejectEku to fail.
    const two = { expectEku: { value: ["serverAuth", "clientAuth"] }, ekuAllows: { value: ["serverAuth", "clientAuth"] }, rejectEku: { value: ["serverAuth", "clientAuth"] } };
    assert.deepEqual(statuses(run({ eku: ["serverAuth"] }, two)).slice(2, 5), ["EKU_MISSING fail", "EKU_NOT_PERMITTED fail", "EKU_FORBIDDEN fail"]);
    assert.deepEqual(statuses(run({ eku: ["clientAuth", "serverAuth"] }, two)).slice(2, 5), ["EKU_MISSING pass", "EKU_NOT_PERMITTED pass", "EKU_FORBIDDEN fail"]);
    assert.deepEqual(statuses(run({ eku: ["codeSigning"] }, two)).slice(2, 5), ["EKU_MISSING fail", "EKU_NOT_PERMITTED fail", "EKU_FORBIDDEN pass"]);
});

test("the messages of the Extended Key Usage rules say whether the extension is absent, empty or lists usages, and which usages are not listed or are", () => {
    const entries = { expectEku: { value: ["serverAuth", "clientAuth"] }, ekuAllows: { value: ["serverAuth"] }, rejectEku: { value: ["codeSigning", "clientAuth"] } };
    const messages = (/** @type {string[] | null} */ eku) => run({ eku }, entries).results.slice(2, 5).map((/** @type {any} */ result) => result.message);
    assert.deepEqual(messages(null), [
        "the certificate has no Extended Key Usage extension, so it does not list serverAuth, clientAuth",
        "the certificate has no Extended Key Usage extension, which restricts nothing",
        "the certificate has no Extended Key Usage extension, which does not include codeSigning, clientAuth",
    ]);
    assert.deepEqual(messages([]), [
        "the Extended Key Usage extension lists nothing, so it does not list serverAuth, clientAuth",
        "the Extended Key Usage extension lists nothing, which does not include serverAuth",
        "the Extended Key Usage extension lists nothing, which does not include codeSigning, clientAuth",
    ]);
    assert.deepEqual(messages(["clientAuth", "serverAuth"]), [
        "the Extended Key Usage extension lists clientAuth, serverAuth, which includes serverAuth, clientAuth",
        "the Extended Key Usage extension lists clientAuth, serverAuth, which includes serverAuth",
        "the Extended Key Usage extension lists clientAuth, serverAuth, which includes clientAuth",
    ]);
    assert.deepEqual(messages(["codeSigning"]), [
        "the Extended Key Usage extension lists codeSigning, so it does not list serverAuth, clientAuth",
        "the Extended Key Usage extension lists codeSigning, which does not include serverAuth",
        "the Extended Key Usage extension lists codeSigning, which includes codeSigning",
    ]);
});

test("a usage written as an OID is the same usage as its name when it has one: 1.3.6.1.5.5.7.3.2 and clientAuth both match the observation's clientAuth", () => {
    for (const [name, oid] of Object.entries(EXTENDED_KEY_USAGE_OIDS)) {
        for (const written of [name, oid]) {
            const entries = { expectEku: { value: [written] }, ekuAllows: { value: [written] }, rejectEku: { value: [written] } };
            const found = run({ eku: [name] }, entries);
            assert.deepEqual(statuses(found).slice(2, 5), ["EKU_MISSING pass", "EKU_NOT_PERMITTED pass", "EKU_FORBIDDEN fail"], `${written} against ${name}`);
            // The result says it by name, where there is one, and keeps what the policy wrote under rule.
            assert.deepEqual(resultOf(found, "expectEku").expected, [name]);
            assert.deepEqual(resultOf(found, "expectEku").rule.value, [written]);
        }
    }
    // A usage the contract has no name for stays as the OID, on both sides.
    const unnamed = run({ eku: ["1.2.3.4"] }, { expectEku: { value: ["1.2.3.4"] }, rejectEku: { value: ["1.2.3.5"] } });
    assert.deepEqual(statuses(unnamed).slice(2), ["EKU_MISSING pass", "EKU_FORBIDDEN pass"]);
    assert.deepEqual(resultOf(unnamed, "expectEku").expected, ["1.2.3.4"]);
    // The order and the repeats of the policy are kept, so each usage is at the position of its own.
    const repeated = run({ eku: ["serverAuth"] }, { expectEku: { value: ["1.3.6.1.5.5.7.3.2", "serverAuth", "1.3.6.1.5.5.7.3.1"] } });
    assert.deepEqual(resultOf(repeated, "expectEku").expected, ["clientAuth", "serverAuth", "serverAuth"]);
    assert.equal(resultOf(repeated, "expectEku").message, "the Extended Key Usage extension lists serverAuth, so it does not list clientAuth");
    // A usage written twice, by name and as an OID, is said once where it is missing and where it is listed.
    const twice = run({ eku: ["serverAuth"] }, { expectEku: { value: ["clientAuth", "1.3.6.1.5.5.7.3.2"] }, ekuAllows: { value: ["codeSigning", "1.3.6.1.5.5.7.3.3", "codeSigning"] }, rejectEku: { value: ["serverAuth", "1.3.6.1.5.5.7.3.1"] } });
    assert.deepEqual(twice.results.slice(2).map((/** @type {any} */ result) => result.message), [
        "the Extended Key Usage extension lists serverAuth, so it does not list clientAuth",
        "the Extended Key Usage extension lists serverAuth, which does not include codeSigning",
        "the Extended Key Usage extension lists serverAuth, which includes serverAuth",
    ]);
    assert.deepEqual(resultOf(twice, "expectEku").expected, ["clientAuth", "clientAuth"], "and the usages found are as the policy wrote them");
});

test("an extension that is present and lists nothing is [] in a real certificate, so the rules tell it from an absent extension", () => {
    const entries = { expectEku: { value: ["serverAuth"] }, ekuAllows: { value: ["serverAuth"] }, rejectEku: { value: ["serverAuth"] } };
    const observation = inspect(EMPTY_EKU_EXTENSION, { at: new Date(AT) });
    assert.deepEqual(observation.certificates[0].eku, []);
    const check = evaluate(observation, policyOf(entries), { now: observation.certificates[0].notBefore });
    assert.deepEqual(statuses(check).slice(2), ["EKU_MISSING fail", "EKU_NOT_PERMITTED fail", "EKU_FORBIDDEN pass"]);
    assert.deepEqual(resultOf(check, "expectEku").actual, []);
    // A certificate with no extension at all is the other case.
    const absent = inspect(fixture("leaf-no-cn.pem"), { at: new Date(AT) });
    assert.equal(absent.certificates[0].eku === null || Array.isArray(absent.certificates[0].eku), true);
    assert.deepEqual(errorsOf(check), []);
});

// ---------------------------------------------------------------------------------------------
// Today's behaviour that looks wrong and is not this function's to change

test("today an Extended Key Usage extension that does not decode reads as eku null with no warning, so ekuAllows and rejectEku pass it and expectEku fails it", () => {
    const observation = inspect(UNDECODABLE_EKU_EXTENSION, { at: new Date(AT) });
    assert.equal(observation.certificates[0].eku, null);
    assert.deepEqual(observation.warnings, []);
    const check = evaluate(observation, policyOf({ expectEku: { value: ["serverAuth"] }, ekuAllows: { value: ["serverAuth"] }, rejectEku: { value: ["serverAuth"] } }), { now: observation.certificates[0].notBefore });
    assert.deepEqual(statuses(check).slice(2), ["EKU_MISSING fail", "EKU_NOT_PERMITTED pass", "EKU_FORBIDDEN pass"]);
    assert.equal(resultOf(check, "ekuAllows").actual, null);
    assert.deepEqual(errorsOf(check), []);
});

test("today an entry this version does not know, such as a misspelled expectSAN, checks nothing, is not in the applied policy, and a policy of nothing else gives POLICY_EMPTY", () => {
    const check = evaluate(observed(), /** @type {any} */ ({ contract: 1, expectSAN: { value: ["nobody.example.com"] }, expiresOn: { value: "x" } }));
    assert.deepEqual(statuses(check), ["NOT_YET_VALID pass", "EXPIRED pass", "POLICY_EMPTY warn"]);
    assert.deepEqual(Object.keys(check.policy), ["contract", "validityStarted", "validityNotEnded"]);
    assert.deepEqual(policyProblems({ contract: 1, expectSAN: { value: [] } }), [], "and policyProblems tolerates it, as the contract says");
});

test("today a certificate that lists anyExtendedKeyUsage satisfies neither expectEku nor ekuAllows for serverAuth, because the rules count only the usages that are listed", () => {
    const check = run({ eku: ["2.5.29.37.0"] }, { expectEku: { value: ["serverAuth"] }, ekuAllows: { value: ["serverAuth"] }, rejectEku: { value: ["serverAuth"] } });
    assert.deepEqual(statuses(check).slice(2), ["EKU_MISSING fail", "EKU_NOT_PERMITTED fail", "EKU_FORBIDDEN pass"]);
});

// ---------------------------------------------------------------------------------------------
// expectSan

test("expectSan reads each item as sanItem does, compares an address in the canonical form in san.ip and a name in lower case in san.dns, and compares a wildcard as written", () => {
    const san = { dns: ["*.wild.example.com", "api.example.com"], ip: ["192.0.2.10", "2001:db8::1"], email: [], uri: [] };
    const found = (/** @type {string[]} */ value, /** @type {Record<string, unknown>} */ target = { san }) => resultOf(run(target, { expectSan: { value } }), "expectSan");

    assert.equal(found(["api.example.com"]).status, "pass");
    assert.equal(found(["API.Example.COM"]).status, "pass", "a name in lower case");
    assert.equal(found(["2001:0DB8:0:0:0:0:0:1"]).status, "pass", "an address in its canonical form");
    assert.equal(found(["2001:DB8::0:1"]).status, "pass");
    assert.equal(found(["::ffff:192.0.2.1"]).status, "fail");
    assert.equal(found(["192.0.2.10", "2001:db8::1", "api.example.com", "*.wild.example.com"]).status, "pass");
    assert.equal(found(["missing.example.com"]).status, "fail");
    assert.equal(found(["api.example.com", "missing.example.com"]).status, "fail", "any missing name fails");

    // A wildcard is one name as written, not a pattern.
    assert.equal(found(["*.wild.example.com"]).status, "pass");
    assert.equal(found(["a.wild.example.com"]).status, "fail", "a name a wildcard would cover is not listed");
    assert.equal(found(["*.example.com"]).status, "fail");
    assert.equal(found(["*.example.com"], { san: { dns: ["a.example.com"], ip: [], email: [], uri: [] } }).status, "fail");
    assert.equal(found(["*.example.com"], { san: { dns: ["*.example.com"], ip: [], email: [], uri: [] } }).status, "pass");

    // An address is an address, and a name is a name: they are not compared in each other's lists.
    assert.equal(found(["192.0.2.10"], { san: { dns: ["192.0.2.10"], ip: [], email: [], uri: [] } }).status, "fail");
    assert.equal(found(["api.example.com"], { san: { dns: [], ip: ["192.0.2.10"], email: [], uri: [] } }).status, "fail");

    // What is found and what is expected: both lists, sorted, with the names as compared.
    const result = found(["2001:0DB8::1", "B.example.com", "192.0.2.10", "a.example.com"]);
    assert.deepEqual(result.expected, { dns: ["a.example.com", "b.example.com"], ip: ["192.0.2.10", "2001:db8::1"] });
    assert.deepEqual(result.actual, { dns: ["*.wild.example.com", "api.example.com"], ip: ["192.0.2.10", "2001:db8::1"] });
    assert.equal(result.message, "the certificate does not list a.example.com, b.example.com");
    assert.equal(found(["api.example.com"]).message, "the certificate lists every expected name");
    assert.deepEqual(errorsOf(run({ san }, { expectSan: { value: ["a.example.com"] } })), []);
    // The two lists of the observation are the ones that are read, and email and uri are not.
    assert.equal(found(["example.com"], { san: { dns: [], ip: [], email: ["example.com"], uri: ["example.com"] } }).status, "fail");
});

test("a certificate that lists thousands of names can be asked for thousands of them", () => {
    const dns = Array.from({ length: 20000 }, (_, index) => `host-${index}.example.com`);
    const san = { dns, ip: [], email: [], uri: [] };
    const found = resultOf(run({ san }, { expectSan: { value: dns.slice(0, 5000) } }), "expectSan");
    assert.equal(found.status, "pass");
    assert.equal(found.expected.dns.length, 5000);
    const missing = resultOf(run({ san }, { expectSan: { value: [...dns.slice(0, 5000), "host-20000.example.com"] } }), "expectSan");
    assert.equal(missing.message, "the certificate does not list host-20000.example.com");
});

test("every address and every host name a certificate among the fixtures lists can be expected as it is listed, and passes", () => {
    let expected = 0;
    for (const file of readdirSync(new URL("fixtures/", import.meta.url)).filter((name) => /\.(pem|der)$/.test(name)).sort()) {
        let observation;
        try {
            observation = inspect(fixture(file), { at: new Date(AT) });
        } catch (error) {
            if (error instanceof AmbiguousTargetError) continue;
            throw error;
        }
        const { san } = observation.certificates[observation.target];
        // A DNS entry that is not a host name cannot be asked for, whatever the certificate lists.
        const names = [...san.dns, ...san.ip].filter((name) => policyProblems(policyOf({ expectSan: { value: [name] } })).length === 0);
        if (names.length === 0) continue;
        const check = evaluate(observation, policyOf({ expectSan: { value: names } }));
        assert.equal(resultOf(check, "expectSan").status, "pass", file);
        expected += names.length;
    }
    assert.ok(expected > 10, `${expected} names expected`);
});

// ---------------------------------------------------------------------------------------------
// The other rules

test("expectFingerprint compares the target's sha256 with the expected one, and expectKind passes only end-entity", () => {
    const sha256 = "ab".repeat(32);
    const same = run({ sha256 }, { expectFingerprint: { value: sha256 } });
    assert.deepEqual(statuses(same).slice(2), ["FINGERPRINT_MISMATCH pass"]);
    assert.equal(resultOf(same, "expectFingerprint").actual, sha256);
    assert.equal(resultOf(same, "expectFingerprint").expected, sha256);
    const other = run({ sha256 }, { expectFingerprint: { value: "cd".repeat(32) } });
    assert.deepEqual(statuses(other).slice(2), ["FINGERPRINT_MISMATCH fail"]);
    assert.equal(resultOf(other, "expectFingerprint").actual, sha256);
    assert.equal(resultOf(other, "expectFingerprint").expected, "cd".repeat(32));

    assert.deepEqual(statuses(run({ kind: "end-entity" }, { expectKind: { value: "end-entity" } })).slice(2), ["TARGET_NOT_END_ENTITY pass"]);
    for (const kind of ["ca", "something-new", ""]) {
        const found = resultOf(run({ kind }, { expectKind: { value: "end-entity" } }), "expectKind");
        assert.equal(found.status, "fail", kind);
        assert.equal(found.actual, kind);
        assert.equal(found.expected, "end-entity");
    }
    assert.equal(resultOf(run({ kind: "ca" }, { expectKind: { value: "end-entity" } }), "expectKind").message, "the target's kind is ca, not end-entity");
});

test("the rules are about the target of the observation, whichever certificate that is", () => {
    const observation = observed({});
    const other = structuredClone(observation.certificates[0]);
    other.index = 1;
    other.sha256 = "ee".repeat(32);
    other.kind = "ca";
    observation.certificates.push(other);
    const policy = policyOf({ expectFingerprint: { value: "ee".repeat(32) }, expectKind: { value: "end-entity" } });
    assert.deepEqual(statuses(evaluate(observation, policy)).slice(2), ["FINGERPRINT_MISMATCH fail", "TARGET_NOT_END_ENTITY pass"]);
    observation.target = 1;
    assert.deepEqual(statuses(evaluate(observation, policy)).slice(2), ["FINGERPRINT_MISMATCH pass", "TARGET_NOT_END_ENTITY fail"]);
});

// ---------------------------------------------------------------------------------------------
// Every rule against the README's table, over every fixture

/** Every observation the fixtures give, with each certificate in turn as the target. */
function fixtureTargets() {
    const found = [];
    for (const file of readdirSync(new URL("fixtures/", import.meta.url)).filter((name) => /\.(pem|der)$/.test(name)).sort()) {
        let observation;
        try {
            observation = inspect(fixture(file), { at: new Date(AT), source: { kind: "file", ref: file } });
        } catch (error) {
            // Two bundles have two possible targets, and the walks of the other tests skip them too.
            if (error instanceof AmbiguousTargetError) continue;
            throw error;
        }
        for (const certificate of observation.certificates) found.push({ file, observation: { ...observation, target: certificate.index }, certificate });
    }
    return found;
}

test("every rule passes or fails as the README's table says and puts in actual and expected what it says, for every certificate of every fixture at the ends of its validity and inside it", () => {
    let compared = 0;
    for (const { file, observation, certificate } of fixtureTargets()) {
        const start = Date.parse(certificate.notBefore) / 1000;
        const end = Date.parse(certificate.notAfter) / 1000;
        const instants = [start - 1, start, start + Math.floor((end - start) / 2), end, end + 1].map((seconds) => new Date(seconds * 1000).toISOString().replace(".000Z", "Z"));
        const names = [...certificate.san.dns, ...certificate.san.ip].filter((name) => policyProblems(policyOf({ expectSan: { value: [name] } })).length === 0);
        for (const [variant, severity] of /** @type {[string, string][]} */ ([["fail", "fail"], ["warn", "warn"]])) {
            const entries = {
                validityStarted: { severity },
                validityNotEnded: { severity },
                expiresWithin: { value: "30d", severity },
                maxLifetimeUsed: { value: 0.5, severity },
                expectEku: { value: ["serverAuth"], severity },
                ekuAllows: { value: ["clientAuth"], severity },
                rejectEku: { value: ["codeSigning", "1.3.6.1.5.5.7.3.1"], severity },
                expectSan: { value: [...names, variant === "fail" ? "missing.example.com" : "MISSING.example.com"], severity },
                expectFingerprint: { value: variant === "fail" ? certificate.sha256 : "0".repeat(64), severity },
                expectKind: { value: "end-entity", severity },
            };
            for (const now of instants) {
                const check = evaluate(observation, policyOf(entries), { now });
                assert.deepEqual(errorsOf(check), [], `${file} at ${now}`);
                assert.equal(check.results.length, 10);
                for (const result of check.results) {
                    const entry = /** @type {any} */ (check.policy)[result.rule.name];
                    const found = checked(result, entry, certificate, now);
                    assert.equal(result.status, found.holds ? "pass" : severity, `${file} ${result.code} at ${now}`);
                    assert.deepEqual(result.actual, found.actual, `${file} ${result.code} at ${now}: actual`);
                    assert.deepEqual(result.expected, found.expected, `${file} ${result.code} at ${now}: expected`);
                    compared += 1;
                }
            }
        }
    }
    assert.ok(compared > 2000, `${compared} results compared`);
});

test("every fixture certificate, as the target, evaluates against every policy in schema/examples/policy without matchesPrivateKey and against the empty policy, and nothing throws and every result validates", () => {
    const examples = new URL("../schema/examples/policy/", import.meta.url);
    /** @type {[string, any][]} */
    const policies = readdirSync(examples).filter((name) => name.endsWith(".json")).sort().map((name) => {
        const policy = JSON.parse(readFileSync(new URL(name, examples), "utf8"));
        delete policy.matchesPrivateKey;
        return [name, policy];
    });
    assert.ok(policies.some(([name]) => name === "every-rule.json") && policies.some(([name]) => name === "empty.json"));
    assert.ok(policies.every(([, policy]) => !("matchesPrivateKey" in policy)));
    policies.push(["the empty policy", policyOf()]);

    let evaluated = 0;
    for (const { file, observation, certificate } of fixtureTargets()) {
        for (const [name, policy] of policies) {
            for (const now of [undefined, certificate.notBefore, certificate.notAfter]) {
                /** @type {any} */
                let check;
                assert.doesNotThrow(() => {
                    check = evaluate(observation, policy, now === undefined ? {} : { now });
                }, `${file} ${name}`);
                assert.deepEqual(errorsOf(check), [], `${file} ${name} at ${now}`);
                const text = serializeCheckResult(check);
                assert.equal(serializeCheckResult(JSON.parse(text)), text, `${file} ${name}`);
                assert.deepEqual(errorsOf(JSON.parse(text)), [], `${file} ${name}`);
                evaluated += 1;
            }
        }
    }
    assert.ok(evaluated > 400, `${evaluated} evaluations`);
});

test("one observation evaluated with two values of now gets different verdicts for expiresWithin and for maxLifetimeUsed", () => {
    const fields = { notBefore: "2026-01-01T00:00:00Z", notAfter: "2026-04-11T00:00:00Z" };
    const entries = { expiresWithin: { value: "30d" }, maxLifetimeUsed: { value: 0.5 } };
    const observation = observed(fields);
    const early = evaluate(observation, policyOf(entries), { now: "2026-01-11T00:00:00Z" });
    const late = evaluate(observation, policyOf(entries), { now: "2026-03-22T00:00:00Z" });
    assert.deepEqual(statuses(early), ["NOT_YET_VALID pass", "EXPIRED pass", "EXPIRES_SOON pass", "LIFETIME_USED_EXCEEDED pass"]);
    assert.deepEqual(statuses(late), ["NOT_YET_VALID pass", "EXPIRED pass", "EXPIRES_SOON fail", "LIFETIME_USED_EXCEEDED fail"]);
    assert.equal(early.now, "2026-01-11T00:00:00Z");
    assert.equal(late.now, "2026-03-22T00:00:00Z");
    assert.equal(early.observation.observation.at, late.observation.observation.at, "the same observation");
    assert.equal(resultOf(early, "expiresWithin").actual, 90 * 86400);
    assert.equal(resultOf(late, "expiresWithin").actual, 20 * 86400);
    assert.equal(resultOf(early, "maxLifetimeUsed").actual, 0.1);
    assert.equal(resultOf(late, "maxLifetimeUsed").actual, 0.8);

    // The same at the two ends of a validity, for a certificate whose dates are the ones in the fixture.
    const real = inspect(fixture("leaf-p256.pem"), { at: new Date(AT) });
    const { notBefore, notAfter } = real.certificates[0];
    const rules = policyOf({ expiresWithin: { value: "1d" }, maxLifetimeUsed: { value: 0.5 } });
    assert.deepEqual(statuses(evaluate(real, rules, { now: notBefore })).slice(2), ["EXPIRES_SOON pass", "LIFETIME_USED_EXCEEDED pass"]);
    assert.deepEqual(statuses(evaluate(real, rules, { now: notAfter })).slice(2), ["EXPIRES_SOON fail", "LIFETIME_USED_EXCEEDED fail"]);
});
