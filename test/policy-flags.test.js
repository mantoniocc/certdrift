import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluate, inspect, policyProblems } from "../src/index.js";
import {
    ALWAYS_ENTRIES,
    FLAGS,
    conflicts,
    entriesOf,
    flagProblems,
    fingerprintOf,
    fractionOf,
    inactiveCodes,
    mergePolicy,
    percentProblem,
    problemCount,
    problemLines,
    warnTargets,
} from "../bin/policy-flags.js";
import { CHECK_OPTIONS } from "../bin/check.js";
import { fixture } from "./helpers/command.js";

// The code that turns the requirement flags into a policy and back into messages. It decides
// nothing about a certificate: `policyProblems` says whether a value is acceptable, so these tests
// only show what the typed text becomes and which flag a problem is reported under.

test("every requirement flag is an option of check, and one that can be repeated is a list in the options", () => {
    for (const { flag } of FLAGS) assert.deepEqual(CHECK_OPTIONS[/** @type {keyof typeof CHECK_OPTIONS} */ (flag)], { type: "string", multiple: true }, flag);
    assert.equal(new Set(FLAGS.map(({ entry }) => entry)).size, FLAGS.length, "each flag builds its own entry");
});

test("--lifetime-used 66.3% is Number(\"0.663\"), which 66.3 / 100 is not", () => {
    assert.equal(fractionOf("66.3%"), Number("0.663"));
    assert.notEqual(66.3 / 100, Number("0.663"));
    assert.equal(fractionOf("57%"), Number("0.57"));
    assert.equal(fractionOf("66%"), 0.66);
    assert.equal(entriesOf({ "lifetime-used": ["66.3%"] }).maxLifetimeUsed.value, Number("0.663"));
});

test("--lifetime-used builds its number from the digits for every percentage from 0.00 to 100.00, where dividing is wrong for some", () => {
    let divided = 0;
    for (let hundredths = 0; hundredths <= 10_000; hundredths++) {
        const text = `${Math.floor(hundredths / 100)}.${String(hundredths % 100).padStart(2, "0")}%`;
        assert.equal(fractionOf(text), Number(`${hundredths}e-4`), text);
        if (Number.parseFloat(text) / 100 !== Number(`${hundredths}e-4`)) divided += 1;
    }
    // The reason the number is not made by dividing.
    assert.ok(divided > 0, "dividing by a hundred gives a different number for some percentages");
});

test("a percentage is read with leading zeros, trailing zeros, a short fraction and a very small value", () => {
    /** @type {[string, number][]} */
    const cases = [["066%", 0.66], ["66.30%", 0.663], ["0%", 0], ["100%", 1], ["100.0%", 1], ["7%", 0.07], ["5%", 0.05], ["0.5%", 0.005], ["0.00001%", 1e-7], ["150%", 1.5], ["100.5%", 1.005]];
    for (const [text, value] of cases) assert.equal(fractionOf(text), value, text);
});

test("what is not a percentage is refused by its form, and given back unchanged for the policy to refuse", () => {
    for (const text of ["66", "%", ".5%", "5.%", "1e2%", "-5%", "+5%", "٣%", "٣.٥%", " 5%", "5% ", "5 %", "5,5%", "0x10%", "", "66.3.1%", "5%%"]) {
        assert.equal(percentProblem(text), "needs a percentage such as 66% or 66.3%", JSON.stringify(text));
        assert.equal(fractionOf(text), text);
    }
    for (const text of ["0%", "66%", "66.3%", "100%", "150%"]) assert.equal(percentProblem(text), null, text);
});

test("--expect-fingerprint accepts upper case and pairs separated by colons, and gives the 64 lower case characters of the policy", () => {
    const sha256 = inspect(fixture("leaf-p256.pem")).certificates[0].sha256;
    const pairs = sha256.toUpperCase().match(/../g) ?? [];
    for (const typed of [sha256, sha256.toUpperCase(), pairs.join(":"), pairs.join(":").toLowerCase(), `${sha256.slice(0, 32)}${sha256.slice(32).toUpperCase()}`]) {
        assert.equal(fingerprintOf(typed), sha256, typed);
        assert.deepEqual(policyProblems({ contract: 1, expectFingerprint: { value: fingerprintOf(typed) } }), [], typed);
    }
});

test("--expect-fingerprint takes a colon out only between pairs, and anything else reaches the policy to be refused", () => {
    const sha256 = "ab".repeat(32);
    /** @type {string[]} */
    const bad = [`${sha256}:`, `:${sha256}`, "ab::cd", "a:bc", "ab:cd", `${sha256.slice(0, 62)}:ab:ab`.replace("ab:ab", "ab:a"), `${sha256}${sha256}`, "xx".repeat(32), sha256.slice(1), ""];
    for (const typed of bad) {
        assert.notEqual(policyProblems({ contract: 1, expectFingerprint: { value: fingerprintOf(typed) } }).length, 0, JSON.stringify(typed));
    }
    // A colon is not taken out of text that only starts like a fingerprint: it reaches the policy as typed.
    assert.equal(fingerprintOf("AB:CD:zz"), "ab:cd:zz");
    assert.equal(fingerprintOf("AB:CD:"), "ab:cd:");
    assert.equal(fingerprintOf("AB:CD:E"), "ab:cd:e");
    // Only the letters A to F are lowered: a letter that is not hexadecimal stays, and is refused.
    assert.equal(fingerprintOf("K"), "K");
    assert.equal(fingerprintOf("ABCDEFabcdef0123"), "abcdefabcdef0123");
});

test("a flag that was not given builds nothing, and a list flag builds a list that is a copy", () => {
    assert.deepEqual(entriesOf({}), {});
    const given = ["serverAuth", "1.3.6.1.5.5.7.3.2"];
    const entries = entriesOf({ "expect-eku": given, "expires-within": ["30d"] });
    assert.deepEqual(entries, { expectEku: { value: ["serverAuth", "1.3.6.1.5.5.7.3.2"] }, expiresWithin: { value: "30d" } });
    assert.notEqual(entries.expectEku.value, given);
});

test("a problem is reported under the flag that built the entry, never under a path in a policy", () => {
    /** @type {[string, string[]][]} */
    const cases = [
        ["expect-eku", ["bogus"]],
        ["eku-allows", [""]],
        ["reject-eku", ["1"]],
        ["expect-san", ["not a name"]],
        ["expect-fingerprint", ["abc"]],
        ["expires-within", ["30"]],
        ["lifetime-used", ["150%"]],
    ];
    for (const [flag, values] of cases) {
        const problems = flagProblems({ [flag]: values });
        assert.equal(problems.length, 1, flag);
        assert.ok(problems[0].startsWith(`--${flag}: `), problems[0]);
        assert.doesNotMatch(problems[0], /\/expect|\/eku|\/reject|\/max|\/value/, "no path of a policy");
    }
    assert.deepEqual(flagProblems({ "expect-eku": ["serverAuth"], "expires-within": ["30d"] }), []);
});

test("a bad value of a list flag is named as it was typed, escaped, and the good ones around it are not", () => {
    const problems = flagProblems({ "expect-san": ["a.example", "bad name", "b.example", `x\u001b[31m`, "c.example"] });
    assert.deepEqual(problems, [
        '--expect-san: "bad name" is not a value this flag accepts',
        '--expect-san: "x\\u001b[31m" is not a value this flag accepts',
    ]);
    // Only the bad second value of a repeated flag.
    assert.deepEqual(flagProblems({ "expect-san": ["a.example", "second one"] }), ['--expect-san: "second one" is not a value this flag accepts']);
});

test("the problems of several flags are all listed, in the order of the policy's entries, which is the same whatever order the flags were typed in", () => {
    const one = flagProblems({ "lifetime-used": ["150%"], "expires-within": ["x"], "expect-eku": ["bogus"] });
    const other = flagProblems({ "expect-eku": ["bogus"], "expires-within": ["x"], "lifetime-used": ["150%"] });
    assert.deepEqual(one.map((problem) => problem.split(":")[0]), ["--expires-within", "--lifetime-used", "--expect-eku"]);
    assert.deepEqual(one, other);
});

test("--warn-only finds the entry of a code through the library and keeps no table: a code with no entry is unknown", () => {
    const { entries, unknown } = warnTargets(["EXPIRED", "EKU_MISSING", "KEY_MISMATCH", "POLICY_EMPTY", "RULE_ERROR", "expired", "", "__proto__", "constructor", "NOPE"]);
    assert.deepEqual([...entries], [["EXPIRED", "validityNotEnded"], ["EKU_MISSING", "expectEku"], ["KEY_MISMATCH", "matchesPrivateKey"]]);
    assert.deepEqual(unknown, ["POLICY_EMPTY", "RULE_ERROR", "expired", "", "__proto__", "constructor", "NOPE"]);
});

test("the entries every run has are the ones evaluate always runs", () => {
    const observation = inspect(fixture("leaf-p256.pem"));
    const names = evaluate(observation, { contract: 1 }).results.flatMap((result) => (result.rule === null ? [] : [result.rule.name]));
    assert.deepEqual(names, ALWAYS_ENTRIES);
});

test("a code is active when its entry is one of the two validity entries or is in the run, and says what would put it there", () => {
    const { entries } = warnTargets(["EXPIRED", "NOT_YET_VALID", "EKU_MISSING", "SAN_MISSING", "KEY_MISMATCH"]);
    assert.deepEqual(inactiveCodes(entries, []), [
        "--warn-only: EKU_MISSING belongs to expectEku, which this run does not check: give --expect-eku or list expectEku in the policy",
        "--warn-only: SAN_MISSING belongs to expectSan, which this run does not check: give --expect-san or list expectSan in the policy",
        "--warn-only: KEY_MISMATCH belongs to matchesPrivateKey, which this run does not check: list matchesPrivateKey in the policy",
    ]);
    assert.deepEqual(inactiveCodes(entries, ["expectEku", "expectSan", "matchesPrivateKey"]), []);
});

test("a flag that gives an entry the file has is a conflict, whatever the values", () => {
    const entries = entriesOf({ "expect-eku": ["serverAuth"], "expires-within": ["30d"], "lifetime-used": ["50%"] });
    assert.deepEqual(conflicts({ contract: 1 }, entries), []);
    assert.deepEqual(conflicts({ contract: 1, expectEku: { value: ["serverAuth"] }, maxLifetimeUsed: { value: 0.5 } }, entries).map((line) => line.split(" gives ")[0]), ["--expect-eku", "--lifetime-used"]);
    // An entry the file has and no flag gives, and a flag that is not given, are not conflicts.
    assert.deepEqual(conflicts({ contract: 1, expectKind: { value: "end-entity" }, rejectEku: { value: ["codeSigning"] } }, entries), []);
    assert.match(conflicts({ contract: 1, expectEku: {} }, entries)[0], /use --warn-only to soften a rule of the file/);
});

test("the policy of a file and of the flags together changes neither, and --warn-only sets the severity of an entry, creating a validity entry that is missing", () => {
    const file = Object.freeze({ contract: 1, expectKind: Object.freeze({ value: "end-entity", severity: "fail" }) });
    const entries = Object.freeze({ expectEku: Object.freeze({ value: Object.freeze(["serverAuth"]) }) });
    const policy = mergePolicy(file, entries, ["expectKind", "expectEku", "validityNotEnded"]);
    assert.deepEqual(policy, {
        contract: 1,
        expectKind: { value: "end-entity", severity: "warn" },
        expectEku: { value: ["serverAuth"], severity: "warn" },
        validityNotEnded: { severity: "warn" },
    });
    assert.deepEqual(file, { contract: 1, expectKind: { value: "end-entity", severity: "fail" } });
    assert.deepEqual(mergePolicy(file, {}, []), file);
});

test("an entry the flags give wins over the same entry of the file, which the command never lets happen: it refuses the pair first", () => {
    const policy = mergePolicy({ contract: 1, expectEku: { value: ["clientAuth"] } }, entriesOf({ "expect-eku": ["serverAuth"] }), []);
    assert.deepEqual(policy.expectEku, { value: ["serverAuth"] });
});

test("a __proto__ key of a policy file stays an own property of the merged policy and never becomes its prototype", () => {
    const file = JSON.parse('{"contract":1,"__proto__":{"expectKind":{"value":"end-entity"}}}');
    const policy = mergePolicy(file, entriesOf({ "expires-within": ["30d"] }), ["validityNotEnded"]);
    assert.equal(Object.getPrototypeOf(policy), Object.prototype);
    assert.equal(Object.hasOwn(policy, "expectKind"), false);
    assert.equal(Object.hasOwn(policy, "__proto__"), true);
    assert.deepEqual(policyProblems(policy), []);
});

test("the problems of a policy file are lines with their path, and the count is said in the words of PolicyError", () => {
    const problems = [{ path: "/expectEku/value", message: "must be a list" }, { path: "", message: "the policy must be a JSON object" }];
    assert.deepEqual(problemLines(problems), ["/expectEku/value: must be a list", "(the policy): the policy must be a JSON object"]);
    assert.equal(problemCount(problems), "the policy is not valid: 2 problems");
    assert.equal(problemCount([problems[0]]), "the policy is not valid: 1 problem");
});
