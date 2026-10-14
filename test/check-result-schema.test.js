import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { validatorFor } from "./helpers/schema.js";
import { inspect, serializeCheckResult, serializeObservation, AmbiguousTargetError } from "../src/index.js";
import { ENTRIES, sanItem } from "../src/policy.js";
import { EXTENDED_KEY_USAGE_OIDS } from "../src/usage.js";

const examplesUrl = new URL("../schema/examples/check-result/", import.meta.url);
const schemaUrl = new URL("../schema/check-result.schema.json", import.meta.url);

/** @param {URL} url */
function readJson(url) {
    return JSON.parse(readFileSync(url, "utf8"));
}

const errorsOf = validatorFor("check-result");
const schema = readJson(schemaUrl);

/** @param {string} text @param {RegExp} pattern */
function says(text, pattern) {
    assert.match(text.replace(/\s+/g, " "), pattern);
}

/** @param {string} name */
const example = (name) => readJson(new URL(name, examplesUrl));

/** The code each entry of the policy produces, which is where a result's `rule` leads back to. */
const CODE_OF = /** @type {Record<string, string>} */ ({
    validityStarted: "NOT_YET_VALID",
    validityNotEnded: "EXPIRED",
    expiresWithin: "EXPIRES_SOON",
    maxLifetimeUsed: "LIFETIME_USED_EXCEEDED",
    expectEku: "EKU_MISSING",
    ekuAllows: "EKU_NOT_PERMITTED",
    rejectEku: "EKU_FORBIDDEN",
    expectSan: "SAN_MISSING",
    expectFingerprint: "FINGERPRINT_MISMATCH",
    expectKind: "TARGET_NOT_END_ENTITY",
    matchesPrivateKey: "KEY_MISMATCH",
});

const KNOWN_CODES = [...Object.values(CODE_OF), "KEY_UNREADABLE", "POLICY_EMPTY"].sort();

test("the check result schema compiles in strict mode and is draft 2020-12", () => {
    assert.equal(typeof errorsOf, "function");
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
    assert.match(schema.$id, /\/schema\/check-result\.schema\.json$/);
    assert.equal(schema.properties.contract.const, 1);
});

const exampleFiles = readdirSync(examplesUrl).filter((name) => name.endsWith(".json")).sort();

test("the check result examples cover a pass, a failure and a warning at another instant, an empty policy, an absent and an empty Extended Key Usage, an own rule and both key codes", () => {
    for (const name of ["pass.json", "fail-and-warn.json", "empty-policy.json", "eku-absent.json", "eku-empty.json", "own-rule.json", "key-mismatch.json", "key-unreadable.json"]) {
        assert.ok(exampleFiles.includes(name), `missing example ${name}`);
    }
});

for (const name of exampleFiles) {
    test(`check result example ${name} validates against the schema`, () => {
        assert.deepEqual(errorsOf(example(name)), []);
    });
}

/** @param {string} iso */
const seconds = (iso) => Date.parse(iso) / 1000;

/**
 * What a rule says about a certificate, from the dates, the usages and the names alone: what the
 * README's table says makes each code pass. The examples are checked against it so that they
 * cannot show a result the rules would not give.
 * @param {any} result
 * @param {any} entry The entry of the applied policy the result's rule names.
 * @param {any} target
 * @param {string} now
 */
function checked(result, entry, target, now) {
    const name = result.rule.name;
    const nowSeconds = seconds(now);
    const notBefore = seconds(target.notBefore);
    const notAfter = seconds(target.notAfter);
    const listed = (/** @type {string} */ usage) => target.eku?.includes(usage) ?? false;
    const wanted = (Array.isArray(entry.value) ? entry.value : []).map((/** @type {string} */ usage) => Object.entries(EXTENDED_KEY_USAGE_OIDS).find(([, oid]) => oid === usage)?.[0] ?? usage);
    switch (name) {
        case "validityStarted":
            return { holds: notBefore <= nowSeconds, actual: target.notBefore, expected: now };
        case "validityNotEnded":
            return { holds: notAfter >= nowSeconds, actual: target.notAfter, expected: now };
        case "expiresWithin": {
            const threshold = Number.parseInt(entry.value) * (entry.value.endsWith("d") ? 86400 : 3600);
            return { holds: notAfter - nowSeconds >= threshold, actual: notAfter - nowSeconds, expected: threshold };
        }
        case "maxLifetimeUsed":
            return {
                holds: nowSeconds - notBefore <= entry.value * (notAfter - notBefore),
                actual: notAfter > notBefore ? (nowSeconds - notBefore) / (notAfter - notBefore) : null,
                expected: entry.value,
            };
        case "expectEku":
            return { holds: target.eku !== null && wanted.every(listed), actual: target.eku, expected: wanted };
        case "ekuAllows":
            return { holds: target.eku === null || wanted.every(listed), actual: target.eku, expected: wanted };
        case "rejectEku":
            return { holds: target.eku === null || !wanted.some(listed), actual: target.eku, expected: wanted };
        case "expectSan": {
            const items = entry.value.map(sanItem);
            const expected = {
                dns: items.filter((/** @type {any} */ item) => item.kind === "dns").map((/** @type {any} */ item) => item.name).sort(),
                ip: items.filter((/** @type {any} */ item) => item.kind === "ip").map((/** @type {any} */ item) => item.name).sort(),
            };
            const holds = expected.dns.every((/** @type {string} */ dns) => target.san.dns.includes(dns)) && expected.ip.every((/** @type {string} */ ip) => target.san.ip.includes(ip));
            return { holds, actual: { dns: target.san.dns, ip: target.san.ip }, expected };
        }
        case "expectFingerprint":
            return { holds: target.sha256 === entry.value, actual: target.sha256, expected: entry.value };
        case "expectKind":
            return { holds: target.kind === "end-entity", actual: target.kind, expected: "end-entity" };
        default:
            throw new Error(`no oracle for ${name}`);
    }
}

for (const name of exampleFiles) {
    // JSON Schema cannot compare a list with the lists around it, nor a result with the
    // certificate it is about, so these rules are checked here to keep the examples honest.
    test(`check result example ${name} is consistent where the schema cannot tell`, () => {
        const document = example(name);
        const { results, summary, policy, observation } = document;

        const count = (/** @type {string} */ status) => results.filter((/** @type {any} */ result) => result.status === status).length;
        assert.deepEqual(summary, {
            status: count("fail") > 0 ? "fail" : count("warn") > 0 ? "warn" : "pass",
            pass: count("pass"),
            warn: count("warn"),
            fail: count("fail"),
        });

        const target = observation.certificates[observation.target];
        assert.ok(observation.target < observation.certificates.length, "target points outside certificates[]");

        // The entries come in the table's order, the two validity ones are always there, and
        // each result is where its entry puts it.
        const order = ENTRIES.map(([entry]) => entry);
        const applied = order.filter((entry) => entry in policy);
        assert.deepEqual(Object.keys(policy), ["contract", ...applied]);
        assert.ok("validityStarted" in policy && "validityNotEnded" in policy);
        const ruled = results.filter((/** @type {any} */ result) => result.rule !== null && order.includes(result.rule.name));
        assert.deepEqual(
            ruled.map((/** @type {any} */ result) => result.rule.name),
            applied,
            "one result per applied entry, in the order of the table",
        );

        for (const result of ruled) {
            const entry = policy[result.rule.name];
            assert.ok(["fail", "warn"].includes(entry.severity), `${result.rule.name} has no severity`);
            assert.deepEqual(result.rule, "value" in entry ? { name: result.rule.name, value: entry.value } : { name: result.rule.name }, "the rule is the entry's name and value as written");

            if (result.rule.name === "matchesPrivateKey") {
                if (result.code === "KEY_UNREADABLE") {
                    assert.notEqual(result.status, "pass");
                    assert.ok(!("actual" in result) && !("expected" in result), "an unreadable key shows nothing");
                } else {
                    assert.equal(result.code, "KEY_MISMATCH");
                    assert.equal(result.expected, target.spkiSha256);
                    assert.equal(result.status, result.actual === result.expected ? "pass" : entry.severity === "warn" ? "warn" : "fail");
                }
                continue;
            }
            const found = checked(result, entry, target, document.now);
            assert.equal(result.code, CODE_OF[result.rule.name]);
            assert.equal(result.status, found.holds ? "pass" : entry.severity === "warn" ? "warn" : "fail", `${result.code}: status`);
            assert.deepEqual(result.actual, found.actual, `${result.code}: actual`);
            assert.deepEqual(result.expected, found.expected, `${result.code}: expected`);
        }

        // A rule with severity warn never makes a check fail.
        for (const result of ruled) {
            if (policy[result.rule.name].severity === "warn") assert.notEqual(result.status, "fail", result.code);
        }

        // POLICY_EMPTY exists only when there is nothing else to apply.
        const empty = results.filter((/** @type {any} */ result) => result.code === "POLICY_EMPTY");
        const others = results.filter((/** @type {any} */ result) => result.code !== "POLICY_EMPTY" && !(result.rule && ["validityStarted", "validityNotEnded"].includes(result.rule.name)));
        assert.equal(empty.length, others.length === 0 ? 1 : 0);
        assert.equal(results.at(-1).code === "POLICY_EMPTY", empty.length === 1, "POLICY_EMPTY comes last");

        // No key material: a PEM armor line would be the first sign of it. The words are fine, a
        // message may say that no passphrase was given.
        assert.doesNotMatch(JSON.stringify(document), /-----BEGIN [A-Z ]*PRIVATE KEY-----/);
    });
}

test("now is the observation's at in every example except the one that evaluates at another instant", () => {
    const another = [];
    for (const name of exampleFiles) {
        const document = example(name);
        if (document.now !== document.observation.observation.at) another.push(name);
    }
    assert.deepEqual(another, ["fail-and-warn.json"]);
    const document = example("fail-and-warn.json");
    assert.equal(document.observation.observation.at, "2026-09-15T14:02:11Z", "the observation's at is unchanged");
    assert.equal(document.now, "2026-10-20T00:00:00Z");
});

test("the empty policy gives one warning besides the two validity results, and a warning is not a failure", () => {
    const document = example("empty-policy.json");
    assert.deepEqual(document.results.map((/** @type {any} */ result) => `${result.code} ${result.status}`), ["NOT_YET_VALID pass", "EXPIRED pass", "POLICY_EMPTY warn"]);
    assert.equal(document.results[2].rule, null);
    assert.equal(document.summary.status, "warn");
});

test("an absent Extended Key Usage and an empty one give different results: the first fails only expectEku, the second fails it and ekuAllows", () => {
    /** @param {string} name */
    const codes = (name) => example(name).results.filter((/** @type {any} */ result) => result.code.startsWith("EKU_")).map((/** @type {any} */ result) => `${result.code} ${result.status} ${JSON.stringify(result.actual)}`);
    assert.deepEqual(codes("eku-absent.json"), ["EKU_MISSING fail null", "EKU_NOT_PERMITTED pass null", "EKU_FORBIDDEN pass null"]);
    assert.deepEqual(codes("eku-empty.json"), ["EKU_MISSING fail []", "EKU_NOT_PERMITTED fail []", "EKU_FORBIDDEN pass []"]);
});

test("a result of an own rule has the same shape as any other, and own rules are code passed to the function, not entries of the policy", () => {
    const document = example("own-rule.json");
    const own = document.results.find((/** @type {any} */ result) => result.code === "ISSUER_NOT_ALLOWED");
    assert.deepEqual(Object.keys(own), ["code", "status", "rule", "message", "actual", "expected"]);
    assert.ok(!("issuerAllowed" in document.policy), "the own rule is not an entry of the policy");
    assert.deepEqual(errorsOf(document), []);
    says(schema.properties.results.description, /A result of an own rule has the same shape as any other/);
    says(schema.properties.results.description, /Own rules are code passed to the function that evaluates, not entries of the policy, so a policy stays a portable JSON document/);
    says(schema.$defs.result.properties.code.description, /A rule of the consumer's own chooses its own/);
});

// ---------------------------------------------------------------------------------------------
// The nested observation is the observation schema's, not a copy

test("the observation inside a result is validated by the observation schema's own definition", () => {
    assert.deepEqual(schema.properties.observation.$ref, "observation.schema.json");
    assert.deepEqual(Object.keys(schema.properties.observation).sort(), ["$ref", "description"]);
    assert.equal(schema.properties.now.$ref, "observation.schema.json#/$defs/timestamp");

    const document = example("pass.json");
    document.observation.contract = 2;
    assert.ok(errorsOf(document).some((error) => error.startsWith("/observation/contract ")));

    const broken = example("pass.json");
    delete broken.observation.certificates[0].sha256;
    assert.ok(errorsOf(broken).some((error) => error.startsWith("/observation/certificates/0 ") && error.includes("sha256")));

    const missing = example("pass.json");
    delete missing.observation;
    assert.ok(errorsOf(missing).some((error) => error.includes("observation")));
});

test("the check result schema defines no field of the observation itself", () => {
    const text = JSON.stringify(schema);
    for (const field of ["certificates", "spkiSha256", "lifetimeFraction", "issuedBy", "selfSigned"]) assert.ok(!text.includes(`"${field}"`), field);
});

test("the observation of every fixture, as inspect() builds it, nests in a check result that validates and serializes to the same bytes again", () => {
    const fixtures = new URL("fixtures/", import.meta.url);
    const at = new Date("2026-09-15T14:02:11Z");
    let nested = 0;
    for (const file of readdirSync(fixtures).filter((name) => /\.(pem|der)$/.test(name)).sort()) {
        let observation;
        try {
            observation = inspect(readFileSync(new URL(file, fixtures)), { at, source: { kind: "file", ref: file } });
        } catch (error) {
            if (error instanceof AmbiguousTargetError) continue;
            throw error;
        }
        const result = {
            contract: 1,
            now: observation.observation.at,
            summary: { status: "warn", pass: 0, warn: 1, fail: 0 },
            results: [{ code: "POLICY_EMPTY", status: "warn", rule: null, message: "m" }],
            policy: { contract: 1, validityStarted: { severity: "fail" }, validityNotEnded: { severity: "fail" } },
            observation,
        };
        assert.deepEqual(errorsOf(result), [], file);
        const text = serializeCheckResult(/** @type {any} */ (result));
        assert.equal(serializeCheckResult(JSON.parse(text)), text, file);
        assert.deepEqual(JSON.parse(text).observation, JSON.parse(serializeObservation(observation)), file);
        nested += 1;
    }
    assert.ok(nested > 30, `${nested} observations nested`);
});

// ---------------------------------------------------------------------------------------------
// What a result holds

/** A valid document to start each case from. */
const base = () => example("pass.json");

test("a result holds a code, a status, the rule with its parameter and a message, and actual and expected only where they apply", () => {
    assert.deepEqual(schema.$defs.result.required, ["code", "status", "rule", "message"]);
    for (const field of ["code", "status", "rule", "message"]) {
        const document = base();
        delete document.results[2][field];
        assert.ok(errorsOf(document).some((error) => error.startsWith("/results/2 ") && error.includes(field)), field);
    }
    // Absent, or present and null: both are valid, and null is a value.
    const document = base();
    delete document.results[0].actual;
    delete document.results[0].expected;
    document.results[1].actual = null;
    assert.deepEqual(errorsOf(document), []);
    assert.ok(errorsOf({ ...base(), results: [{ code: "X", status: "pass", rule: { name: "r" } }] }).some((error) => error.includes("message")));
});

test("a code is capital letters, digits and underscores starting with a letter, and every known code is one", () => {
    for (const code of [...KNOWN_CODES, "TLS13_REQUIRED", "A", "RULE_ERROR"]) {
        const document = base();
        document.results[0].code = code;
        assert.deepEqual(errorsOf(document).filter((error) => error.startsWith("/results/0/code")), [], code);
    }
    for (const code of ["", "eku_missing", "Eku", "1ABC", "_A", "A-B", "A B", "ÉKU", "A\n", "CÓDIGO"]) {
        const document = base();
        document.results[0].code = code;
        assert.ok(errorsOf(document).some((error) => error.startsWith("/results/0/code ")), JSON.stringify(code));
    }
    assert.deepEqual(
        schema.$defs.result.properties.code.description.match(/Known values: ([A-Z_, ]+)\./)?.[1].split(", ").sort(),
        KNOWN_CODES,
    );
});

test("the status is pass, fail or warn and nothing else, in a result and in the summary", () => {
    for (const status of ["error", "PASS", "", null, 1, "skipped"]) {
        const document = base();
        document.results[0].status = status;
        assert.ok(errorsOf(document).some((error) => error.startsWith("/results/0/status ")), `result ${JSON.stringify(status)}`);
        const summary = base();
        summary.summary.status = status;
        assert.ok(errorsOf(summary).some((error) => error.startsWith("/summary/status ")), `summary ${JSON.stringify(status)}`);
    }
    for (const status of ["pass", "fail", "warn"]) {
        const document = base();
        document.results[0].status = status;
        assert.deepEqual(errorsOf(document), [], status);
    }
});

test("the description of status says why it is closed: a consumer that does not know one cannot tell a pass from a failure", () => {
    const { description, enum: values } = schema.$defs.status;
    assert.deepEqual(values, ["pass", "fail", "warn"]);
    says(description, /Closed on purpose, unlike the open values of the observation/);
    says(description, /a consumer that does not know a status cannot tell a pass from a failure, so a new status needs a new contract number/);
});

test("a rule is an object with a name and any parameter, and is null only for POLICY_EMPTY", () => {
    for (const value of [undefined, 1, "a", [1, 2], { a: [] }, null, false]) {
        const document = base();
        document.results[0].rule = value === undefined ? { name: "own" } : { name: "own", value };
        assert.deepEqual(errorsOf(document), [], JSON.stringify(value));
    }
    for (const rule of [{}, { name: "" }, { name: 1 }, "expectEku", []]) {
        const document = base();
        document.results[0].rule = rule;
        assert.ok(errorsOf(document).some((error) => error.startsWith("/results/0/rule")), JSON.stringify(rule));
    }

    const nullRule = base();
    nullRule.results[0].rule = null;
    assert.ok(errorsOf(nullRule).some((error) => error.startsWith("/results/0")), "a null rule on another code");

    const empty = base();
    empty.results[0] = { code: "POLICY_EMPTY", status: "warn", rule: { name: "x" }, message: "m" };
    assert.ok(errorsOf(empty).some((error) => error.startsWith("/results/0")), "POLICY_EMPTY with a rule");
    empty.results[0] = { code: "POLICY_EMPTY", status: "fail", rule: null, message: "m" };
    assert.ok(errorsOf(empty).some((error) => error.startsWith("/results/0")), "POLICY_EMPTY that is not a warning");
    empty.results[0] = { code: "POLICY_EMPTY", status: "warn", rule: null, message: "m" };
    assert.deepEqual(errorsOf(empty), []);
});

test("the summary counts are non-negative integers and all four fields are required", () => {
    for (const field of ["status", "pass", "warn", "fail"]) {
        const document = base();
        delete document.summary[field];
        assert.ok(errorsOf(document).some((error) => error.includes(field)), field);
    }
    for (const count of [-1, 1.5, "1", null]) {
        const document = base();
        document.summary.warn = count;
        assert.ok(errorsOf(document).some((error) => error.startsWith("/summary/warn ")), JSON.stringify(count));
    }
});

test("severity is a fail or a warn, and the check result's policy writes it for every entry it holds, the two validity entries included", () => {
    const missing = base();
    delete missing.policy.validityStarted.severity;
    assert.ok(errorsOf(missing).some((error) => error.startsWith("/policy/validityStarted ") && error.includes("severity")));

    const absent = base();
    delete absent.policy.validityNotEnded;
    assert.ok(errorsOf(absent).some((error) => error.startsWith("/policy ") && error.includes("validityNotEnded")));

    for (const entry of ENTRIES.map(([name]) => name).filter((name) => name in base().policy)) {
        const document = base();
        delete document.policy[entry].severity;
        assert.ok(errorsOf(document).some((error) => error.startsWith(`/policy/${entry} `)), `${entry} without a severity`);
    }
    for (const [entry] of ENTRIES) {
        const document = base();
        document.policy[entry] = { ...(entry === "expiresWithin" ? { value: "1d" } : {}), severity: "loud" };
        assert.ok(errorsOf(document).some((error) => error.includes(`/policy/${entry}/severity`)), entry);
    }
    // The applied policy is still a policy: its values follow the policy schema.
    const bad = base();
    bad.policy.expiresWithin.value = "14";
    assert.ok(errorsOf(bad).some((error) => error.startsWith("/policy/expiresWithin/value ")));
});

test("unknown properties are tolerated in the check result, in a result and in the applied policy", () => {
    const document = base();
    document.tool = { name: "certdrift" };
    document.summary.skipped = 0;
    document.results[0].note = "extra";
    document.policy.futureRule = { value: 1, severity: "fail" };
    document.policy.matchesPrivateKey = { severity: "fail", passphrase: "x" };
    assert.deepEqual(errorsOf(document), []);
});

test("a different contract version, a missing field and a now with a fraction fail validation", () => {
    for (const contract of [2, "1", undefined]) {
        const document = base();
        document.contract = contract;
        assert.ok(errorsOf(document).some((error) => error.startsWith("/contract ") || error.includes("contract")), String(contract));
    }
    for (const field of schema.required) {
        const document = base();
        delete document[field];
        assert.ok(errorsOf(document).some((error) => error.includes(field)), field);
    }
    for (const now of ["2026-09-15T14:02:11.500Z", "2026-09-15", "now", 0, null]) {
        const document = base();
        document.now = now;
        assert.ok(errorsOf(document).some((error) => error.startsWith("/now ")), JSON.stringify(now));
    }
});

// ---------------------------------------------------------------------------------------------
// What the descriptions say

test("the time rules are defined on the original dates and now, never on derived, and now is the observation's at unless another instant was asked for", () => {
    says(schema.properties.now.description, /It is the observation's at unless another instant was asked for; the observation's at is never changed/);
    says(schema.properties.now.description, /defined on the certificate's original notBefore and notAfter and this instant, never on the rounded values in derived/);
});

test("the descriptions say a rule with severity warn never makes a check fail, how the verdict is reached and in what order the results come", () => {
    says(schema.properties.summary.description, /A rule with severity warn never makes a check fail/);
    says(schema.properties.summary.description, /status is fail when any result has status fail, otherwise warn when any has status warn, otherwise pass/);
    const { description } = schema.properties.results;
    says(description, /validityStarted, validityNotEnded, expiresWithin, maxLifetimeUsed, expectEku, ekuAllows, rejectEku, expectSan, expectFingerprint, expectKind, matchesPrivateKey/);
    says(description, /then POLICY_EMPTY, which exists only when there is nothing else to apply/);
    assert.deepEqual(
        description.match(/validityStarted, [A-Za-z, ]+matchesPrivateKey/)?.[0].split(", "),
        ENTRIES.map(([entry]) => entry),
    );
});

test("nothing a result carries is a private key, a passphrase or anything read from them, and the applied policy repeats only what this version knows", () => {
    for (const field of ["message", "actual", "expected"]) {
        says(schema.$defs.result.properties[field].description, /never holds a private key, a passphrase or anything read from them/);
    }
    says(schema.properties.policy.description, /A property of the policy this version does not know is not repeated here/);
    says(schema.properties.policy.description, /each with its severity written out, the two validity entries included/);
});

test("the contract of the check result is its own, and the description says what needs a new number", () => {
    says(schema.properties.contract.description, /independent of the observation's own contract number and of the policy's/);
    says(schema.properties.contract.description, /changing what a code means, requires 2/);
});

// ---------------------------------------------------------------------------------------------
// The README

const readmeText = readFileSync(new URL("../README.md", import.meta.url), "utf8");

/** The rows of every table of the README that starts with this header, as lists of cells. */
function table(/** @type {string} */ header) {
    const lines = readmeText.split("\n");
    /** @type {string[][]} */
    const rows = [];
    let found = 0;
    lines.forEach((line, start) => {
        if (!line.startsWith(header)) return;
        found += 1;
        for (const row of lines.slice(start + 2)) {
            if (!row.startsWith("|")) break;
            rows.push(row.split(/(?<!\\)\|/).slice(1, -1).map((cell) => cell.trim()));
        }
    });
    assert.ok(found > 0, `the README has no table that starts with ${header}`);
    return rows;
}

test("the README defines every reason code in a table with what makes it pass and what makes it fail", () => {
    const rows = table("| Code | Entry | Passes when | Fails when |");
    assert.deepEqual(rows.map((row) => row[0].replaceAll("`", "")).sort(), KNOWN_CODES);
    for (const row of rows) {
        assert.equal(row.length, 5, row[0]);
        for (const cell of row) assert.notEqual(cell, "", `${row[0]} has an empty cell`);
    }
    // The table names, for each code, the entry that produces it.
    for (const [entry, code] of Object.entries(CODE_OF)) {
        const row = rows.find((found) => found[0] === `\`${code}\``);
        assert.equal(row?.[1], `\`${entry}\``, code);
    }
    assert.equal(rows.find((row) => row[0] === "`KEY_UNREADABLE`")?.[1], "`matchesPrivateKey`");
});

test("the README table agrees with the schema about the codes, and with the policy table about the entries", () => {
    const codes = schema.$defs.result.properties.code.description.match(/Known values: ([A-Z_, ]+)\./)?.[1].split(", ").sort();
    assert.deepEqual(table("| Code | Entry | Passes when | Fails when |").map((row) => row[0].replaceAll("`", "")).sort(), codes);
    const entries = table("| Entry | Parameter | Produces |");
    assert.deepEqual(entries.map((row) => row[0].replaceAll("`", "")), ENTRIES.map(([entry]) => entry));
    for (const row of entries) {
        for (const code of row[2].replaceAll("`", "").split(", ")) assert.ok(KNOWN_CODES.includes(code), `${row[0]} produces ${code}`);
    }
});

test("the README documents the shape of a result: its fields, the statuses, how the verdict is reached and what a rule of your own gives", () => {
    const fields = table("| Field | What it holds |").map((row) => row[0]);
    for (const field of ["`contract`", "`now`", "`summary`", "`results`", "`policy`", "`observation`", "`code`", "`status`", "`rule`", "`message`", "`actual`, `expected`"]) {
        assert.ok(fields.includes(field), `the README does not describe ${field}`);
    }
    const text = readmeText.replace(/\s+/g, " ").replaceAll("`", "");
    assert.match(text, /A rule that does not hold gives fail, or warn when its severity is warn/);
    assert.match(text, /A result of a rule of your own has the same shape/);
    assert.match(text, /a consumer that does not know a status cannot tell a pass from a failure, so a new one needs a new contract number/);
    assert.match(text, /null is a value: eku is null when the extension is absent/);
    assert.match(text, /An instant equal to notAfter or to notBefore is still valid/i);
    assert.match(text, /Codes are versioned with the contract: adding a code is additive, and changing what a code means requires a new contract number/);
});

test("the README says the policy never carries a key, a passphrase or anything read from them, and that a function is not an entry", () => {
    const text = readmeText.replace(/\s+/g, " ").replaceAll("`", "");
    assert.match(text, /It never carries a private key, a passphrase or anything read from them/);
    assert.match(text, /a property put in a policy anyway is tolerated like any property the contract does not know and is never repeated in a result/);
    assert.match(text, /A rule of your own is code passed to the function that evaluates, not an entry of the policy, so a policy holds no function/);
    assert.match(text, /A policy with no entry besides the two validity ones is valid, and evaluating it produces a POLICY_EMPTY warning/);
});

test("the README says an absent Extended Key Usage and an empty one are different, and that a CA read as end-entity passes TARGET_NOT_END_ENTITY", () => {
    const text = readmeText.replace(/\s+/g, " ").replaceAll("`", "");
    assert.match(text, /eku is null when the extension is absent, which means Extended Key Usage does not restrict the purpose/);
    assert.match(text, /An extension that is present and lists nothing \(\[\]\) permits nothing, so both fail on it, each with its own code, and rejectEku passes on it/);
    assert.match(text, /A CA that carries a known extension twice, or one that does not decode, reads as end-entity, so TARGET_NOT_END_ENTITY passes for it/);
});
