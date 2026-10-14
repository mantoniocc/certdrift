import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { validatorFor } from "./helpers/schema.js";
import { ENTRIES } from "../src/policy.js";

const examplesUrl = new URL("../schema/examples/policy/", import.meta.url);
const schemaUrl = new URL("../schema/", import.meta.url);

/** @param {URL} url */
function readJson(url) {
    return JSON.parse(readFileSync(url, "utf8"));
}

const errorsOf = validatorFor("policy");
const schema = readJson(new URL("policy.schema.json", schemaUrl));

/** The error messages of a document, for a test that asks which property was refused. */
const refusedAt = (/** @type {string} */ path, /** @type {unknown} */ document) =>
    errorsOf(document).some((error) => error.startsWith(`${path} `));

/** @param {string} text @param {RegExp} pattern */
function says(text, pattern) {
    assert.match(text.replace(/\s+/g, " "), pattern);
}

test("the policy schema compiles in strict mode and is draft 2020-12", () => {
    assert.equal(typeof errorsOf, "function");
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
    assert.match(schema.$id, /\/schema\/policy\.schema\.json$/);
});

const exampleFiles = readdirSync(examplesUrl).filter((name) => name.endsWith(".json")).sort();

test("the policy examples exist: an empty policy, a server policy, one with every rule and a pinned one", () => {
    for (const name of ["empty.json", "server.json", "every-rule.json", "pinned.json"]) {
        assert.ok(exampleFiles.includes(name), `missing example ${name}`);
    }
});

for (const name of exampleFiles) {
    test(`policy example ${name} validates against the schema`, () => {
        assert.deepEqual(errorsOf(readJson(new URL(name, examplesUrl))), []);
    });

    // The order is the one the entries have in the README, the schema and the check result's
    // echo of the policy, so a reader sees the same order everywhere.
    test(`policy example ${name} lists its entries in the order of the table, value before severity`, () => {
        const policy = readJson(new URL(name, examplesUrl));
        const order = ["contract", ...ENTRIES.map(([entry]) => entry)];
        const keys = Object.keys(policy);
        assert.deepEqual(keys, order.filter((entry) => keys.includes(entry)));
        for (const entry of keys.slice(1)) {
            assert.deepEqual(Object.keys(policy[entry]), ["value", "severity"].filter((key) => key in policy[entry]), entry);
        }
        assert.equal(readFileSync(new URL(name, examplesUrl), "utf8"), `${JSON.stringify(policy, null, 2)}\n`);
    });
}

test("the example with every rule has an entry for each kind of rule the schema describes", () => {
    const every = readJson(new URL("every-rule.json", examplesUrl));
    assert.deepEqual(Object.keys(every), ["contract", ...ENTRIES.map(([entry]) => entry)]);
    assert.deepEqual(Object.keys(schema.properties), ["contract", ...ENTRIES.map(([entry]) => entry)]);
});

test("the schema rejects an unknown severity, a duration with no unit and a lifetime fraction outside 0 to 1", () => {
    assert.ok(refusedAt("/expectKind/severity", { contract: 1, expectKind: { value: "end-entity", severity: "error" } }));
    assert.ok(refusedAt("/validityNotEnded/severity", { contract: 1, validityNotEnded: { severity: "info" } }));
    assert.ok(refusedAt("/expiresWithin/value", { contract: 1, expiresWithin: { value: "30" } }));
    assert.ok(refusedAt("/expiresWithin/value", { contract: 1, expiresWithin: { value: 30 } }));
    assert.ok(refusedAt("/maxLifetimeUsed/value", { contract: 1, maxLifetimeUsed: { value: 1.01 } }));
    assert.ok(refusedAt("/maxLifetimeUsed/value", { contract: 1, maxLifetimeUsed: { value: -0.01 } }));
    assert.ok(refusedAt("/maxLifetimeUsed/value", { contract: 1, maxLifetimeUsed: { value: "0.5" } }));
});

test("a lifetime fraction of 0 and of 1 are valid, and so are both severities", () => {
    for (const value of [0, 0.66, 1]) assert.deepEqual(errorsOf({ contract: 1, maxLifetimeUsed: { value } }), [], String(value));
    for (const severity of ["fail", "warn"]) assert.deepEqual(errorsOf({ contract: 1, expectKind: { value: "end-entity", severity } }), [], severity);
});

test("a duration is whole days or hours with the unit written, at most six digits and no leading zero", () => {
    for (const value of ["1d", "30d", "72h", "999999d", "1h"]) assert.deepEqual(errorsOf({ contract: 1, expiresWithin: { value } }), [], value);
    for (const value of ["", "d", "0d", "030d", "30", "30D", "30 d", "30d ", "30d\n", "1.5d", "-1d", "30m", "30days", "1000000d", "٣٠d"]) {
        assert.ok(refusedAt("/expiresWithin/value", { contract: 1, expiresWithin: { value } }), JSON.stringify(value));
    }
});

test("an Extended Key Usage is one of the six names or an OID, and the list needs at least one", () => {
    for (const rule of ["expectEku", "ekuAllows", "rejectEku"]) {
        for (const usage of ["serverAuth", "clientAuth", "codeSigning", "emailProtection", "timeStamping", "OCSPSigning", "1.3.6.1.5.5.7.3.1", "2.5.29.37.0", "0.0"]) {
            assert.deepEqual(errorsOf({ contract: 1, [rule]: { value: [usage] } }), [], `${rule} ${usage}`);
        }
        for (const usage of ["", "ServerAuth", "serverauth", "server", "1", "3.1", "1.2.", ".1.2", "1.02", "1.2.x", "1..2"]) {
            assert.ok(refusedAt(`/${rule}/value/0`, { contract: 1, [rule]: { value: [usage] } }), `${rule} ${JSON.stringify(usage)}`);
        }
        assert.ok(refusedAt(`/${rule}/value`, { contract: 1, [rule]: { value: [] } }), `${rule} with no usage`);
        assert.ok(refusedAt(`/${rule}/value`, { contract: 1, [rule]: { value: "serverAuth" } }), `${rule} with a bare string`);
        assert.ok(refusedAt(`/${rule}`, { contract: 1, [rule]: { severity: "warn" } }), `${rule} with no value`);
    }
});

test("a fingerprint is the observation's: 64 lowercase hexadecimal characters, nothing else", () => {
    assert.deepEqual(errorsOf({ contract: 1, expectFingerprint: { value: "ab".repeat(32) } }), []);
    for (const value of ["AB".repeat(32), "ab".repeat(31), "ab".repeat(33), `${"ab:".repeat(31)}ab`, "sha256:" + "ab".repeat(32), ""]) {
        assert.ok(refusedAt("/expectFingerprint/value", { contract: 1, expectFingerprint: { value } }), JSON.stringify(value));
    }
});

test("expectKind accepts end-entity and nothing else", () => {
    assert.deepEqual(errorsOf({ contract: 1, expectKind: { value: "end-entity" } }), []);
    for (const value of ["ca", "End-Entity", "", null]) assert.ok(refusedAt("/expectKind/value", { contract: 1, expectKind: { value } }), JSON.stringify(value));
});

test("an entry that is not an object is refused", () => {
    for (const [entry] of ENTRIES) {
        for (const value of [null, "fail", 1, [], true]) assert.ok(refusedAt(`/${entry}`, { contract: 1, [entry]: value }), `${entry} ${JSON.stringify(value)}`);
    }
});

test("a policy with no entries is valid, and the schema says evaluating it produces a warning", () => {
    assert.deepEqual(errorsOf({ contract: 1 }), []);
    says(schema.description, /A policy with no entry besides validityStarted and validityNotEnded/);
    says(schema.description, /is valid, and evaluating it.*produces an explicit warning \(POLICY_EMPTY\)/);
    says(schema.description, /a policy that checks nothing is a false 'correct' under another name/);
});

test("the policy carries a contract number, which must be 1, and the schema says an unknown number is misuse and why it is carried", () => {
    assert.deepEqual(schema.required, ["contract"]);
    assert.equal(schema.properties.contract.const, 1);
    assert.deepEqual(errorsOf({}), ["/ must have required property 'contract'"]);
    for (const contract of [2, 0, "1", 1.5, null, true, [1]]) assert.ok(refusedAt("/contract", { contract }), JSON.stringify(contract));
    const { description } = schema.properties.contract;
    says(description, /A policy whose number the tool does not know is misuse, not a failed check/);
    says(description, /must not apply it as if it did/);
});

test("the time rules are defined on the original notBefore and notAfter and an instant now, never on derived, and now defaults to the observation's at", () => {
    says(schema.description, /defined on the certificate's original notBefore and notAfter and an instant now, never on the rounded values in derived/);
    says(schema.description, /now defaults to the observation's at/);
    says(schema.properties.expiresWithin.description, /time left until notAfter, in seconds/);
    says(schema.properties.maxLifetimeUsed.description, /\(now - notBefore\) \/ \(notAfter - notBefore\) on the original dates/);
    says(schema.properties.maxLifetimeUsed.description, /without the division/);
    says(schema.properties.validityNotEnded.description, /an instant equal to notAfter is still valid/);
    says(schema.properties.validityStarted.description, /an instant equal to notBefore is still valid/);
});

test("the two Extended Key Usage rules and the one that rejects a usage treat an absent extension and an empty one as different cases", () => {
    const { expectEku, ekuAllows, rejectEku } = schema.properties;
    says(expectEku.description, /\(eku is null\) fails, and so does one whose extension lists nothing \(eku is \[\]\)/);
    says(ekuAllows.description, /\(eku is null\) passes, because an absent extension restricts nothing/);
    says(ekuAllows.description, /\(eku is \[\]\) fails, because an extension that is present and empty permits nothing/);
    says(rejectEku.description, /Both null and \[\] pass/);
    assert.match(expectEku.description, /EKU_MISSING/);
    assert.match(ekuAllows.description, /EKU_NOT_PERMITTED/);
    assert.match(rejectEku.description, /EKU_FORBIDDEN/);
});

test("a rule of the consumer's own is code passed to the function that evaluates, never an entry, so the policy is a portable JSON document", () => {
    says(schema.description, /A policy is a portable document that people share and commit: it holds data only, so it cannot hold a function/);
    says(schema.description, /a rule of a consumer's own is code passed to the function that evaluates, never an entry of the policy/);
});

test("the policy never carries a key, a passphrase or anything read from them, and an entry with such a property tolerates it", () => {
    says(schema.description, /never carries a private key, a passphrase or anything read from them/);
    says(schema.properties.matchesPrivateKey.description, /a policy never carries a private key, a passphrase or anything read from them/);
    assert.equal(schema.properties.matchesPrivateKey.required, undefined, "the entry has no value to require");
    for (const extra of [{ key: "-----BEGIN PRIVATE KEY-----" }, { passphrase: "secret" }, { path: "/etc/key.pem" }]) {
        assert.deepEqual(errorsOf({ contract: 1, matchesPrivateKey: { severity: "warn", ...extra } }), [], Object.keys(extra)[0]);
    }
});

test("unknown properties and unknown entries are tolerated, and no schema of the project closes an object", () => {
    assert.deepEqual(errorsOf({ contract: 1, futureRule: { value: 1 }, note: "x", expectKind: { value: "end-entity", severity: "warn", note: "y" } }), []);

    /** @param {unknown} node @returns {string[]} */
    const closers = (node, path = "") => {
        if (typeof node !== "object" || node === null) return [];
        return Object.entries(node).flatMap(([key, value]) => [
            ...(key === "additionalProperties" && value === false ? [path] : []),
            ...closers(value, `${path}/${key}`),
        ]);
    };
    const files = readdirSync(schemaUrl).filter((name) => name.endsWith(".schema.json"));
    assert.ok(files.length >= 3, files.join(", "));
    for (const file of files) assert.deepEqual(closers(readJson(new URL(file, schemaUrl))), [], file);
});

test("severity is fail by default, and a rule with severity warn never makes a check fail", () => {
    const { description } = schema.$defs.severity;
    says(description, /fail, the default, makes the check fail when the rule does not hold/);
    says(description, /warn reports the rule with status warn and never makes a check fail/);
    assert.deepEqual(schema.$defs.severity.enum, ["fail", "warn"]);
    assert.equal(schema.$defs.entry.required, undefined, "severity is optional in a policy");
});

test("the policy references the observation's sha256 definition, not a copy of it", () => {
    assert.equal(schema.properties.expectFingerprint.properties.value.$ref, "observation.schema.json#/$defs/sha256");
    assert.equal(schema.properties.expectFingerprint.properties.value.pattern, undefined);
});

test("every entry that takes a value requires it, and the three that do not take only a severity", () => {
    const withoutValue = ["validityStarted", "validityNotEnded", "matchesPrivateKey"];
    for (const [entry, kind] of ENTRIES) {
        const required = schema.properties[entry].required ?? [];
        assert.equal(required.includes("value"), kind !== "none", entry);
        assert.equal(withoutValue.includes(entry), kind === "none", entry);
    }
});
