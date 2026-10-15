import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { PolicyError, evaluate as evaluateObservation, serializeCheckResult } from "../src/index.js";
import { evaluate, observed, policyOf } from "./helpers/evaluation.js";
import { PASSPHRASE, REASON, bytes, matchesPrivateKey, observationOf, text } from "./helpers/keys.js";
import { validatorFor } from "./helpers/schema.js";

// `evaluate` with `options.privateKey`: the rule `matchesPrivateKey` is evaluated when a key is
// given, and the code of its result comes from what the rule found.

const errorsOf = validatorFor("check-result");
const P256 = observationOf("leaf-p256.pem");
const examples = new URL("../schema/examples/check-result/", import.meta.url);

/** @param {string} name */
const example = (name) => JSON.parse(readFileSync(new URL(name, examples), "utf8"));

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
    return assert.fail("it did not throw");
}

test("evaluate with options.privateKey evaluates matchesPrivateKey when the policy does not list it, with severity fail, shows the entry in the applied policy, and puts its result after the policy's rules and before the caller's own", () => {
    const own = function issuerAllowed() {
        return { code: "ISSUER_NOT_ALLOWED", status: /** @type {const} */ ("pass"), message: "m" };
    };
    const policy = policyOf({ expiresWithin: { value: "1d" }, expectKind: { value: "end-entity" } });
    const check = evaluate(observed(), policy, { privateKey: { material: text("leaf-rsa.key") }, rules: [own] });
    assert.deepEqual(check.results.map((/** @type {any} */ result) => result.code), ["NOT_YET_VALID", "EXPIRED", "EXPIRES_SOON", "TARGET_NOT_END_ENTITY", "KEY_MISMATCH", "ISSUER_NOT_ALLOWED"]);
    const result = check.results[4];
    assert.deepEqual(result.rule, { name: "matchesPrivateKey" });
    assert.equal(result.status, "fail");
    assert.deepEqual(check.policy.matchesPrivateKey, { severity: "fail" });
    assert.deepEqual(Object.keys(check.policy), ["contract", "validityStarted", "validityNotEnded", "expiresWithin", "expectKind", "matchesPrivateKey"]);
    assert.equal(check.summary.status, "fail");
    assert.deepEqual(errorsOf(check), []);
    // The policy that was given is not changed by the entry the key asked for.
    assert.deepEqual(policy, policyOf({ expiresWithin: { value: "1d" }, expectKind: { value: "end-entity" } }));
});

test("the entry's severity is used when the policy lists matchesPrivateKey, and its other properties are not repeated", () => {
    const key = { material: text("leaf-rsa.key") };
    const warned = evaluate(observed(), policyOf({ matchesPrivateKey: { severity: "warn" } }), { privateKey: key });
    assert.equal(warned.results.at(-1).status, "warn");
    assert.deepEqual(warned.policy.matchesPrivateKey, { severity: "warn" });
    assert.equal(warned.summary.status, "warn");
    const failed = evaluate(observed(), policyOf({ matchesPrivateKey: { severity: "fail" } }), { privateKey: key });
    assert.equal(failed.results.at(-1).status, "fail");
    const plain = evaluate(observed(), policyOf({ matchesPrivateKey: {} }), { privateKey: key });
    assert.equal(plain.results.at(-1).status, "fail");
    assert.deepEqual(plain.policy.matchesPrivateKey, { severity: "fail" });
    const extra = evaluate(observed(), policyOf({ matchesPrivateKey: { severity: "warn", passphrase: "s3cret", key: "k" } }), { privateKey: key });
    assert.deepEqual(extra.policy.matchesPrivateKey, { severity: "warn" });
    // A key that matches passes, whatever the severity.
    const matched = evaluate(observed(), policyOf({ matchesPrivateKey: { severity: "warn" } }), { privateKey: { material: text("leaf-p256.key") } });
    assert.equal(matched.results.at(-1).status, "pass");
    assert.equal(matched.summary.status, "pass");
});

test("a policy that lists matchesPrivateKey and no key still throws PolicyError at /matchesPrivateKey, and with a key it does not", () => {
    for (const options of [undefined, {}, { privateKey: undefined }, { rules: [] }]) {
        const error = thrown(() => evaluate(observed(), policyOf({ matchesPrivateKey: {} }), options));
        assert.ok(error instanceof PolicyError);
        assert.deepEqual(error.problems, [{ path: "/matchesPrivateKey", message: "needs a private key, and none is given" }]);
    }
    assert.doesNotThrow(() => evaluate(observed(), policyOf({ matchesPrivateKey: {} }), { privateKey: { material: "" } }));
    // A key does not make a policy valid that is not.
    const error = thrown(() => evaluate(observed(), policyOf({ matchesPrivateKey: null, expiresWithin: { value: "30" } }), { privateKey: { material: "" } }));
    assert.ok(error instanceof PolicyError);
    assert.deepEqual(error.problems.map((/** @type {any} */ problem) => problem.path).sort(), ["/expiresWithin/value", "/matchesPrivateKey"]);
    assert.deepEqual(thrown(() => evaluate(observed(), policyOf({ matchesPrivateKey: { severity: "loud" } }), { privateKey: { material: "" } })).problems.map((/** @type {any} */ problem) => problem.path), ["/matchesPrivateKey/severity"]);
});

test("the code of the result comes from what the rule found, KEY_MISMATCH for a key that was read and KEY_UNREADABLE for one that was not, and it is the result matchesPrivateKey gives", async (t) => {
    /** @type {[string, string | Uint8Array, string | undefined, string, string][]} */
    const cases = [
        ["a key that matches", text("leaf-p256.key"), undefined, "KEY_MISMATCH", "pass"],
        ["a key that does not", text("leaf-rsa.key"), undefined, "KEY_MISMATCH", "fail"],
        ["a key that is encrypted", text("leaf-p256.pkcs8-encrypted.key"), undefined, "KEY_UNREADABLE", "fail"],
        ["an encrypted key with its passphrase", text("leaf-p256.pkcs8-encrypted.key"), PASSPHRASE, "KEY_MISMATCH", "pass"],
        ["a truncated key", text("leaf-rsa.truncated.key"), undefined, "KEY_UNREADABLE", "fail"],
        ["a certificate", text("leaf-rsa.certificate.key"), undefined, "KEY_UNREADABLE", "fail"],
        ["a file with two keys", text("two-keys.key"), undefined, "KEY_UNREADABLE", "fail"],
        ["an empty file", "", undefined, "KEY_UNREADABLE", "fail"],
        ["a DER file", bytes("leaf-p256.der"), undefined, "KEY_UNREADABLE", "fail"],
    ];
    for (const [what, material, passphrase, code, status] of cases) {
        await t.test(what, () => {
            const privateKey = { material, passphrase };
            for (const severity of ["fail", "warn"]) {
                const check = evaluateObservation(P256, { contract: 1, matchesPrivateKey: { severity: /** @type {"fail" | "warn"} */ (severity) } }, { privateKey });
                const result = check.results.at(-1);
                assert.ok(result);
                assert.equal(result.code, code);
                assert.equal(result.status, status === "pass" ? "pass" : severity);
                assert.deepEqual(result, matchesPrivateKey(P256, privateKey, { severity }));
                assert.deepEqual(errorsOf(check), []);
                assert.equal(serializeCheckResult(JSON.parse(serializeCheckResult(check))), serializeCheckResult(check));
                assert.equal(check.summary.fail + check.summary.warn + check.summary.pass, check.results.length);
            }
            const last = /** @type {object} */ (evaluateObservation(P256, { contract: 1 }, { privateKey }).results.at(-1));
            assert.equal("actual" in last, code === "KEY_MISMATCH");
            assert.equal("expected" in last, code === "KEY_MISMATCH");
        });
    }
});

test("a key that is asked for counts as something checked, so a policy with no other rule gives no POLICY_EMPTY", () => {
    const withKey = evaluate(observed(), policyOf(), { privateKey: { material: text("leaf-p256.key") } });
    assert.deepEqual(withKey.results.map((/** @type {any} */ result) => result.code), ["NOT_YET_VALID", "EXPIRED", "KEY_MISMATCH"]);
    const without = evaluate(observed(), policyOf());
    assert.deepEqual(without.results.map((/** @type {any} */ result) => result.code), ["NOT_YET_VALID", "EXPIRED", "POLICY_EMPTY"]);
});

test("options.privateKey is not copied by evaluate's reader of JSON: a Buffer and a Uint8Array are accepted, and nothing is changed", () => {
    const material = Buffer.from(text("leaf-p256.pkcs8-encrypted.key"));
    const copy = Buffer.from(material);
    const given = Object.freeze({ material, passphrase: PASSPHRASE });
    const check = evaluate(observed(), policyOf(), { privateKey: given });
    assert.equal(check.results.at(-1).code, "KEY_MISMATCH");
    assert.ok(material.equals(copy));
    assert.deepEqual(Object.keys(given), ["material", "passphrase"]);
    assert.equal(evaluate(observed(), policyOf(), { privateKey: { material: new Uint8Array(copy), passphrase: PASSPHRASE } }).results.at(-1).code, "KEY_MISMATCH");
    // The same arguments give equal results.
    assert.deepEqual(evaluate(observed(), policyOf(), { privateKey: given }), check);
});

test("a wrong options.privateKey is a TypeError, reported before a problem of the policy and before anything else is evaluated", () => {
    for (const privateKey of [null, "-----BEGIN PRIVATE KEY-----", 5, [], { material: 5 }, { material: "" , passphrase: 12345 }, { material: "", passphrase: Buffer.from("x") }]) {
        const error = thrown(() => evaluate(observed(), policyOf({ matchesPrivateKey: {}, expiresWithin: { value: "30" } }), { privateKey }));
        assert.ok(error instanceof TypeError, JSON.stringify(privateKey));
        assert.ok(!(error instanceof PolicyError));
    }
    assert.equal(thrown(() => evaluate(observed(), policyOf(), { privateKey: { material: 5 } })).message, "options.privateKey.material must be a string, a Buffer or a Uint8Array");
    assert.equal(thrown(() => evaluate(observed(), policyOf(), { privateKey: { material: "", passphrase: {} } })).message, "options.privateKey.passphrase must be text");
    assert.equal(thrown(() => evaluate(observed(), policyOf(), { privateKey: 5 })).message, "options.privateKey must be an object with a material and, optionally, a passphrase");
    // An observation with no spkiSha256 is a TypeError when a key needs it, and only then.
    const observation = observed();
    delete observation.certificates[0].spkiSha256;
    assert.equal(thrown(() => evaluate(observation, policyOf(), { privateKey: { material: "" } })).message, "observation.certificates[0].spkiSha256 must be 64 lowercase hexadecimal characters");
    assert.doesNotThrow(() => evaluate(observation, policyOf()));
});

test("a rule of the caller's own is given the observation and the instant and never the key", () => {
    /** @type {unknown[][]} */
    const seen = [];
    const spy = (/** @type {unknown[]} */ ...args) => {
        seen.push(args);
        return { code: "OWN", status: /** @type {const} */ ("pass"), message: "m" };
    };
    evaluate(observed(), policyOf(), { privateKey: { material: text("leaf-p256.key"), passphrase: PASSPHRASE }, rules: [spy] });
    assert.equal(seen.length, 1);
    assert.equal(seen[0].length, 2);
    assert.equal(typeof seen[0][1], "string");
    assert.ok(!JSON.stringify(seen).includes("PRIVATE KEY"));
    assert.ok(!JSON.stringify(seen).includes(PASSPHRASE));
});

test("the key examples are what the library writes for their result, and the message of the one for an encrypted key is the one a key without its passphrase gets", () => {
    const unreadable = example("key-unreadable.json");
    const mine = evaluate(observed(), policyOf({ matchesPrivateKey: { severity: "warn" } }), { privateKey: { material: text("leaf-p256.pkcs8-encrypted.key") } });
    assert.deepEqual(mine.results.at(-1), unreadable.results.at(-1));
    assert.equal(unreadable.results.at(-1).message, REASON.encrypted);
    assert.deepEqual(mine.policy.matchesPrivateKey, unreadable.policy.matchesPrivateKey);

    const mismatch = example("key-mismatch.json");
    const other = evaluate(observed(), policyOf(), { privateKey: { material: text("leaf-rsa.key") } });
    const { actual, expected, ...written } = mismatch.results.at(-1);
    const { actual: gotActual, expected: gotExpected, ...got } = other.results.at(-1);
    assert.deepEqual(got, written);
    assert.match(actual, /^[0-9a-f]{64}$/);
    assert.match(gotActual, /^[0-9a-f]{64}$/);
    assert.match(expected, /^[0-9a-f]{64}$/);
    assert.match(gotExpected, /^[0-9a-f]{64}$/);
});
