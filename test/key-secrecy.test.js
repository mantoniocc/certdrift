import { test } from "node:test";
import assert from "node:assert/strict";
import { createPrivateKey } from "node:crypto";
import { PolicyError, evaluate as evaluateObservation, serializeCheckResult } from "../src/index.js";
import { evaluate, observed, policyOf } from "./helpers/evaluation.js";
import { PASSPHRASE, bodyLines, matchesPrivateKey, observationOf, text } from "./helpers/keys.js";

// The key and the passphrase never appear in a result, in a message, in a PolicyError, in a
// TypeError or anywhere `evaluate` or `matchesPrivateKey` returns or throws. For each case below,
// pieces of the key's body and the passphrase are searched for in the serialized check result, in
// every message and in the text of every error, whatever the way the call ends.

const P256 = observationOf("leaf-p256.pem");
const WRONG_PASSPHRASE = "hunter2-wrong-passphrase";

/**
 * Pieces of a key's body that nothing public repeats: every line of base64, and a slice of the
 * middle of each, which is what a message that quotes part of a line would hold.
 * @param {string} key
 */
function piecesOf(key) {
    return bodyLines(key).flatMap((line) => (line.length >= 16 ? [line, line.slice(4, 20)] : []));
}

/**
 * Everything an error says: its name, message and stack, its text, each property it carries, and its cause.
 * @param {any} error
 * @returns {string}
 */
function textOfError(error) {
    return JSON.stringify([error?.name, error?.message, String(error?.stack), String(error), Object.getOwnPropertyNames(error ?? {}).map((name) => [name, error[name]]), String(error?.cause), error?.problems]);
}

/**
 * @param {unknown} value
 * @returns {boolean} Whether a value holds bytes or text a key could be read from, at any depth.
 */
function holdsBytes(value) {
    if (value === null || typeof value !== "object") return false;
    if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) return true;
    return Object.values(value).some(holdsBytes);
}

/** @type {{ what: string, material: string | Uint8Array, passphrase?: string, policy?: object }[]} */
const OUTCOMES = [
    { what: "the key matches", material: text("leaf-p256.key") },
    { what: "the key matches, encrypted, with its passphrase", material: text("leaf-p256.pkcs8-encrypted.key"), passphrase: PASSPHRASE },
    { what: "the key does not match", material: text("leaf-rsa.key") },
    { what: "the key is truncated", material: text("leaf-rsa.truncated.key") },
    { what: "the key is encrypted and no passphrase was given", material: text("leaf-rsa.pkcs8-encrypted.key") },
    { what: "the traditional key is encrypted and no passphrase was given", material: text("leaf-rsa.pkcs1-encrypted.key") },
    { what: "the key is encrypted and the passphrase is wrong", material: text("leaf-rsa.pkcs8-encrypted.key"), passphrase: WRONG_PASSPHRASE },
    { what: "the key is encrypted and the passphrase is empty", material: text("leaf-rsa.pkcs1-encrypted.key"), passphrase: "" },
    { what: "the file holds a certificate", material: text("leaf-rsa.certificate.key") },
    { what: "the file holds a public key", material: text("leaf-rsa.public.key") },
    { what: "the file holds two keys", material: text("two-keys.key") },
    { what: "the file holds an encrypted key and a plain one", material: text("leaf-rsa.pkcs8-encrypted.key") + text("leaf-rsa.key"), passphrase: PASSPHRASE },
    { what: "the file holds a block that is not a key", material: text("not-a-key.key") },
    { what: "the file is empty", material: "" },
    { what: "the key is DER", material: createPrivateKey(text("leaf-rsa.key")).export({ format: "der", type: "pkcs8" }) },
    { what: "the key is bytes", material: Buffer.from(text("leaf-rsa.key")) },
    { what: "the key has a passphrase it does not need", material: text("leaf-rsa.key"), passphrase: WRONG_PASSPHRASE },
];

test("the key and the passphrase never appear in the result of matchesPrivateKey or of evaluate, in its message or in the serialized check result, for each way the check can end", async (t) => {
    for (const { what, material, passphrase } of OUTCOMES) {
        await t.test(what, () => {
            const keyText = typeof material === "string" ? material : Buffer.from(material).toString("latin1");
            const secrets = [...piecesOf(keyText), ...piecesOf(text("leaf-rsa.key")).filter(() => what === "the key is DER"), ...(passphrase ? [passphrase] : []), PASSPHRASE, WRONG_PASSPHRASE];
            assert.ok(piecesOf(keyText).length > 0 || material.length === 0 || what === "the key is DER" || what.includes("certificate") || what.includes("public"), "the test has pieces to search for");

            for (const severity of /** @type {const} */ (["fail", "warn"])) {
                const direct = matchesPrivateKey(P256, { material, passphrase }, { severity });
                const check = evaluateObservation(P256, { contract: 1, matchesPrivateKey: { severity } }, { privateKey: { material, passphrase } });
                const unlisted = evaluateObservation(P256, { contract: 1 }, { privateKey: { material, passphrase } });
                const searched = [JSON.stringify(direct), direct.message, serializeCheckResult(check), JSON.stringify(check), ...check.results.map((result) => result.message), serializeCheckResult(unlisted)];
                for (const place of searched) {
                    for (const secret of secrets) {
                        // The passphrase that is empty or is a piece of the public certificate proves nothing.
                        if (secret.length < 8) continue;
                        assert.ok(!place.includes(secret), `${what}: ${JSON.stringify(secret.slice(0, 12))}... is in ${place.slice(0, 80)}`);
                    }
                }
                assert.equal(holdsBytes(direct), false);
                assert.equal(holdsBytes(check), false);
                assert.ok(!/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(searched.join("\n")));
            }
        });
    }
});

test("the key and the passphrase never appear in a TypeError, whatever the wrong call", async (t) => {
    const key = text("leaf-p256.key");
    const encrypted = text("leaf-p256.pkcs8-encrypted.key");
    const [line] = bodyLines(key);
    const secrets = [...piecesOf(key), ...piecesOf(encrypted), "hunter2-pass", PASSPHRASE, "12345"];
    /** @type {[string, any][]} */
    const wrongKeys = [
        ["a number as the passphrase", { material: encrypted, passphrase: 12345 }],
        ["an object as the passphrase", { material: encrypted, passphrase: { secret: "hunter2-pass" } }],
        ["a Buffer as the passphrase", { material: encrypted, passphrase: Buffer.from("hunter2-pass") }],
        ["a list as the passphrase", { material: key, passphrase: ["hunter2-pass", PASSPHRASE] }],
        ["a String object as the passphrase", { material: key, passphrase: new String(PASSPHRASE) }],
        ["a symbol as the passphrase", { material: key, passphrase: Symbol("hunter2-pass") }],
        ["an accessor as the passphrase", { material: key, get passphrase() { return "hunter2-pass"; } }],
        ["a key where the material is a String object", { material: new String(key) }],
        ["a list holding the key", { material: [key] }],
        ["an object holding the key", { material: { key, line } }],
        ["an ArrayBuffer holding the key", { material: new TextEncoder().encode(key).buffer }],
        ["a number as the material", { material: 12345, passphrase: "hunter2-pass" }],
        ["the key as the argument itself", key],
        ["the key in a list", [key]],
        ["the key as a Buffer", Buffer.from(key)],
        ["a proxy that throws the key", new Proxy({}, { getOwnPropertyDescriptor() { throw new Error(key); } })],
    ];
    for (const [what, privateKey] of wrongKeys) {
        await t.test(what, () => {
            for (const call of [
                () => matchesPrivateKey(P256, privateKey),
                () => matchesPrivateKey(P256, privateKey, { severity: "warn" }),
                () => evaluateObservation(observed(), policyOf(), { privateKey }),
                () => evaluate(observed(), policyOf({ matchesPrivateKey: {} }), { privateKey }),
                () => evaluate(observed(), policyOf({ expiresWithin: { value: "30" } }), { privateKey }),
            ]) {
                /** @type {any} */
                let error;
                try {
                    call();
                } catch (caught) {
                    error = caught;
                }
                assert.ok(error instanceof TypeError || error instanceof PolicyError, what);
                // An error of the caller's own, such as the proxy's, is not ours to rewrite, but a TypeError
                // that is ours says what is wrong with fixed text.
                assert.ok(error instanceof TypeError, what);
                assert.equal(/** @type {any} */ (error).code, undefined, "an error of Node.js has a code");
                const shown = textOfError(error);
                for (const secret of secrets) assert.ok(!shown.includes(secret), `${what}: ${secret.slice(0, 12)}... is in ${shown.slice(0, 100)}`);
            }
        });
    }

    // The other arguments of a wrong call do not quote the key either.
    for (const options of [{ severity: key }, { severity: PASSPHRASE }, key]) {
        const error = (() => {
            try {
                matchesPrivateKey(P256, { material: key }, options);
            } catch (caught) {
                return caught;
            }
        })();
        assert.ok(error instanceof TypeError);
        for (const secret of secrets) assert.ok(!textOfError(error).includes(secret), secret.slice(0, 12));
    }
    for (const observation of [key, [key], { contract: 1, target: key, certificates: [key] }, { ...P256, certificates: [{ spkiSha256: key }] }]) {
        const error = (() => {
            try {
                matchesPrivateKey(observation, { material: key, passphrase: PASSPHRASE });
            } catch (caught) {
                return caught;
            }
        })();
        assert.ok(error instanceof TypeError);
        for (const secret of secrets) assert.ok(!textOfError(error).includes(secret), secret.slice(0, 12));
    }
});

test("the key and the passphrase never appear in a PolicyError, for a policy that lists matchesPrivateKey with no key and for one that holds them in the wrong place", () => {
    const key = text("leaf-p256.key");
    const secrets = [...piecesOf(key), PASSPHRASE, "hunter2-pass"];
    const policies = [
        policyOf({ matchesPrivateKey: {} }),
        policyOf({ matchesPrivateKey: { severity: "warn", passphrase: PASSPHRASE, key, material: key } }),
        policyOf({ matchesPrivateKey: { severity: key, passphrase: "hunter2-pass" } }),
        policyOf({ matchesPrivateKey: key }),
        policyOf({ matchesPrivateKey: null, expiresWithin: { value: key }, expectSan: { value: [key, PASSPHRASE] }, privateKey: { material: key, passphrase: "hunter2-pass" } }),
        { contract: 1, privateKey: { material: key, passphrase: PASSPHRASE }, passphrase: PASSPHRASE, [key]: { value: key } },
    ];
    for (const [position, policy] of policies.entries()) {
        for (const options of [undefined, { privateKey: { material: key, passphrase: PASSPHRASE } }]) {
            /** @type {any} */
            let error;
            try {
                evaluate(observed(), policy, options);
            } catch (caught) {
                error = caught;
            }
            // With a key, only a policy that is wrong in itself throws.
            if (error === undefined) continue;
            assert.ok(error instanceof PolicyError, `policy ${position}`);
            const shown = textOfError(error);
            for (const secret of secrets) assert.ok(!shown.includes(secret), `policy ${position}: ${secret.slice(0, 12)}...`);
        }
    }
    // A key that is given is not in the applied policy, which holds only the entries this version knows.
    const check = evaluate(observed(), policyOf({ matchesPrivateKey: { severity: "warn", passphrase: PASSPHRASE, key, material: key } }), { privateKey: { material: key, passphrase: PASSPHRASE } });
    assert.deepEqual(check.policy.matchesPrivateKey, { severity: "warn" });
    const written = serializeCheckResult(check);
    for (const secret of secrets) assert.ok(!written.includes(secret), secret.slice(0, 12));
});

test("nothing a rule of the caller's own can reach holds the key: it gets the observation and the instant, frozen, and the check result is a copy", () => {
    const key = text("leaf-p256.key");
    /** @type {unknown[]} */
    const seen = [];
    const spy = (/** @type {unknown[]} */ ...args) => {
        seen.push(...args);
        return { code: "OWN", status: /** @type {const} */ ("pass"), message: "m" };
    };
    const check = evaluate(observed(), policyOf(), { privateKey: { material: key, passphrase: PASSPHRASE }, rules: [spy] });
    const everything = JSON.stringify([seen, check]);
    for (const secret of [...piecesOf(key), PASSPHRASE]) assert.ok(!everything.includes(secret), secret.slice(0, 12));
});
