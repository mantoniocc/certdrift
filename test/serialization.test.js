import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { X509Certificate } from "node:crypto";
import { inspect } from "../src/index.js";
import { validatorFor } from "./helpers/schema.js";

const fixturesUrl = new URL("fixtures/", import.meta.url);
const errorsOf = validatorFor("observation");
const AT = new Date("2026-09-15T14:02:11Z");

/** @param {string} name File name in test/fixtures/, e.g. `"leaf-rsa.pem"`. */
function certificate(name) {
    return new X509Certificate(readFileSync(new URL(name, fixturesUrl)));
}

// Node reports publicExponent as a BigInt for both key types.
const RSA_FIXTURES = [
    { name: "leaf-rsa.pem", algorithm: "rsa" },
    { name: "leaf-rsa-pss.pem", algorithm: "rsa-pss" },
];

for (const { name, algorithm } of RSA_FIXTURES) {
    // This is the reason key fields are copied one by one. If it stops throwing,
    // Node's behaviour has changed and that rule may no longer be needed.
    test(`${name}: Node reports publicExponent as a BigInt, which JSON.stringify rejects`, () => {
        const details = certificate(name).publicKey.asymmetricKeyDetails;
        assert.equal(typeof details?.publicExponent, "bigint");
        assert.throws(() => JSON.stringify(details), TypeError);
    });

    test(`${name}: the observation inspect() builds from it serializes and validates`, () => {
        // Throws "Do not know how to serialize a BigInt" if one reached the observation.
        const json = JSON.stringify(inspect(readFileSync(new URL(name, fixturesUrl)), { at: AT }));

        const observation = JSON.parse(json);
        assert.deepEqual(errorsOf(observation), []);
        assert.deepEqual(observation.certificates[0].key, { algorithm, size: 2048, curve: null });
    });
}

// Two runs over the same material with the same `observation.at` must produce identical bytes.
// Remove the skip once the library builds observations and defines their JSON output.
test(
    "the same material and `at` serialize to identical bytes",
    { skip: "the library does not build observations yet" },
    () => {},
);