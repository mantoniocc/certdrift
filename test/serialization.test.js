import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { X509Certificate } from "node:crypto";
import { inspect, serializeObservation, AmbiguousTargetError } from "../src/index.js";
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

const examplesUrl = new URL("../schema/examples/observation/", import.meta.url);

/** The key order the issue fixes, which the examples in schema/ show. */
const TOP_LEVEL = ["contract", "format", "observation", "target", "certificates", "warnings"];
const PER_CERTIFICATE = [
    "index", "kind", "selfSigned", "issuedBy", "subject", "issuer", "serial", "notBefore", "notAfter",
    "san", "eku", "key", "sha256", "spkiSha256", "derived",
];

/** @param {string} name File name in schema/examples/observation/. */
function example(name) {
    return readFileSync(new URL(name, examplesUrl), "utf8");
}

const EXAMPLES = readdirSync(examplesUrl).filter((name) => name.endsWith(".json")).sort();

/**
 * Every certificate fixture whose observation exists, with the bytes the library gives for it.
 * A bundle with two possible targets has no observation, and says so with an AmbiguousTargetError.
 * @returns {{ name: string, bytes: string }[]}
 */
function serializedFixtures() {
    return readdirSync(fixturesUrl)
        .filter((name) => /\.(pem|der)$/.test(name))
        .sort()
        .flatMap((name) => {
            try {
                return [{ name, bytes: serializeObservation(inspect(readFileSync(new URL(name, fixturesUrl)), { at: AT })) }];
            } catch (error) {
                if (error instanceof AmbiguousTargetError) return [];
                throw error;
            }
        });
}

/** The observation of the first fixture, as a plain object to be rearranged by each test. */
function observation() {
    return JSON.parse(serializeObservation(inspect(readFileSync(new URL("leaf-p256.pem", fixturesUrl)), { at: AT })));
}

test("the fixtures that have an observation are all but the two ambiguous bundles", () => {
    const names = serializedFixtures().map((found) => found.name);
    assert.ok(names.length > 30, `only ${names.length} fixtures were serialized`);
    assert.ok(names.includes("leaf-p256.pem") && names.includes("bundle-cross-signed.pem"));
    assert.ok(!names.includes("bundle-two-leaves.pem") && !names.includes("bundle-renewed-root.pem"));
});

test("the same material and `at` serialize to identical bytes", () => {
    const first = serializedFixtures();
    const second = serializedFixtures();
    assert.ok(first.length > 0);
    assert.deepEqual(second, first);
});

test("key order matches schema/examples/observation: top level and per certificate", () => {
    for (const name of EXAMPLES) {
        const shown = JSON.parse(example(name));
        assert.deepEqual(Object.keys(shown), TOP_LEVEL, name);
        for (const found of shown.certificates) assert.deepEqual(Object.keys(found), PER_CERTIFICATE, name);
    }
    for (const { name, bytes } of serializedFixtures()) {
        const written = JSON.parse(bytes);
        assert.deepEqual(Object.keys(written), TOP_LEVEL, name);
        for (const found of written.certificates) assert.deepEqual(Object.keys(found), PER_CERTIFICATE, name);
    }
});

test("serializing each example reproduces its bytes", () => {
    assert.ok(EXAMPLES.length >= 9);
    for (const name of EXAMPLES) {
        assert.equal(serializeObservation(JSON.parse(example(name))), example(name), name);
    }
});

test("serializing the output of a fixture again reproduces its bytes", () => {
    for (const { name, bytes } of serializedFixtures()) {
        assert.equal(serializeObservation(JSON.parse(bytes)), bytes, name);
    }
});

test("output ends in one newline and indents with two spaces", () => {
    for (const { name, bytes } of serializedFixtures()) {
        assert.ok(bytes.endsWith("}\n") && !bytes.endsWith("\n\n"), name);
        assert.ok(!bytes.includes("\t"), name);
        const depth = (/** @type {string} */ line) => line.length - line.trimStart().length;
        const lines = bytes.slice(0, -1).split("\n");
        assert.equal(lines[0], "{", name);
        let previous = 0;
        for (const line of lines.slice(1)) {
            assert.equal(depth(line) % 2, 0, `${name}: ${line}`);
            // One level deeper only right after an opening bracket, and never more than one.
            assert.ok(depth(line) <= previous + 2, `${name}: ${line}`);
            if (depth(line) === previous + 2) assert.match(lines[lines.indexOf(line) - 1] ?? "", /[[{]$/, name);
            previous = depth(line);
        }
    }
});

test("the caller's key order does not change the bytes", () => {
    const material = readFileSync(new URL("leaf-p256.pem", fixturesUrl));
    const forward = serializeObservation(inspect(material, { at: AT, source: { kind: "host", ref: "a:443", servername: "a" } }));
    const backward = serializeObservation(inspect(material, { at: AT, source: { servername: "a", ref: "a:443", kind: "host" } }));
    assert.equal(backward, forward);
    assert.deepEqual(Object.keys(JSON.parse(forward).observation.source), ["kind", "ref", "servername"]);
});

test("keys the contract does not name are kept after the named ones, sorted", () => {
    const made = observation();
    const reordered = {
        zeta: 1,
        warnings: made.warnings,
        certificates: made.certificates.map((/** @type {any} */ found) => ({ extra: { b: 1, a: 2 }, ...found })),
        target: made.target,
        observation: { source: { vendor: "x", kind: "external", ref: "r", about: { z: 1, y: 2 } }, at: made.observation.at },
        format: made.format,
        contract: made.contract,
        alpha: 2,
    };
    const written = JSON.parse(serializeObservation(reordered));
    assert.deepEqual(Object.keys(written), [...TOP_LEVEL, "alpha", "zeta"]);
    assert.deepEqual(Object.keys(written.certificates[0]), [...PER_CERTIFICATE, "extra"]);
    assert.deepEqual(Object.keys(written.certificates[0].extra), ["a", "b"]);
    assert.deepEqual(Object.keys(written.observation.source), ["kind", "ref", "about", "vendor"]);
    assert.deepEqual(Object.keys(written.observation.source.about), ["y", "z"]);
});

test("keys that look like array indices give the same bytes whatever the order they came in", () => {
    const made = observation();
    const one = serializeObservation({ ...made, observation: { ...made.observation, source: { kind: "x", 10: 1, 2: 2, b: 3 } } });
    const other = serializeObservation({ ...made, observation: { ...made.observation, source: { b: 3, 2: 2, kind: "x", 10: 1 } } });
    assert.equal(other, one);
});

test("an own __proto__ key from JSON.parse survives", () => {
    const made = observation();
    const parsed = JSON.parse('{"kind":"x","__proto__":{"polluted":true}}');
    const written = serializeObservation({ ...made, observation: { ...made.observation, source: parsed } });
    assert.match(written, /"__proto__": \{\s+"polluted": true\s+\}/);
    assert.equal(/** @type {any} */ ({}).polluted, undefined);
});

test("the same certificates in any form give identical bytes", () => {
    const text = readFileSync(new URL("bundle-ordered.pem", fixturesUrl), "latin1");
    const expected = serializeObservation(inspect(text, { at: AT }));
    const forms = {
        "a Buffer": Buffer.from(text, "latin1"),
        "CRLF line endings": text.replaceAll("\n", "\r\n"),
        "text around the blocks": `subject=...\n${text}\ntrailing text\n`,
    };
    for (const [name, material] of Object.entries(forms)) {
        assert.equal(serializeObservation(inspect(material, { at: AT })), expected, name);
    }
    const sameSecond = new Date(AT.getTime() + 999);
    assert.equal(serializeObservation(inspect(text, { at: sameSecond })), expected, "an `at` with milliseconds");
});

test("line breaks and control characters in a value add no lines", () => {
    const made = observation();
    const withRef = (/** @type {string} */ ref) =>
        serializeObservation({ ...made, observation: { ...made.observation, source: { kind: "external", ref } } });
    const text = withRef("a\nb\r\nc\u0000\u001f");
    assert.equal(text.split("\n").length, withRef("plain").split("\n").length);
    assert.equal(JSON.parse(text).observation.source.ref, "a\nb\r\nc\u0000\u001f");
});

test("a lone surrogate is escaped so that the output is valid UTF-8", () => {
    const made = observation();
    const text = serializeObservation({ ...made, observation: { ...made.observation, source: { kind: "external", ref: "a\ud800b" } } });
    assert.match(text, /a\\ud800b/);
    assert.equal(Buffer.from(text, "utf8").toString("utf8"), text);
});

test("a Date inside the observation is written as its ISO string", () => {
    const made = observation();
    const text = serializeObservation({ ...made, observation: { ...made.observation, source: { kind: "external", ref: "r", seen: new Date(0) } } });
    assert.equal(JSON.parse(text).observation.source.seen, "1970-01-01T00:00:00.000Z");
});

test("an observation that contains itself throws a TypeError, one that repeats a value does not", () => {
    const made = observation();
    const shared = { z: 1 };
    const cyclic = { ...made, observation: { ...made.observation, source: { kind: "x", ref: "r" } } };
    cyclic.observation.source.loop = cyclic;
    assert.throws(() => serializeObservation(cyclic), { name: "TypeError", message: /contains itself/ });

    const text = serializeObservation({ ...made, observation: { ...made.observation, source: { kind: "x", a: shared, b: shared } } });
    assert.deepEqual(JSON.parse(text).observation.source, { kind: "x", a: { z: 1 }, b: { z: 1 } });
});

test("anything but an object throws a TypeError", () => {
    for (const value of [undefined, null, "{}", 1, [], true]) {
        assert.throws(() => serializeObservation(/** @type {any} */ (value)), TypeError, String(value));
    }
});
