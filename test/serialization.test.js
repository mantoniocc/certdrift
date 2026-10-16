import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { X509Certificate } from "node:crypto";
import { inspect, serializeObservation, serializeCheckResult, serializeDelta, AmbiguousTargetError } from "../src/index.js";
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

/** The key order the examples in schema/examples/observation/ show, which are the reference. */
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
        for (let i = 1; i < lines.length; i += 1) {
            const line = lines[i];
            assert.equal(depth(line) % 2, 0, `${name}: ${line}`);
            // One level deeper only right after an opening bracket, and never more than one.
            assert.ok(depth(line) <= previous + 2, `${name}: ${line}`);
            if (depth(line) === previous + 2) assert.match(lines[i - 1], /[[{]$/, name);
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

// ---------------------------------------------------------------------------------------------
// The check result

const checkExamplesUrl = new URL("../schema/examples/check-result/", import.meta.url);
const CHECK_EXAMPLES = readdirSync(checkExamplesUrl).filter((name) => name.endsWith(".json")).sort();

/** @param {string} name File name in schema/examples/check-result/. */
const checkExample = (name) => readFileSync(new URL(name, checkExamplesUrl), "utf8");

const CHECK_TOP_LEVEL = ["contract", "now", "summary", "results", "policy", "observation"];

/**
 * The same value with every object's keys in the opposite order, which is a different way to have
 * built it.
 * @param {unknown} value
 * @returns {unknown}
 */
function reversed(value) {
    if (Array.isArray(value)) return value.map(reversed);
    if (typeof value !== "object" || value === null) return value;
    return Object.fromEntries(Object.entries(value).reverse().map(([key, inner]) => [key, reversed(inner)]));
}

test("serializing each check result example reproduces its bytes", () => {
    assert.ok(CHECK_EXAMPLES.length >= 9, CHECK_EXAMPLES.join(", "));
    for (const name of CHECK_EXAMPLES) {
        assert.equal(serializeCheckResult(JSON.parse(checkExample(name))), checkExample(name), name);
    }
});

test("one check result built in two ways, with its objects in opposite orders, gives the same bytes", () => {
    for (const name of CHECK_EXAMPLES) {
        const forward = JSON.parse(checkExample(name));
        const backward = reversed(forward);
        assert.notDeepEqual(Object.keys(/** @type {object} */ (backward)), Object.keys(forward), `${name} was not reordered`);
        assert.equal(serializeCheckResult(/** @type {any} */ (backward)), serializeCheckResult(forward), name);
        assert.equal(serializeCheckResult(/** @type {any} */ (backward)), checkExample(name), name);
    }
});

test("a check result is written verdict first, the observation last, and every object in the order of the contract", () => {
    for (const name of CHECK_EXAMPLES) {
        const written = JSON.parse(serializeCheckResult(/** @type {any} */ (reversed(JSON.parse(checkExample(name))))));
        assert.deepEqual(Object.keys(written), CHECK_TOP_LEVEL, name);
        assert.deepEqual(Object.keys(written.summary), ["status", "pass", "warn", "fail"], name);
        for (const result of written.results) {
            const named = ["code", "status", "rule", "message", "actual", "expected"].filter((key) => key in result);
            assert.deepEqual(Object.keys(result), named, name);
            if (result.rule !== null) assert.deepEqual(Object.keys(result.rule), ["name", "value"].filter((key) => key in result.rule), name);
        }
        const entries = Object.keys(written.policy);
        assert.deepEqual(entries.slice(0, 3), ["contract", "validityStarted", "validityNotEnded"], name);
        for (const entry of entries.slice(1)) assert.deepEqual(Object.keys(written.policy[entry]), ["value", "severity"].filter((key) => key in written.policy[entry]), `${name} ${entry}`);
    }
});

test("the observation inside a check result is written in the observation's own key order, from the same table", () => {
    for (const name of CHECK_EXAMPLES) {
        const written = JSON.parse(serializeCheckResult(/** @type {any} */ (reversed(JSON.parse(checkExample(name))))));
        assert.deepEqual(Object.keys(written.observation), TOP_LEVEL, name);
        for (const found of written.observation.certificates) assert.deepEqual(Object.keys(found), PER_CERTIFICATE, name);
        // What the observation serializer writes for it is what the check result holds, indentation aside.
        assert.equal(serializeObservation(written.observation), serializeObservation(JSON.parse(checkExample(name)).observation), name);
        assert.deepEqual(JSON.stringify(written.observation), JSON.stringify(JSON.parse(serializeObservation(written.observation))), name);
    }
});

test("the expected and actual of a name rule are written in a fixed order whatever order they were built in", () => {
    const made = JSON.parse(checkExample("ip-san.json"));
    const reordered = structuredClone(made);
    const found = reordered.results.find((/** @type {any} */ result) => result.code === "SAN_MISSING");
    found.actual = { ip: found.actual.ip, dns: found.actual.dns };
    found.expected = { ip: found.expected.ip, dns: found.expected.dns };
    assert.deepEqual(Object.keys(found.actual), ["ip", "dns"]);
    assert.equal(serializeCheckResult(reordered), serializeCheckResult(made));
    assert.deepEqual(Object.keys(JSON.parse(serializeCheckResult(reordered)).results.find((/** @type {any} */ result) => result.code === "SAN_MISSING").actual), ["dns", "ip"]);
});

test("keys the contract does not name are kept after the named ones in a check result, sorted, at every depth", () => {
    const made = JSON.parse(checkExample("own-rule.json"));
    const written = JSON.parse(serializeCheckResult({
        zeta: 1,
        ...made,
        summary: { zz: 1, ...made.summary, aa: 2 },
        results: made.results.map((/** @type {any} */ result) => ({ extra: { b: 1, a: 2 }, ...result })),
        policy: { ...made.policy, futureRule: { severity: "fail", value: 1, note: 2 }, expectKind: { note: 1, ...made.policy.expectKind } },
        alpha: 2,
    }));
    assert.deepEqual(Object.keys(written), [...CHECK_TOP_LEVEL, "alpha", "zeta"]);
    assert.deepEqual(Object.keys(written.summary), ["status", "pass", "warn", "fail", "aa", "zz"]);
    assert.deepEqual(Object.keys(written.results[0]), ["code", "status", "rule", "message", "actual", "expected", "extra"]);
    assert.deepEqual(Object.keys(written.results[0].extra), ["a", "b"]);
    assert.deepEqual(Object.keys(written.policy), ["contract", "validityStarted", "validityNotEnded", "expectKind", "futureRule"]);
    assert.deepEqual(Object.keys(written.policy.expectKind), ["value", "severity", "note"]);
    // An entry this version does not know has no table, so all its keys are sorted.
    assert.deepEqual(Object.keys(written.policy.futureRule), ["note", "severity", "value"]);
});

test("a check result ends in one newline and indents with two spaces", () => {
    for (const name of CHECK_EXAMPLES) {
        const text = serializeCheckResult(JSON.parse(checkExample(name)));
        assert.ok(text.endsWith("}\n") && !text.endsWith("\n\n"), name);
        assert.ok(!text.includes("\t"), name);
        assert.equal(text, `${JSON.stringify(JSON.parse(text), null, 2)}\n`, name);
    }
});

test("an own rule's parameter and a result's actual keep their own keys, in a fixed order, and arrays keep theirs", () => {
    const made = JSON.parse(checkExample("own-rule.json"));
    const own = made.results.at(-1);
    own.rule = { value: { z: [3, 1, 2], a: { y: 1, x: 2 } }, name: "own" };
    own.actual = { b: 1, a: [{ d: 1, c: 2 }] };
    const written = JSON.parse(serializeCheckResult(made)).results.at(-1);
    assert.deepEqual(Object.keys(written.rule), ["name", "value"]);
    assert.deepEqual(Object.keys(written.rule.value), ["a", "z"]);
    assert.deepEqual(Object.keys(written.rule.value.a), ["x", "y"]);
    assert.deepEqual(written.rule.value.z, [3, 1, 2]);
    assert.deepEqual(Object.keys(written.actual), ["a", "b"]);
    assert.deepEqual(Object.keys(written.actual.a[0]), ["c", "d"]);
});

test("a check result that contains itself throws a TypeError that says so, and anything but an object does too", () => {
    const made = JSON.parse(checkExample("pass.json"));
    made.results[0].rule.value = made;
    assert.throws(() => serializeCheckResult(made), { name: "TypeError", message: "the check result contains itself" });

    for (const value of [undefined, null, "{}", 1, [], true]) {
        assert.throws(() => serializeCheckResult(/** @type {any} */ (value)), { name: "TypeError", message: "the check result must be an object" }, String(value));
    }

    // The observation serializer keeps its own words.
    const observation = JSON.parse(example("file-single.json"));
    observation.warnings.push(observation);
    assert.throws(() => serializeObservation(observation), { name: "TypeError", message: "the observation contains itself" });
    assert.throws(() => serializeObservation(/** @type {any} */ (null)), { name: "TypeError", message: "the observation must be an object" });
});

test("a check result repeating the same value is not one that contains itself", () => {
    const made = JSON.parse(checkExample("pass.json"));
    const shared = { z: 1 };
    made.results[0].actual = shared;
    made.results[0].expected = shared;
    assert.deepEqual(JSON.parse(serializeCheckResult(made)).results[0].expected, { z: 1 });
});

test("the check result of the same checks serializes to the same bytes on every run, whatever the order it was assembled in", () => {
    const first = CHECK_EXAMPLES.map((name) => serializeCheckResult(JSON.parse(checkExample(name))));
    const second = CHECK_EXAMPLES.map((name) => serializeCheckResult(/** @type {any} */ (reversed(JSON.parse(checkExample(name))))));
    assert.deepEqual(second, first);
});

// ---------------------------------------------------------------------------------------------
// Deltas

const deltaExamplesUrl = new URL("../schema/examples/delta/", import.meta.url);
const DELTA_EXAMPLES = readdirSync(deltaExamplesUrl).filter((name) => name.endsWith(".json")).sort();

/** @param {string} name File name in schema/examples/delta/. */
const deltaExample = (name) => readFileSync(new URL(name, deltaExamplesUrl), "utf8");

const DELTA_TOP_LEVEL = ["contract", "identical", "before", "after", "changes"];

test("serializing each delta example reproduces its bytes", () => {
    assert.ok(DELTA_EXAMPLES.length >= 20, DELTA_EXAMPLES.join(", "));
    for (const name of DELTA_EXAMPLES) {
        assert.equal(serializeDelta(JSON.parse(deltaExample(name))), deltaExample(name), name);
    }
});

test("one Delta built in two ways, with its objects in opposite orders, gives the same bytes", () => {
    for (const name of DELTA_EXAMPLES) {
        const forward = JSON.parse(deltaExample(name));
        const backward = reversed(forward);
        assert.notDeepEqual(Object.keys(/** @type {object} */ (backward)), Object.keys(forward), `${name} was not reordered`);
        assert.equal(serializeDelta(/** @type {any} */ (backward)), serializeDelta(forward), name);
        assert.equal(serializeDelta(/** @type {any} */ (backward)), deltaExample(name), name);
    }
    // Also built from pieces, the way a comparison would assemble it.
    const made = {};
    const parts = JSON.parse(deltaExample("chain-replaced.json"));
    for (const key of [...DELTA_TOP_LEVEL].reverse()) /** @type {any} */ (made)[key] = parts[key];
    assert.equal(serializeDelta(/** @type {any} */ (made)), deltaExample("chain-replaced.json"));
});

test("a Delta is written in the order of the contract, and its before and after use the observation's own table for at and source", () => {
    for (const name of DELTA_EXAMPLES) {
        const written = JSON.parse(serializeDelta(/** @type {any} */ (reversed(JSON.parse(deltaExample(name))))));
        assert.deepEqual(Object.keys(written), DELTA_TOP_LEVEL, name);
        for (const side of [written.before, written.after]) {
            assert.deepEqual(Object.keys(side), ["at", "source"], name);
            assert.deepEqual(Object.keys(side.source), ["kind", "ref", "servername", "provider"].filter((key) => key in side.source), name);
        }
        for (const change of written.changes) {
            assert.deepEqual(Object.keys(change), ["field", "direction", "before", "after"].filter((key) => key in change), name);
            for (const link of [change.before, change.after].filter((value) => typeof value === "object" && value !== null && !Array.isArray(value))) {
                assert.deepEqual(Object.keys(link), ["position", "sha256"], name);
            }
        }
    }

    // The same table as the observation's: a source with every key, in any order, comes out as the observation writes it.
    const made = JSON.parse(deltaExample("identical.json"));
    made.before.source = { servername: "s", provider: "p", ref: "r", kind: "host", zeta: 1, alpha: 2 };
    const written = JSON.parse(serializeDelta(made));
    assert.deepEqual(Object.keys(written.before.source), ["kind", "ref", "servername", "provider", "alpha", "zeta"]);
    const observed = JSON.parse(serializeObservation(Object.assign(observation(), { observation: { source: made.before.source, at: made.before.at } })));
    assert.deepEqual(Object.keys(observed.observation.source), Object.keys(written.before.source));
    assert.deepEqual(Object.keys(observed.observation), Object.keys(written.before));
});

test("keys the contract does not name are kept after the named ones in a Delta, sorted, at every depth", () => {
    const made = JSON.parse(deltaExample("chain-replaced.json"));
    const written = JSON.parse(serializeDelta({
        zeta: 1,
        ...made,
        before: { zz: 1, ...made.before, aa: 2 },
        changes: made.changes.map((/** @type {any} */ change) => ({ extra: { b: 1, a: 2 }, ...change })),
        alpha: 2,
    }));
    assert.deepEqual(Object.keys(written), [...DELTA_TOP_LEVEL, "alpha", "zeta"]);
    assert.deepEqual(Object.keys(written.before), ["at", "source", "aa", "zz"]);
    assert.deepEqual(Object.keys(written.changes[0]), ["field", "direction", "before", "after", "extra"]);
    assert.deepEqual(Object.keys(written.changes[0].extra), ["a", "b"]);

    const link = written.changes.find((/** @type {any} */ change) => change.field === "chain" && change.direction === "added");
    const withNote = JSON.parse(serializeDelta({ ...made, changes: [{ ...link, after: { note: 1, sha256: link.after.sha256, position: link.after.position } }] }));
    assert.deepEqual(Object.keys(withNote.changes[0].after), ["position", "sha256", "note"]);
});

test("the values of a change keep their own keys, in a fixed order, and arrays keep their order", () => {
    const made = JSON.parse(deltaExample("san-added.json"));
    made.changes.push({ field: "future.field", direction: "changed", before: { z: [3, 1, 2], a: { y: 1, x: 2 } }, after: [{ d: 1, c: 2 }, "b", "a"] });
    const written = JSON.parse(serializeDelta(made)).changes.at(-1);
    assert.deepEqual(Object.keys(written.before), ["a", "z"]);
    assert.deepEqual(Object.keys(written.before.a), ["x", "y"]);
    assert.deepEqual(written.before.z, [3, 1, 2]);
    assert.deepEqual(Object.keys(written.after[0]), ["c", "d"]);
    assert.deepEqual(written.after.slice(1), ["b", "a"]);

    // An Extended Key Usage keeps the order of its list, and an order of the chain keeps its own.
    const eku = JSON.parse(serializeDelta({ ...made, changes: [{ field: "eku", direction: "changed", before: ["serverAuth", "clientAuth"], after: null }] }));
    assert.deepEqual(eku.changes[0].before, ["serverAuth", "clientAuth"]);
    assert.equal(eku.changes[0].after, null);
});

test("a side that is undefined is written as absent, and null is written as a value", () => {
    const text = serializeDelta(/** @type {any} */ ({
        ...JSON.parse(deltaExample("identical.json")),
        changes: [
            { field: "san.dns", direction: "added", before: undefined, after: "a.example" },
            { field: "san.dns", direction: "removed", before: "b.example", after: undefined },
            { field: "key.size", direction: "changed", before: null, after: 2048 },
        ],
    }));
    const { changes } = JSON.parse(text);
    assert.deepEqual(changes, [
        { field: "san.dns", direction: "added", after: "a.example" },
        { field: "san.dns", direction: "removed", before: "b.example" },
        { field: "key.size", direction: "changed", before: null, after: 2048 },
    ]);
    assert.ok(!("before" in changes[0]) && !("after" in changes[1]));
    assert.deepEqual(Object.keys(changes[2]), ["field", "direction", "before", "after"]);
});

test("a Delta ends in one newline and indents with two spaces", () => {
    for (const name of DELTA_EXAMPLES) {
        const text = serializeDelta(JSON.parse(deltaExample(name)));
        assert.ok(text.endsWith("}\n") && !text.endsWith("\n\n"), name);
        assert.ok(!text.includes("\t"), name);
        assert.equal(text, `${JSON.stringify(JSON.parse(text), null, 2)}\n`, name);
    }
});

test("a Delta that contains itself throws a TypeError that says so, and anything but an object does too", () => {
    const made = JSON.parse(deltaExample("san-added.json"));
    made.changes[0].after = made;
    assert.throws(() => serializeDelta(made), { name: "TypeError", message: "the delta contains itself" });

    for (const value of [undefined, null, "{}", 1, [], true]) {
        assert.throws(() => serializeDelta(/** @type {any} */ (value)), { name: "TypeError", message: "the delta must be an object" }, String(value));
    }
    // The other serializers keep their own words.
    assert.throws(() => serializeCheckResult(/** @type {any} */ (null)), { name: "TypeError", message: "the check result must be an object" });
    assert.throws(() => serializeObservation(/** @type {any} */ (null)), { name: "TypeError", message: "the observation must be an object" });
});

test("a Delta repeating the same value is not one that contains itself, and an own __proto__ key and a key that looks like an index survive", () => {
    const made = JSON.parse(deltaExample("san-added.json"));
    const shared = { z: 1 };
    made.changes.push({ field: "future.a", direction: "added", after: shared }, { field: "future.b", direction: "added", after: shared });
    assert.deepEqual(JSON.parse(serializeDelta(made)).changes.at(-1).after, { z: 1 });

    const proto = JSON.parse('{"field":"future.p","direction":"added","after":{"__proto__":"own","2":"b","1":"a"}}');
    const text = serializeDelta({ ...made, changes: [proto] });
    const after = JSON.parse(text).changes[0].after;
    assert.ok(Object.hasOwn(after, "__proto__"));
    assert.equal(after.__proto__, "own");
    assert.equal(serializeDelta({ ...made, changes: [JSON.parse('{"after":{"1":"a","__proto__":"own","2":"b"},"direction":"added","field":"future.p"}')] }), text);
});

test("a toJSON result is used before arranging a Delta, as in the other documents", () => {
    const made = JSON.parse(deltaExample("san-added.json"));
    made.before.at = new Date("2026-09-15T14:02:11Z");
    assert.equal(JSON.parse(serializeDelta(made)).before.at, "2026-09-15T14:02:11.000Z");
});

test("the Delta serializer does not change what the other two write", () => {
    const check = checkExample("pass.json");
    assert.equal(serializeCheckResult(JSON.parse(check)), check);
    assert.equal(serializeObservation(JSON.parse(example("file-single.json"))), example("file-single.json"));
});
