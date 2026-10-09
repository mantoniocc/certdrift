import { test, mock } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { inspect, ParseError } from "../src/index.js";
import { validatorFor } from "./helpers/schema.js";

const fixturesUrl = new URL("fixtures/", import.meta.url);
const errorsOf = validatorFor("observation");
const AT = new Date("2026-10-08T12:00:00Z");

/** @param {string} name File name in test/fixtures/. */
function fixture(name) {
    return readFileSync(new URL(name, fixturesUrl));
}

/**
 * The PEM blocks of a fixture, one string each.
 * @param {string} name
 */
function blocksOf(name) {
    return fixture(name).toString("utf8").match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
}

/** @param {() => unknown} run @param {number | null} block */
function assertParseError(run, block) {
    assert.throws(run, (error) => {
        assert.ok(error instanceof ParseError, `expected a ParseError, got ${error}`);
        assert.equal(error.name, "ParseError");
        assert.equal(error.block, block);
        return true;
    });
}

const certificateFixtures = readdirSync(fixturesUrl).filter((name) => /\.(pem|der)$/.test(name));

test("the scan finds the certificate fixtures", () => {
    assert.ok(certificateFixtures.includes("leaf-p256.pem") && certificateFixtures.includes("leaf-p256.der"));
});

// bundle-two-leaves.pem is included on purpose: it validates until the chain issue makes the
// library refuse it as ambiguous, and that issue must take it out of this loop.
for (const name of certificateFixtures) {
    test(`${name}: the observation validates and holds one certificate per block`, () => {
        const observation = inspect(fixture(name), { at: AT });
        assert.deepEqual(errorsOf(observation), []);
        const expected = name.endsWith(".der") ? 1 : blocksOf(name).length;
        assert.equal(observation.certificates.length, expected);
        observation.certificates.forEach((certificate, position) => assert.equal(certificate.index, position));
    });
}

test("a shuffled bundle yields every certificate, not only the first block", () => {
    const observation = inspect(fixture("bundle-shuffled.pem"), { at: AT });
    assert.equal(observation.certificates.length, 3);
    assert.ok(observation.certificates.some((certificate) => certificate.kind === "end-entity"));
    assert.ok(observation.certificates.some((certificate) => certificate.subject.cn === "p256.example"));
});

test("leaf-p256.pem and leaf-p256.der are the same certificate", () => {
    const fromPem = inspect(fixture("leaf-p256.pem"), { at: AT });
    const fromDer = inspect(fixture("leaf-p256.der"), { at: AT });
    assert.equal(fromPem.certificates[0].sha256, fromDer.certificates[0].sha256);
    assert.deepEqual(fromPem, fromDer);
});

test("a string, a Buffer and a Uint8Array give the same observation", () => {
    const buffer = fixture("bundle-ordered.pem");
    const expected = inspect(buffer, { at: AT });
    assert.deepEqual(inspect(buffer.toString("utf8"), { at: AT }), expected);
    assert.deepEqual(inspect(new Uint8Array(buffer), { at: AT }), expected);
    // A view into a larger buffer must not read the bytes around it.
    const padded = Buffer.concat([Buffer.from("junk"), buffer, Buffer.from("junk")]);
    assert.deepEqual(inspect(padded.subarray(4, 4 + buffer.length), { at: AT }), expected);
});

test("text between PEM blocks is ignored", () => {
    const [leaf, intermediate] = blocksOf("bundle-ordered.pem");
    const showcerts = [
        "CONNECTED(00000003)",
        "---",
        "Certificate chain",
        " 0 s:CN = p256.example",
        "   i:CN = certdrift test intermediate CA",
        leaf,
        " 1 s:CN = certdrift test intermediate CA",
        intermediate,
        "---",
        "Server certificate",
        "",
    ].join("\n");
    const observation = inspect(showcerts, { at: AT });
    assert.deepEqual(errorsOf(observation), []);
    assert.deepEqual(
        observation.certificates.map((certificate) => certificate.subject.cn),
        ["p256.example", "certdrift test intermediate CA"],
    );
});

test("PEM blocks that are not certificates are ignored", () => {
    const withKey = `${fixture("leaf-p256.pem")}\n${fixture("leaf-p256.key")}`;
    assert.equal(inspect(withKey, { at: AT }).certificates.length, 1);
});

test("CRLF line endings are accepted", () => {
    const text = fixture("bundle-ordered.pem").toString("utf8").replaceAll("\n", "\r\n");
    assert.equal(inspect(text, { at: AT }).certificates.length, 3);
});

test("source defaults to bytes and `at` is used as given", () => {
    const observation = inspect(fixture("leaf-p256.pem"), { at: AT });
    assert.deepEqual(observation.observation, { at: "2026-10-08T12:00:00Z", source: { kind: "bytes" } });
});

test("source keeps only the fields the contract defines", () => {
    const source = { kind: "file", ref: "api.pem", unknown: "dropped" };
    const observation = inspect(fixture("leaf-p256.pem"), { at: AT, source });
    assert.deepEqual(observation.observation.source, { kind: "file", ref: "api.pem" });
    assert.deepEqual(errorsOf(observation), []);
});

test("`at` defaults to the moment of the call, with second precision", () => {
    mock.timers.enable({ apis: ["Date"], now: new Date("2026-10-08T12:00:00.987Z") });
    try {
        const observation = inspect(fixture("leaf-p256.pem"));
        assert.equal(observation.observation.at, "2026-10-08T12:00:00Z");
    } finally {
        mock.timers.reset();
    }
});

test("warnings is always present, empty when there is nothing to report", () => {
    const observation = inspect(fixture("leaf-p256.pem"), { at: AT });
    assert.deepEqual(observation.warnings, []);
});

test("lifetimeFraction is null when the validity period has no duration", () => {
    const { derived } = inspect(fixture("leaf-zero-validity.pem"), { at: AT }).certificates[0];
    assert.equal(derived.lifetimeFraction, null);
    assert.deepEqual(errorsOf(inspect(fixture("leaf-zero-validity.pem"), { at: AT })), []);
});

test("an expired certificate has negative days remaining and a fraction above 1", () => {
    const { derived } = inspect(fixture("leaf-expired.pem"), { at: AT }).certificates[0];
    assert.ok(derived.daysRemaining < 0);
    assert.ok(derived.lifetimeFraction !== null && derived.lifetimeFraction > 1);
});

test("a certificate without a subject has an empty dn and a null cn", () => {
    const { subject } = inspect(fixture("leaf-no-cn.pem"), { at: AT }).certificates[0];
    assert.deepEqual(subject, { cn: null, dn: "" });
});

test("key fields serialize: an RSA observation survives JSON.stringify", () => {
    const observation = inspect(fixture("leaf-rsa.pem"), { at: AT });
    assert.deepEqual(JSON.parse(JSON.stringify(observation)), observation);
});

test("empty material throws a ParseError", () => {
    assertParseError(() => inspect("", { at: AT }), null);
    assertParseError(() => inspect("  \n", { at: AT }), null);
    assertParseError(() => inspect(Buffer.alloc(0), { at: AT }), null);
    assertParseError(() => inspect(new Uint8Array(0), { at: AT }), null);
});

test("material without a certificate throws a ParseError", () => {
    assertParseError(() => inspect("hello", { at: AT }), null);
    assertParseError(() => inspect(fixture("leaf-p256.key"), { at: AT }), null);
});

test("a corrupt PEM block throws a ParseError that names the block", () => {
    const [first, second, third] = blocksOf("bundle-ordered.pem");
    const lines = second.split("\n");
    lines[1] = `!!!!${lines[1].slice(4)}`;
    const text = [first, lines.join("\n"), third].join("\n");
    assert.throws(() => inspect(text, { at: AT }), (error) => {
        assert.ok(error instanceof ParseError);
        assert.equal(error.block, 2);
        assert.match(error.message, /input block 2\b/);
        assert.ok(error.cause instanceof Error);
        return true;
    });
});

test("a truncated PEM block and a block without its END line throw a ParseError", () => {
    const [first, second] = blocksOf("bundle-ordered.pem");
    const lines = second.split("\n");
    const truncated = [lines[0], ...lines.slice(1, 3), lines.at(-1)].join("\n");
    assertParseError(() => inspect(`${first}\n${truncated}`, { at: AT }), 2);
    assertParseError(() => inspect(`${first}\n${lines.slice(0, -1).join("\n")}`, { at: AT }), 2);
});

test("an invalid DER throws a ParseError", () => {
    const der = fixture("leaf-p256.der");
    assertParseError(() => inspect(der.subarray(0, der.length - 10), { at: AT }), 1);
    assertParseError(() => inspect(Buffer.from([1, 2, 3, 4]), { at: AT }), 1);
});

test("wrong argument types throw a TypeError, not a ParseError", () => {
    // @ts-expect-error material must be a string or bytes
    assert.throws(() => inspect(42, { at: AT }), TypeError);
    assert.throws(() => inspect(fixture("leaf-p256.pem"), { at: new Date("nope") }), TypeError);
    // @ts-expect-error at must be a Date
    assert.throws(() => inspect(fixture("leaf-p256.pem"), { at: "2026-10-08T12:00:00Z" }), TypeError);
});
