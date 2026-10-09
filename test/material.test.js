import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { X509Certificate } from "node:crypto";
import { inspect, ParseError } from "../src/index.js";

// Node.js reads the first certificate of its input and says nothing about the rest, and it
// repairs input that is not quite PEM or DER. Each test below is a way a certificate could
// vanish or be rewritten on the way in, and pins that the library throws instead.

const fixturesUrl = new URL("fixtures/", import.meta.url);
const AT = new Date("2026-09-15T14:02:11Z");

/** @param {string} name File name in test/fixtures/. */
function fixture(name) {
    return readFileSync(new URL(name, fixturesUrl));
}

/** The text of a PEM fixture without its final line break, so blocks can be joined as wanted. @param {string} name */
function pem(name) {
    return fixture(name).toString("latin1").trim();
}

/** The base64 lines of a one-block PEM fixture. @param {string} name */
function bodyOf(name) {
    return pem(name).split("\n").slice(1, -1).join("\n");
}

/** @param {string} name */
function fingerprint(name) {
    return new X509Certificate(fixture(name)).fingerprint256.replaceAll(":", "").toLowerCase();
}

/** @param {Parameters<typeof inspect>[0]} material */
function hashesOf(material) {
    return inspect(material, { at: AT }).certificates.map((certificate) => certificate.sha256);
}

/**
 * @param {Parameters<typeof inspect>[0]} material
 * @param {number | null} block
 * @param {RegExp} [message]
 */
function assertParseError(material, block, message) {
    assert.throws(() => inspect(material, { at: AT }), (error) => {
        assert.ok(error instanceof ParseError, `expected a ParseError, got ${error}`);
        assert.equal(error.block, block);
        if (block !== null) assert.match(error.message, new RegExp(`input block ${block}\\b`));
        if (message) assert.match(error.message, message);
        return true;
    });
}

const LEAF = pem("leaf-p256.pem");
const MIDDLE = pem("intermediate.pem");
const ROOT = pem("root-ca.pem");

test("two concatenated DER certificates throw instead of dropping the second", () => {
    assertParseError(Buffer.concat([fixture("leaf-p256.der"), new X509Certificate(ROOT).raw]), 1, /bytes after its certificate/);
});

test("bytes after a DER certificate throw instead of being ignored", () => {
    assertParseError(Buffer.concat([fixture("leaf-p256.der"), Buffer.from([0])]), 1, /1 bytes after its certificate/);
    assertParseError(Buffer.concat([fixture("leaf-p256.der"), Buffer.from("junk")]), 1, /4 bytes after its certificate/);
});

// Given a PEM block on a line of its own anywhere in the bytes, Node.js returns that certificate
// and ignores the DER one before it: here the root would be observed in place of the leaf.
test("a PEM block after a DER certificate throws instead of replacing it", () => {
    assertParseError(Buffer.concat([fixture("leaf-p256.der"), Buffer.from(`\n${ROOT}\n`)]), 1, /not exactly one DER-encoded certificate/);
});

test("PEM text hidden after the certificate inside a PEM block throws instead of replacing it", () => {
    const hidden = Buffer.concat([fixture("leaf-p256.der"), Buffer.from(`\n${ROOT}\n`)]);
    const block = `-----BEGIN CERTIFICATE-----\n${hidden.toString("base64").replace(/.{64}/g, "$&\n")}\n-----END CERTIFICATE-----\n`;
    assertParseError(`${block}`, 1, /not exactly one DER-encoded certificate/);
});

test("a DER certificate passed as a string throws, since a string is read as PEM", () => {
    assertParseError(fixture("leaf-p256.der").toString("latin1"), null, /no certificate/);
});

test("a non-DER encoding of a certificate throws instead of being rewritten", async (t) => {
    const der = fixture("leaf-p256.der");

    await t.test("a length written with a leading zero byte", () => {
        const longer = Buffer.concat([Buffer.from([0x30, 0x83, 0x00]), der.subarray(2)]);
        assertParseError(longer, 1, /not exactly one DER-encoded certificate/);
    });

    await t.test("an indefinite length, which Node.js reads as a certificate of the same size", () => {
        const indefinite = Buffer.concat([Buffer.from([0x30, 0x80]), der.subarray(4), Buffer.from([0, 0])]);
        assertParseError(indefinite, 1, /not exactly one DER-encoded certificate/);
    });
});

test("a PEM block without its END line throws instead of absorbing the next block", () => {
    const noEnd = LEAF.replace(/-----END CERTIFICATE-----/, "");
    assertParseError(`${noEnd}\n${MIDDLE}\n`, 1, /no END line/);
});

test("a PEM block cut off at the end of the material throws", () => {
    assertParseError(`${LEAF}\n${MIDDLE.slice(0, MIDDLE.length - 40)}`, 2, /no END line|malformed boundary/);
    assertParseError(`${LEAF}\n-----BEGIN CERTIFICATE-----\n${bodyOf("intermediate.pem")}\n`, 2, /no END line/);
});

test("an END line without its BEGIN line throws instead of hiding the block as text", () => {
    const noBegin = MIDDLE.replace(/-----BEGIN CERTIFICATE-----\n/, "");
    assertParseError(`${LEAF}\n${noBegin}\n`, 2, /END CERTIFICATE line but no BEGIN line/);
});

test("a boundary whose label changes between BEGIN and END throws", () => {
    assertParseError(LEAF.replace("END CERTIFICATE", "END X509 CERTIFICATE"), 1, /begins as CERTIFICATE and ends as X509 CERTIFICATE/);
});

test("a malformed boundary line throws instead of being read as text", async (t) => {
    const malformed = {
        "four dashes": LEAF.replace("-----BEGIN CERTIFICATE-----", "----BEGIN CERTIFICATE-----"),
        "six dashes": LEAF.replace("-----END CERTIFICATE-----", "------END CERTIFICATE-----"),
        "lowercase": LEAF.replace("-----BEGIN CERTIFICATE-----", "-----begin certificate-----"),
        "a space before the closing dashes": LEAF.replace("BEGIN CERTIFICATE-----", "BEGIN CERTIFICATE -----"),
        "no closing dashes": LEAF.replace("BEGIN CERTIFICATE-----", "BEGIN CERTIFICATE"),
        "no label": LEAF.replace("BEGIN CERTIFICATE", "BEGIN"),
        "text after the closing dashes": LEAF.replace("END CERTIFICATE-----", "END CERTIFICATE----- trailing"),
    };
    for (const [name, material] of Object.entries(malformed)) {
        await t.test(name, () => assertParseError(`${material}\n`, 1, /malformed boundary line/));
    }
});

// Word processors and chat tools replace "-" with typographic dashes. A boundary written with
// them is not read, and the block would be ordinary text, so it has to be an error instead.
test("a boundary written with typographic dashes throws instead of being read as text", async (t) => {
    const dashes = { "en dash": "–", "hyphen": "‐", "minus sign": "−", "fullwidth hyphen-minus": "－" };
    for (const [name, dash] of Object.entries(dashes)) {
        const mangled = `${LEAF}\n${MIDDLE.replaceAll("-----", dash.repeat(5))}\n`;
        await t.test(`${name}, as a string`, () => assertParseError(mangled, 2, /malformed boundary line/));
        await t.test(`${name}, as UTF-8 bytes`, () => assertParseError(Buffer.from(mangled, "utf8"), 2, /malformed boundary line/));
    }
});

test("bytes that are not UTF-8 inside a PEM body throw instead of being skipped", () => {
    const [begin, first, ...rest] = LEAF.split("\n");
    const damaged = Buffer.concat([Buffer.from(`${begin}\n${first}\n`), Buffer.from([0xff]), Buffer.from(`\n${rest.join("\n")}\n`)]);
    assertParseError(damaged, 1, /not valid base64/);
});

test("dashes, BEGIN and END on their own are ordinary text", () => {
    const text = [
        "---",
        "-----",
        "BEGIN",
        "END",
        "    Extended master secret: yes",
        "re-ending the pre-begin phase",
        "- END -",
        "-- BEGIN",
    ].join("\n");
    assert.deepEqual(hashesOf(`${text}\n${LEAF}\n${text}\n`), [fingerprint("leaf-p256.pem")]);
});

test("a boundary line is found when text precedes it on the same line", () => {
    assert.deepEqual(hashesOf(`subject=CN = p256.example${LEAF}\n`), [fingerprint("leaf-p256.pem")]);
    assert.deepEqual(hashesOf(LEAF.replace(/\n-----END/, "-----END")), [fingerprint("leaf-p256.pem")]);
});

test("a PEM block holding two certificates throws instead of keeping the first", async (t) => {
    // Whether two bodies glued together are still valid base64 depends on the first certificate's
    // size: a multiple of three has no padding. Fixtures are regenerated with new sizes, so the
    // first certificate is chosen by that property instead of by name.
    const singles = readdirSync(fixturesUrl).filter((name) => /^(leaf|root|intermediate|legacy)[^.]*\.pem$/.test(name)).sort();
    const sizeOf = (/** @type {string} */ name) => new X509Certificate(fixture(name)).raw.length;
    const unpadded = singles.find((name) => sizeOf(name) % 3 === 0);
    const padded = singles.find((name) => sizeOf(name) % 3 !== 0);
    assert.ok(unpadded && padded, "the fixtures must include certificates of both kinds of size");

    await t.test("with no padding in between", () => {
        const joined = `-----BEGIN CERTIFICATE-----\n${bodyOf(unpadded)}\n${bodyOf("intermediate.pem")}\n-----END CERTIFICATE-----\n`;
        assertParseError(joined, 1, /bytes after its certificate/);
    });

    await t.test("with padding in between", () => {
        const joined = `-----BEGIN CERTIFICATE-----\n${bodyOf(padded)}\n${bodyOf("leaf-p256.pem")}\n-----END CERTIFICATE-----\n`;
        assertParseError(joined, 1, /not valid base64/);
    });
});

test("a PEM body with characters outside base64 throws instead of being repaired", async (t) => {
    const lines = bodyOf("leaf-p256.pem").split("\n");
    const withLine = (/** @type {string} */ line) => `-----BEGIN CERTIFICATE-----\n${[lines[0], line, ...lines.slice(2)].join("\n")}\n-----END CERTIFICATE-----\n`;

    await t.test("a stray character", () => assertParseError(withLine(`${lines[1].slice(0, 10)}!${lines[1].slice(11)}`), 1, /not valid base64/));
    await t.test("a header line, as an encrypted key carries", () => assertParseError(withLine("Proc-Type: 4,ENCRYPTED"), 1, /not valid base64/));
    await t.test("a dash", () => assertParseError(withLine(`${lines[1].slice(0, 10)}-${lines[1].slice(11)}`), 1, /not valid base64/));
    await t.test("padding in the middle", () => assertParseError(withLine(`${lines[1].slice(0, 8)}====${lines[1].slice(12)}`), 1, /not valid base64/));
    await t.test("a length that is not a multiple of four", () => assertParseError(withLine(lines[1].slice(1)), 1, /not valid base64/));
});

test("a certificate block with no body throws", () => {
    assertParseError("-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----\n", 1, /is empty/);
    assertParseError("-----BEGIN CERTIFICATE----------END CERTIFICATE-----", 1, /malformed boundary line/);
});

test("labels that are neither read nor known to hold no certificate throw", async (t) => {
    for (const label of ["TRUSTED CERTIFICATE", "PKCS7", "CMS", "PKCS #7 SIGNED DATA", "CERTIFICATE CHAIN", "SOMETHING ELSE"]) {
        await t.test(label, () => {
            const block = `-----BEGIN ${label}-----\nAAAA\n-----END ${label}-----\n`;
            assertParseError(`${LEAF}\n${block}`, 2, new RegExp(label.replace(/[#]/g, ".")));
        });
    }
});

test("keys, requests, revocation lists and parameters are ignored, and still count as input blocks", async (t) => {
    const labels = [
        "PRIVATE KEY",
        "RSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
        "PUBLIC KEY",
        "RSA PUBLIC KEY",
        "CERTIFICATE REQUEST",
        "NEW CERTIFICATE REQUEST",
        "X509 CRL",
        "EC PARAMETERS",
        "DH PARAMETERS",
    ];
    for (const label of labels) {
        await t.test(label, () => {
            const block = `-----BEGIN ${label}-----\nAAAA\n-----END ${label}-----\n`;
            assert.deepEqual(hashesOf(`${block}${LEAF}\n${block}`), [fingerprint("leaf-p256.pem")]);
            // The block before it counts, so a failure in the next one is reported at its place in the file.
            assertParseError(`${block}${LEAF.replace("END CERTIFICATE", "END X509 CERTIFICATE")}\n`, 2, /begins as CERTIFICATE/);
        });
    }

    await t.test("a private key next to its chain", () => {
        const key = readFileSync(new URL("leaf-p256.key", fixturesUrl), "latin1");
        assert.deepEqual(hashesOf(`${key}${LEAF}\n${MIDDLE}\n`), ["leaf-p256.pem", "intermediate.pem"].map(fingerprint));
    });
});

test("material with no certificate block throws", () => {
    assertParseError("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", null, /no certificate/);
    assertParseError("just some text\n---\n", null, /no certificate/);
    assertParseError("   \n\n", null, /no certificate/);
});

test("CRLF and bare CR line endings are read", () => {
    const expected = ["leaf-p256.pem", "intermediate.pem"].map(fingerprint);
    const bundle = `${LEAF}\n${MIDDLE}\n`;
    assert.deepEqual(hashesOf(bundle.replaceAll("\n", "\r\n")), expected);
    assert.deepEqual(hashesOf(bundle.replaceAll("\n", "\r")), expected);
});

test("a certificate whose key Node.js cannot export throws, naming its block, instead of being dropped", () => {
    const der = Buffer.from(fixture("intermediate.pem").toString("latin1").split("\n").filter((line) => line && !line.startsWith("-----")).join(""), "base64");
    // id-ecPublicKey, which appears once, in the SubjectPublicKeyInfo. Changing its last byte names an algorithm OpenSSL does not know.
    const oid = Buffer.from("06072a8648ce3d0201", "hex");
    const at = der.indexOf(oid);
    assert.notEqual(at, -1);
    assert.equal(der.lastIndexOf(oid), at);
    const patched = Buffer.from(der);
    patched[at + oid.length - 1] = 0x09;

    // Node.js still parses it, which is what makes it a certificate that could be skipped.
    assert.doesNotThrow(() => new X509Certificate(patched));

    const block = `-----BEGIN CERTIFICATE-----\n${patched.toString("base64").replace(/.{64}/g, "$&\n")}\n-----END CERTIFICATE-----\n`;
    assert.throws(() => inspect(`${LEAF}\n${block}`, { at: AT }), (error) => {
        assert.ok(error instanceof ParseError);
        assert.equal(error.block, 2);
        assert.match(error.message, /input block 2\b.*public key/);
        assert.ok(error.cause instanceof Error);
        return true;
    });
    assertParseError(patched, 1, /public key/);
});
