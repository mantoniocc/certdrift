import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { X509Certificate, createHash } from "node:crypto";
import { inspect, ParseError } from "../src/index.js";
import { validatorFor } from "./helpers/schema.js";

const fixturesUrl = new URL("fixtures/", import.meta.url);
const errorsOf = validatorFor("observation");
const AT = new Date("2026-09-15T14:02:11Z");

/** @param {string} name File name in test/fixtures/. */
function fixture(name) {
    return readFileSync(new URL(name, fixturesUrl));
}

/**
 * Fingerprint of a certificate fixture, from Node.js itself so that the library is not its own oracle.
 * @param {string} name
 */
function fingerprint(name) {
    return new X509Certificate(fixture(name)).fingerprint256.replaceAll(":", "").toLowerCase();
}

/**
 * The order of the certificates in each bundle, as scripts/generate-certs.sh builds them.
 * Bundles that change meaning once duplicates and ambiguous targets are decided are left out.
 */
const BUNDLES = {
    "bundle-ordered.pem": ["leaf-p256.pem", "intermediate.pem", "root-ca.pem"],
    "bundle-shuffled.pem": ["root-ca.pem", "leaf-p256.pem", "intermediate.pem"],
    "bundle-no-leaf.pem": ["intermediate.pem", "root-ca.pem"],
    "bundle-cross-signed.pem": ["intermediate.pem", "root-ca.pem", "root-ca-cross.pem", "legacy-root.pem"],
};

/** @param {Parameters<typeof inspect>[0]} material */
function hashesOf(material) {
    return inspect(material, { at: AT }).certificates.map((certificate) => certificate.sha256);
}

/** @param {() => unknown} action @param {number | null} block */
function assertParseError(action, block) {
    assert.throws(action, (error) => {
        assert.ok(error instanceof ParseError, `expected a ParseError, got ${error}`);
        assert.equal(error.name, "ParseError");
        assert.equal(error.block, block);
        if (block !== null) assert.match(error.message, new RegExp(`input block ${block}\\b`));
        return true;
    });
}

test("accepts PEM as a string, a Buffer or a Uint8Array and DER as a Buffer or a Uint8Array", async (t) => {
    const expected = [fingerprint("leaf-p256.pem")];
    const pem = fixture("leaf-p256.pem");
    const der = fixture("leaf-p256.der");

    /** A view into the middle of a larger buffer, as a pooled Buffer or a subarray is. */
    const inside = (/** @type {Uint8Array} */ bytes) => {
        const larger = new Uint8Array(bytes.length + 20).fill(0x41);
        larger.set(bytes, 7);
        return larger.subarray(7, 7 + bytes.length);
    };

    const forms = {
        "PEM string": pem.toString("latin1"),
        "PEM Buffer": pem,
        "PEM Uint8Array": new Uint8Array(pem),
        "PEM Uint8Array at an offset": inside(pem),
        "DER Buffer": der,
        "DER Uint8Array": new Uint8Array(der),
        "DER Uint8Array at an offset": inside(der),
    };
    for (const [name, material] of Object.entries(forms)) {
        await t.test(name, () => assert.deepEqual(hashesOf(material), expected));
    }

    await t.test("several PEM blocks concatenated", () => {
        assert.equal(hashesOf(fixture("bundle-ordered.pem")).length, 3);
        assert.equal(hashesOf(fixture("bundle-ordered.pem").toString("latin1")).length, 3);
    });

    await t.test("a type that is neither throws a TypeError that says so", () => {
        const wrong = [undefined, null, 42, {}, ["-----BEGIN CERTIFICATE-----"], new ArrayBuffer(8), new Uint16Array(8), new DataView(new ArrayBuffer(8))];
        for (const material of wrong) {
            assert.throws(
                () => inspect(/** @type {any} */ (material), { at: AT }),
                { name: "TypeError", message: /^material must be a string, a Buffer or a Uint8Array$/ },
            );
        }
    });

    // Nothing here opens a file or a socket: the material is the certificate, never a place to read it from.
    // The imports of src/ are pinned by invariants.test.js.
    await t.test("reads no files and opens no sockets: a path or an address is not a certificate", () => {
        assertParseError(() => inspect(new URL("leaf-p256.pem", fixturesUrl).pathname, { at: AT }), null);
        assertParseError(() => inspect("example.com:443", { at: AT }), null);
    });
});

test("splits the material into PEM blocks before parsing: every certificate of a bundle is observed, in input order", async (t) => {
    // Node.js given a bundle reads only its first block. In bundle-shuffled that block is the root.
    for (const [bundle, members] of Object.entries(BUNDLES)) {
        await t.test(bundle, () => {
            assert.deepEqual(hashesOf(fixture(bundle)), members.map(fingerprint));
        });
    }
});

test("ignores text between PEM blocks, as in the output of openssl s_client -showcerts", () => {
    const blocks = ["leaf-p256.pem", "intermediate.pem"].map((name) => fixture(name).toString("latin1").trim());
    const material = [
        "CONNECTED(00000003)",
        "depth=1 CN = Example Intermediate",
        "verify return:1",
        "---",
        "Certificate chain",
        " 0 s:CN = p256.example",
        "   i:CN = Example Intermediate",
        "   a:PKEY: id-ecPublicKey, 256 (bit); sigalg: ecdsa-with-SHA256",
        blocks[0],
        " 1 s:CN = Example Intermediate",
        "   i:CN = Example Root",
        blocks[1],
        "---",
        "Server certificate",
        "subject=CN = p256.example",
        "issuer=CN = Example Intermediate",
        "---",
        "SSL handshake has read 2535 bytes and written 410 bytes",
        "Verification: OK",
        "---",
        "SSL-Session:",
        "    Protocol  : TLSv1.3",
        "    Extended master secret: yes",
        "---",
        "Verify return code: 0 (ok)",
        "---",
        "",
    ].join("\n");

    assert.deepEqual(hashesOf(material), ["leaf-p256.pem", "intermediate.pem"].map(fingerprint));
});

test("options: source defaults to { kind: \"bytes\" } and at to the moment of the call", async (t) => {
    const pem = fixture("leaf-p256.pem");

    await t.test("defaults", (t) => {
        t.mock.timers.enable({ apis: ["Date"], now: new Date("2026-09-15T14:02:11.789Z") });
        const { observation } = inspect(pem);
        assert.deepEqual(observation, { at: "2026-09-15T14:02:11Z", source: { kind: "bytes" } });
    });

    await t.test("a given at is used, cut to the whole second", () => {
        const { observation } = inspect(pem, { at: new Date("2030-01-02T03:04:05.999Z") });
        assert.equal(observation.at, "2030-01-02T03:04:05Z");
    });

    await t.test("a given source is used, as a copy", () => {
        const source = { kind: "external", ref: "vault:kv/slug/tls", provider: "vault" };
        const result = inspect(pem, { at: AT, source });
        assert.deepEqual(result.observation.source, source);
        source.ref = "changed";
        assert.equal(result.observation.source.ref, "vault:kv/slug/tls");
    });

    await t.test("each call without a source gets its own object", () => {
        const first = inspect(pem, { at: AT }).observation.source;
        first.ref = "changed";
        assert.deepEqual(inspect(pem, { at: AT }).observation.source, { kind: "bytes" });
    });

    await t.test("options of the wrong type throw a TypeError", () => {
        const wrong = [
            { at: "2026-09-15T14:02:11Z" },
            { at: 1789480931000 },
            { at: new Date(NaN) },
            { at: new Date("+010000-01-01T00:00:00Z") },
            { at: new Date("-000001-01-01T00:00:00Z") },
            { source: "file" },
            { source: null },
            { source: [] },
            { source: {} },
            { source: { kind: "" } },
            { source: { kind: 1 } },
        ];
        for (const options of wrong) {
            assert.throws(() => inspect(pem, /** @type {any} */ (options)), TypeError, JSON.stringify(options));
        }
        assert.throws(() => inspect(pem, /** @type {any} */ (null)), TypeError);
        assert.throws(() => inspect(pem, /** @type {any} */ ("at")), TypeError);
    });
});

test("throws a ParseError that says which block failed for empty material, a corrupt PEM block or an invalid DER", async (t) => {
    const bundle = fixture("bundle-ordered.pem").toString("latin1");
    const second = fixture("intermediate.pem").toString("latin1");
    assert.ok(bundle.includes(second), "bundle-ordered.pem must hold intermediate.pem as its second block");

    await t.test("empty material", () => {
        for (const material of ["", Buffer.alloc(0), new Uint8Array(0)]) {
            assertParseError(() => inspect(material, { at: AT }), null);
        }
    });

    await t.test("a PEM block with characters outside base64", () => {
        const corrupt = bundle.replace(second, second.replace(/\n(.{10})/, "\n$1!!"));
        assertParseError(() => inspect(corrupt, { at: AT }), 2);
    });

    await t.test("a PEM block whose bytes are not a certificate carries Node.js's error as the cause", () => {
        const corrupt = bundle.replace(second, second.replace(/(-----BEGIN CERTIFICATE-----\n)[^\n]+/, "$1AAAAAAAA"));
        assert.throws(() => inspect(corrupt, { at: AT }), (error) => {
            assert.ok(error instanceof ParseError);
            assert.equal(error.block, 2);
            assert.match(error.message, /input block 2\b/);
            assert.ok(error.cause instanceof Error);
            return true;
        });
    });

    await t.test("a DER that is cut short", () => {
        const der = fixture("leaf-p256.der");
        assertParseError(() => inspect(der.subarray(0, der.length - 10), { at: AT }), 1);
    });

    await t.test("ParseError is an Error", () => {
        const error = new ParseError("input block 1 is bad", 1, { cause: "why" });
        assert.ok(error instanceof Error);
        assert.deepEqual([error.name, error.block, error.message, error.cause], ["ParseError", 1, "input block 1 is bad", "why"]);
    });
});

// PENDING: bundle-two-leaves.pem leaves this loop once an ambiguous target makes inspect throw.
test("the observation of every fixture validates against the observation schema and holds every certificate", async (t) => {
    const names = readdirSync(fixturesUrl).filter((name) => /\.(pem|der)$/.test(name));
    assert.ok(names.length >= 30, `expected the fixtures, found ${names.length}`);

    for (const name of names) {
        await t.test(name, () => {
            const bytes = fixture(name);
            const observation = inspect(bytes, { at: AT });
            assert.deepEqual(errorsOf(observation), []);

            // The number of certificates in the file, counted without the library.
            const inFile = name.endsWith(".der") ? 1 : bytes.toString("latin1").split("-----BEGIN CERTIFICATE-----").length - 1;
            assert.equal(observation.certificates.length, inFile);
            observation.certificates.forEach((certificate, position) => assert.equal(certificate.index, position));
            assert.ok(observation.target < observation.certificates.length);

            // Survives serialization, so nothing in it needs a custom encoder.
            assert.deepEqual(JSON.parse(JSON.stringify(observation)), observation);
        });
    }
});

test("warnings is always present, as an empty array when there is nothing to warn about", () => {
    const { warnings } = inspect(fixture("leaf-p256.pem"), { at: AT });
    assert.ok(Array.isArray(warnings));
    assert.deepEqual(warnings, []);
});

test("leaf-p256.pem and leaf-p256.der are the same certificate and produce the same sha256", () => {
    const fromPem = inspect(fixture("leaf-p256.pem"), { at: AT }).certificates[0];
    const fromDer = inspect(fixture("leaf-p256.der"), { at: AT }).certificates[0];
    assert.equal(fromPem.sha256, fromDer.sha256);
    assert.equal(fromPem.sha256, fingerprint("leaf-p256.pem"));
    assert.equal(fromPem.spkiSha256, fromDer.spkiSha256);

    const spki = new X509Certificate(fixture("leaf-p256.pem")).publicKey.export({ type: "spki", format: "der" });
    assert.equal(fromPem.spkiSha256, createHash("sha256").update(spki).digest("hex"));
});

test("every test pins at: the observation of given material and at does not depend on the clock", (t) => {
    const material = fixture("bundle-ordered.pem");
    t.mock.timers.enable({ apis: ["Date"], now: new Date("2020-01-01T00:00:00Z") });
    const before = inspect(material, { at: AT });
    t.mock.timers.setTime(new Date("2040-06-07T08:09:10Z").getTime());
    const after = inspect(material, { at: AT });
    assert.deepEqual(after, before);
    assert.equal(after.observation.at, "2026-09-15T14:02:11Z");
});
