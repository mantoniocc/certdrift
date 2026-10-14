import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { inspect } from "../src/index.js";
import { expectedContents } from "../scripts/package-contents.mjs";

// The private keys among the fixtures, in every form the key match has to meet. Nothing here
// depends on a key's bytes or on a value one derives, because `npm run fixtures` makes new keys:
// a key is compared with the certificate it belongs to, and a file is shown to be the case its
// name says by its first line, its shape and whether Node.js loads it. No test asserts an
// OpenSSL error code or message, since those change between versions. Reading a PEM label or a
// header is reading text, not DER.

const fixturesUrl = new URL("fixtures/", import.meta.url);
const AT = new Date("2026-09-15T14:02:11Z");

/** @param {string} name File name in test/fixtures/. */
const text = (name) => readFileSync(new URL(name, fixturesUrl), "latin1");

/** @param {string} content */
const firstLine = (content) => content.split("\n", 1)[0];

/** The passphrase of the encrypted keys, as the generator wrote it, without the line end. */
const PASSPHRASE = text("test-only-passphrase.txt").replace(/\n$/, "");

const BEGIN_PKCS8 = "-----BEGIN PRIVATE KEY-----";

/**
 * The SPKI SHA-256 of the public key a private key file derives, the way the key match will
 * compare it. Throws when Node.js cannot load the key.
 * @param {string | Buffer} key
 * @param {string | Buffer} [passphrase]
 */
function derivedFrom(key, passphrase) {
    const spki = createPublicKey(createPrivateKey({ key, passphrase })).export({ type: "spki", format: "der" });
    return createHash("sha256").update(spki).digest("hex");
}

/**
 * The `spkiSha256` the observation of a certificate carries.
 * @param {string} name File name of a single certificate in test/fixtures/.
 */
function spkiOf(name) {
    return inspect(readFileSync(new URL(name, fixturesUrl)), { at: AT }).certificates[0].spkiSha256;
}

/** Every readable key that is not PKCS#8 or not unencrypted, with what it needs and what it matches. */
const OTHER_FORMS = [
    { file: "leaf-rsa.pkcs1.key", first: "-----BEGIN RSA PRIVATE KEY-----", certificate: "leaf-rsa.pem", encrypted: false },
    { file: "leaf-p256.sec1.key", first: "-----BEGIN EC PRIVATE KEY-----", certificate: "leaf-p256.pem", encrypted: false },
    { file: "leaf-rsa.pkcs8-encrypted.key", first: "-----BEGIN ENCRYPTED PRIVATE KEY-----", certificate: "leaf-rsa.pem", encrypted: true },
    { file: "leaf-p256.pkcs8-encrypted.key", first: "-----BEGIN ENCRYPTED PRIVATE KEY-----", certificate: "leaf-p256.pem", encrypted: true },
    { file: "leaf-rsa.pkcs1-encrypted.key", first: "-----BEGIN RSA PRIVATE KEY-----", certificate: "leaf-rsa.pem", encrypted: true },
];

const ENCRYPTED = OTHER_FORMS.filter((form) => form.encrypted).map((form) => form.file);

/** Every key file that cannot be read, each for its own reason. */
const UNREADABLE = ["leaf-rsa.truncated.key", "not-a-key.key", "leaf-rsa.certificate.key", "leaf-rsa.public.key", "empty.key"];

test("the generator writes an RSA key in PKCS#1, an EC key in SEC1, both encrypted in PKCS#8 and an RSA key encrypted in the traditional format, each next to the certificate it was converted for", async (t) => {
    for (const { file, first, certificate, encrypted } of OTHER_FORMS) {
        await t.test(file, () => {
            const content = text(file);
            assert.equal(firstLine(content), first);
            assert.ok(existsSync(new URL(certificate, fixturesUrl)), `${certificate} is the certificate this key is for`);
            // The traditional format keeps its cipher in headers; PKCS#8 keeps it inside the body.
            const lines = content.split("\n");
            const traditional = first.startsWith("-----BEGIN RSA ") || first.startsWith("-----BEGIN EC ");
            assert.equal(lines[1] === "Proc-Type: 4,ENCRYPTED", traditional && encrypted, "Proc-Type header");
            assert.equal(/^DEK-Info: /.test(lines[2] ?? ""), traditional && encrypted, "DEK-Info header");
            assert.ok(content.trimEnd().endsWith(first.replace("BEGIN", "END")), "the block is closed");
        });
    }
});

test("each unreadable key is a different case: cut short, a PRIVATE KEY block that is not a key, a certificate, a public key, an empty file and two private keys", async (t) => {
    await t.test("a key cut short is the start of a key without its END line", () => {
        const whole = text("leaf-rsa.key");
        const cut = text("leaf-rsa.truncated.key");
        assert.equal(firstLine(cut), BEGIN_PKCS8);
        assert.ok(cut.length > 0 && cut.length < whole.length, "shorter than the key it was cut from");
        assert.ok(whole.startsWith(cut), "what is left is the beginning of the key");
        assert.ok(!cut.includes("-----END"), "the END line is gone");
    });

    await t.test("a PRIVATE KEY block whose body is not a key is one block around plain text", () => {
        const lines = text("not-a-key.key").trimEnd().split("\n");
        assert.equal(lines[0], BEGIN_PKCS8);
        assert.equal(lines.at(-1), "-----END PRIVATE KEY-----");
        assert.equal(lines.filter((line) => line.startsWith("-----")).length, 2, "one block");
        const body = Buffer.from(lines.slice(1, -1).join(""), "base64").toString("latin1");
        assert.match(body, /^[\x20-\x7e\n]+$/, "the body decodes to text");
    });

    await t.test("a certificate where a key should be is the bytes of a certificate", () => {
        assert.equal(text("leaf-rsa.certificate.key"), text("leaf-rsa.pem"));
        assert.equal(firstLine(text("leaf-rsa.certificate.key")), "-----BEGIN CERTIFICATE-----");
    });

    await t.test("a public key is the public half of a key that matches a certificate", () => {
        const content = text("leaf-rsa.public.key");
        assert.equal(firstLine(content), "-----BEGIN PUBLIC KEY-----");
        const spki = createPublicKey(content).export({ type: "spki", format: "der" });
        assert.equal(createHash("sha256").update(spki).digest("hex"), spkiOf("leaf-rsa.pem"));
    });

    await t.test("an empty file has no bytes", () => {
        assert.equal(text("empty.key"), "");
    });

    await t.test("a file with two private keys holds one key after the other, each matching a different certificate", () => {
        const content = text("two-keys.key");
        assert.equal(content, text("leaf-p256.key") + text("leaf-6-days.key"));
        assert.equal(content.split("\n").filter((line) => line === BEGIN_PKCS8).length, 2);
        assert.notEqual(spkiOf("leaf-p256.pem"), spkiOf("leaf-6-days.pem"));
    });
});

test("the passphrase of the encrypted keys is fixed and public, in test-only-passphrase.txt next to them", () => {
    // It is the same in every regeneration. A file named for test material is what tells a reader
    // that it protects nothing.
    assert.equal(text("test-only-passphrase.txt"), "certdrift-public-test-passphrase\n");
    for (const file of ENCRYPTED) {
        assert.doesNotThrow(() => derivedFrom(text(file), PASSPHRASE), file);
    }
});

test("every certificate among the fixtures keeps its <name>.key in unencrypted PKCS#8, and every end entity its <name>.mismatch.key", async (t) => {
    const names = readdirSync(fixturesUrl)
        .filter((name) => name.endsWith(".pem") && !name.startsWith("bundle-"))
        .map((name) => name.slice(0, -".pem".length))
        .sort();
    assert.ok(names.length >= 25, `expected the single-certificate fixtures, found ${names.length}`);
    let endEntities = 0;
    for (const name of names) {
        await t.test(name, () => {
            const certificate = spkiOf(`${name}.pem`);
            const key = text(`${name}.key`);
            assert.equal(firstLine(key), BEGIN_PKCS8);
            assert.equal(derivedFrom(key), certificate);
            const observation = inspect(readFileSync(new URL(`${name}.pem`, fixturesUrl)), { at: AT });
            if (observation.certificates[0].kind !== "end-entity") return;
            endEntities++;
            const mismatch = text(`${name}.mismatch.key`);
            assert.equal(firstLine(mismatch), BEGIN_PKCS8);
            assert.notEqual(derivedFrom(mismatch), certificate);
        });
    }
    assert.ok(endEntities >= 15, `expected the end entities among the fixtures, found ${endEntities}`);
});

test("each readable key, with its passphrase when it has one, derives its certificate's SPKI SHA-256, each unreadable key fails to load, and the file with two keys loads as its first", async (t) => {
    for (const { file, certificate, encrypted } of OTHER_FORMS) {
        await t.test(`${file} derives the key of ${certificate}`, () => {
            assert.equal(derivedFrom(text(file), encrypted ? PASSPHRASE : undefined), spkiOf(certificate));
        });
    }

    for (const file of UNREADABLE) {
        await t.test(`${file} fails to load, with or without a passphrase`, () => {
            assert.throws(() => derivedFrom(readFileSync(new URL(file, fixturesUrl))));
            assert.throws(() => derivedFrom(readFileSync(new URL(file, fixturesUrl)), PASSPHRASE));
        });
    }

    await t.test("two-keys.key loads, and the key it derives is its first one's", () => {
        const derived = derivedFrom(text("two-keys.key"));
        assert.equal(derived, spkiOf("leaf-p256.pem"));
        assert.notEqual(derived, spkiOf("leaf-6-days.pem"));
    });
});

test("none of the key material is in what the published allowlist packs", () => {
    const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
    const material = readdirSync(fixturesUrl)
        .filter((name) => name.endsWith(".key") || name === "test-only-passphrase.txt")
        .map((name) => `test/fixtures/${name}`);
    assert.ok(material.includes("test/fixtures/two-keys.key") && material.includes("test/fixtures/test-only-passphrase.txt"));
    // The allowlist names no directory the material is in, so none of it is packed.
    const packed = expectedContents(manifest.files, material);
    assert.deepEqual(packed.filter((path) => material.includes(path)), []);
});

// ---------------------------------------------------------------------------------------------
// What the files show about Node.js, for whoever reads the keys

test("an encrypted key fails to load without its passphrase and with a wrong or empty one, while an unencrypted key loads whatever passphrase is given", async (t) => {
    for (const file of ENCRYPTED) {
        await t.test(file, () => {
            const key = text(file);
            assert.doesNotThrow(() => derivedFrom(key, PASSPHRASE));
            assert.throws(() => derivedFrom(key), "no passphrase");
            assert.throws(() => derivedFrom(key, ""), "an empty passphrase");
            assert.throws(() => derivedFrom(key, "not the passphrase"), "a wrong passphrase");
            assert.throws(() => derivedFrom(key, PASSPHRASE.toUpperCase()), "the case matters");
            assert.throws(() => derivedFrom(key, `${PASSPHRASE} `), "so does a space at the end");
        });
    }
    // A passphrase for a key that is not encrypted is ignored, so loading with one proves nothing
    // about whether a file is encrypted: the first line and the headers do.
    for (const file of ["leaf-rsa.key", "leaf-rsa.pkcs1.key", "leaf-p256.sec1.key"]) {
        const expected = derivedFrom(text(file));
        for (const passphrase of ["", "not the passphrase", PASSPHRASE]) {
            assert.equal(derivedFrom(text(file), passphrase), expected, `${file} with ${JSON.stringify(passphrase)}`);
        }
    }
});

test("the passphrase file ends in a line end that a reader must drop: with it, no encrypted key decrypts", () => {
    const raw = text("test-only-passphrase.txt");
    assert.ok(raw.endsWith("\n"));
    for (const file of ENCRYPTED) {
        assert.throws(() => derivedFrom(text(file), raw), file);
        assert.doesNotThrow(() => derivedFrom(text(file), Buffer.from(PASSPHRASE)), `${file}, as a Buffer`);
    }
});

test("today Node.js skips a certificate, a public key, a block that is not a key or plain text before a private key, and loads that key", async (t) => {
    const key = text("leaf-p256.key");
    const before = {
        "a certificate": text("leaf-rsa.certificate.key"),
        "a public key": text("leaf-rsa.public.key"),
        "a PRIVATE KEY block that is not a key": text("not-a-key.key"),
        "plain text": "these are my keys\n",
        "blank lines": "\n\n",
        "a byte order mark": "﻿",
    };
    for (const [what, prefix] of Object.entries(before)) {
        await t.test(what, () => {
            assert.equal(derivedFrom(Buffer.from(prefix + key, "utf8")), spkiOf("leaf-p256.pem"));
        });
    }
    // The same file read the other way is a key with something after it.
    assert.equal(derivedFrom(text("leaf-rsa.certificate.key") + key), derivedFrom(key + text("leaf-rsa.certificate.key")));
    // So a certificate is rejected only when nothing in the file is a key.
    assert.throws(() => derivedFrom(text("leaf-rsa.certificate.key") + text("leaf-rsa.public.key")));
});

test("today an encrypted key followed by an unencrypted one fails without a passphrase, and with one loads as the first", () => {
    const encrypted = text("leaf-rsa.pkcs8-encrypted.key");
    const plain = text("leaf-p256.key");
    assert.throws(() => derivedFrom(encrypted + plain));
    assert.equal(derivedFrom(encrypted + plain, PASSPHRASE), spkiOf("leaf-rsa.pem"));
    // In the other order the first key is the one that loads, and nothing asks for the second's passphrase.
    assert.equal(derivedFrom(plain + encrypted), spkiOf("leaf-p256.pem"));
});

test("today Node.js does not check a PEM label against the body: a PKCS#8 body loads under the traditional label of its own type, and not under another type's or the reverse", () => {
    const rsa = text("leaf-rsa.key");
    const ec = text("leaf-p256.key");
    assert.equal(derivedFrom(rsa.replaceAll("PRIVATE KEY", "RSA PRIVATE KEY")), spkiOf("leaf-rsa.pem"));
    assert.equal(derivedFrom(ec.replaceAll("PRIVATE KEY", "EC PRIVATE KEY")), spkiOf("leaf-p256.pem"));
    assert.throws(() => derivedFrom(ec.replaceAll("PRIVATE KEY", "RSA PRIVATE KEY")));
    assert.throws(() => derivedFrom(text("leaf-rsa.pkcs1.key").replaceAll("RSA PRIVATE KEY", "PRIVATE KEY")));
    assert.throws(() => derivedFrom(text("leaf-p256.sec1.key").replaceAll("EC PRIVATE KEY", "PRIVATE KEY")));
});

test("a key is read with Windows line ends, a byte order mark, text before it and no final line end, encrypted or not", async (t) => {
    const forms = [...OTHER_FORMS, { file: "leaf-rsa.key", certificate: "leaf-rsa.pem", encrypted: false }];
    const variations = {
        "Windows line ends": (/** @type {string} */ key) => key.replaceAll("\n", "\r\n"),
        "a byte order mark": (/** @type {string} */ key) => `﻿${key}`,
        "text before": (/** @type {string} */ key) => `a comment\n${key}`,
        "no final line end": (/** @type {string} */ key) => key.trimEnd(),
    };
    for (const { file, certificate, encrypted } of forms) {
        for (const [what, vary] of Object.entries(variations)) {
            await t.test(`${file} with ${what}`, () => {
                const key = Buffer.from(vary(text(file)), "utf8");
                assert.equal(derivedFrom(key, encrypted ? PASSPHRASE : undefined), spkiOf(certificate));
            });
        }
    }
});

test("a key cut anywhere before its last two bytes fails to load, in the middle or by whole lines, with or without its END line", async (t) => {
    const whole = text("leaf-rsa.key");
    const lines = whole.trimEnd().split("\n");
    const end = lines.at(-1) ?? "";
    const cuts = {
        "half of the bytes": whole.slice(0, whole.length >> 1),
        "half of the bytes and the END line": `${whole.slice(0, whole.length >> 1)}\n${end}\n`,
        "half of the lines": `${lines.slice(0, lines.length >> 1).join("\n")}\n`,
        "half of the lines and the END line": `${lines.slice(0, lines.length >> 1).join("\n")}\n${end}\n`,
        "all but the END line": `${lines.slice(0, -1).join("\n")}\n`,
        "all but the last line of the body": `${[...lines.slice(0, -2), end].join("\n")}\n`,
        "the BEGIN line alone": `${lines[0]}\n`,
    };
    for (const [what, key] of Object.entries(cuts)) {
        await t.test(what, () => assert.throws(() => derivedFrom(key)));
    }
});
