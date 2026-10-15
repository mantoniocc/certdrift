import { test } from "node:test";
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import * as library from "../src/index.js";
import { holdsPrivateKey } from "../scripts/package-contents.mjs";
import { validatorFor } from "./helpers/schema.js";
import { PASSPHRASE, REASON, block, bytes, matchesPrivateKey, observationOf, text } from "./helpers/keys.js";

// `matchesPrivateKey(observation, privateKey, options)`: whether a private key is the key of the
// certificate an observation targets, and why not when it cannot be said. No test asserts a key's
// bytes, an OpenSSL error code or message: `npm run fixtures` makes new keys, and those change
// between OpenSSL versions.

const errorsOf = validatorFor("check-result");

/** Every algorithm among the fixtures, with a certificate, its key and the key that is not its. */
const ALGORITHMS = ["leaf-rsa", "leaf-rsa-pss", "leaf-p256", "leaf-p384", "leaf-p521", "leaf-brainpool", "leaf-ed25519", "leaf-ml-dsa-44", "leaf-sm2"];

const P256 = observationOf("leaf-p256.pem");

/** A check result around one result, so that the schema can say whether it is one. @param {any} result @param {any} [observation] */
function wrapped(result, observation = P256) {
    return {
        contract: 1,
        now: observation.observation.at,
        summary: { status: result.status, pass: result.status === "pass" ? 1 : 0, warn: result.status === "warn" ? 1 : 0, fail: result.status === "fail" ? 1 : 0 },
        results: [result],
        policy: { contract: 1, validityStarted: { severity: "fail" }, validityNotEnded: { severity: "fail" }, matchesPrivateKey: { severity: "fail" } },
        observation,
    };
}

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

/** The result for a file given as text, against the P-256 certificate. @param {string | Uint8Array} material @param {string} [passphrase] @param {any} [options] */
const resultFor = (material, passphrase, options) => matchesPrivateKey(P256, { material, passphrase }, options);

/** A result of an unreadable key: only these properties, and none of the public values. @param {any} result @param {string} message @param {string} [status] */
function assertUnreadable(result, message, status = "fail") {
    assert.deepEqual(result, { code: "KEY_UNREADABLE", status, rule: { name: "matchesPrivateKey" }, message });
    assert.equal("actual" in result || "expected" in result, false);
}

// ---------------------------------------------------------------------------------------------
// The function and its result

test("matchesPrivateKey is exported from the entry point and returns one result for the rule matchesPrivateKey in the shape of any result, which validates inside a check result", () => {
    assert.equal(typeof library.matchesPrivateKey, "function");
    for (const key of ["leaf-p256.key", "leaf-rsa.key", "two-keys.key", "leaf-p256.pkcs8-encrypted.key"]) {
        const result = resultFor(text(key));
        assert.deepEqual(Object.keys(result).slice(0, 4), ["code", "status", "rule", "message"], key);
        assert.deepEqual(result.rule, { name: "matchesPrivateKey" });
        assert.deepEqual(errorsOf(wrapped(result)), [], key);
    }
});

test("options.severity is fail unless it says warn, and a word that is neither is a TypeError", () => {
    const mismatch = (/** @type {any} */ options) => resultFor(text("leaf-p256.mismatch.key"), undefined, options).status;
    const unreadable = (/** @type {any} */ options) => resultFor("", undefined, options).status;
    for (const options of [undefined, {}, { severity: undefined }, { severity: "fail" }]) {
        assert.equal(mismatch(options), "fail", JSON.stringify(options));
        assert.equal(unreadable(options), "fail", JSON.stringify(options));
    }
    assert.equal(mismatch({ severity: "warn" }), "warn");
    assert.equal(unreadable({ severity: "warn" }), "warn");
    // A key that matches passes whatever the severity.
    assert.equal(resultFor(text("leaf-p256.key"), undefined, { severity: "warn" }).status, "pass");
    assert.equal(resultFor(text("leaf-p256.key"), undefined, { severity: "fail" }).status, "pass");

    for (const severity of ["WARN", "warning", "", "loud", null, 0, true, {}, ["warn"]]) {
        assert.throws(() => resultFor(text("leaf-p256.key"), undefined, { severity }), { name: "TypeError", message: `options.severity must be "fail" or "warn"` }, String(severity));
    }
    for (const options of [null, 5, "warn", true]) {
        assert.throws(() => resultFor(text("leaf-p256.key"), undefined, options), { name: "TypeError", message: "options must be an object" });
    }
});

// ---------------------------------------------------------------------------------------------
// A key that was read

test("the key matches when the SHA-256 of the SPKI derived from the private key equals the target's spkiSha256, for every algorithm among the fixtures, and the mismatch key does not", async (t) => {
    for (const name of ALGORITHMS) {
        await t.test(name, () => {
            // Through JSON, so that the observation holds no certificate, only what it says.
            const observation = JSON.parse(library.serializeObservation(observationOf(`${name}.pem`)));
            const target = observation.certificates[observation.target];

            const matched = matchesPrivateKey(observation, { material: text(`${name}.key`) });
            assert.equal(matched.code, "KEY_MISMATCH");
            assert.equal(matched.status, "pass");
            assert.equal(matched.actual, target.spkiSha256);
            assert.equal(matched.expected, target.spkiSha256);
            assert.equal(matched.message, "the private key corresponds to the certificate's public key");

            // The derivation, written again here from Node.js alone.
            const spki = createPublicKey(createPrivateKey(text(`${name}.key`))).export({ type: "spki", format: "der" });
            assert.equal(matched.actual, createHash("sha256").update(spki).digest("hex"));

            const other = matchesPrivateKey(observation, { material: text(`${name}.mismatch.key`) });
            assert.equal(other.code, "KEY_MISMATCH");
            assert.equal(other.status, "fail");
            assert.notEqual(other.actual, target.spkiSha256);
            assert.match(other.actual, /^[0-9a-f]{64}$/);
            assert.equal(other.expected, target.spkiSha256);
            assert.equal(other.message, "the private key does not correspond to the certificate's public key");
        });
    }
});

test("a key that was read gives KEY_MISMATCH: pass when it matches and the status of the severity when it does not, with the key's public hash as actual and the target's as expected", () => {
    const warned = resultFor(text("leaf-rsa.key"), undefined, { severity: "warn" });
    assert.deepEqual(warned, {
        code: "KEY_MISMATCH",
        status: "warn",
        rule: { name: "matchesPrivateKey" },
        message: "the private key does not correspond to the certificate's public key",
        actual: observationOf("leaf-rsa.pem").certificates[0].spkiSha256,
        expected: P256.certificates[0].spkiSha256,
    });
    assert.deepEqual(errorsOf(wrapped(warned)), []);
    const failed = resultFor(text("leaf-rsa.key"));
    assert.equal(failed.status, "fail");
    assert.deepEqual(errorsOf(wrapped(failed)), []);
    const passed = resultFor(text("leaf-p256.key"));
    assert.deepEqual(Object.keys(passed), ["code", "status", "rule", "message", "actual", "expected"]);
    assert.deepEqual(errorsOf(wrapped(passed)), []);
});

test("PKCS#1 and SEC1 keys match, and so do encrypted keys in PKCS#8 and in the traditional format with the passphrase of test-only-passphrase.txt", async (t) => {
    const forms = [
        ["leaf-rsa.pkcs1.key", "leaf-rsa.pem", undefined],
        ["leaf-p256.sec1.key", "leaf-p256.pem", undefined],
        ["leaf-rsa.pkcs8-encrypted.key", "leaf-rsa.pem", PASSPHRASE],
        ["leaf-p256.pkcs8-encrypted.key", "leaf-p256.pem", PASSPHRASE],
        ["leaf-rsa.pkcs1-encrypted.key", "leaf-rsa.pem", PASSPHRASE],
    ];
    for (const [key, certificate, passphrase] of forms) {
        await t.test(key, () => {
            const result = matchesPrivateKey(observationOf(certificate ?? ""), { material: text(key ?? ""), passphrase });
            assert.equal(result.code, "KEY_MISMATCH");
            assert.equal(result.status, "pass");
        });
    }
    // An unencrypted key loads with any passphrase, so a passphrase for it is harmless.
    for (const passphrase of ["", "not the passphrase", PASSPHRASE]) {
        assert.equal(resultFor(text("leaf-p256.key"), passphrase).status, "pass", JSON.stringify(passphrase));
    }
});

test("a key with CRLF line ends, with a byte order mark and with text before the block is read, encrypted or not, as text or as bytes", async (t) => {
    const forms = [
        ["leaf-rsa.key", "leaf-rsa.pem", undefined],
        ["leaf-rsa.pkcs1.key", "leaf-rsa.pem", undefined],
        ["leaf-p256.sec1.key", "leaf-p256.pem", undefined],
        ["leaf-rsa.pkcs8-encrypted.key", "leaf-rsa.pem", PASSPHRASE],
        ["leaf-rsa.pkcs1-encrypted.key", "leaf-rsa.pem", PASSPHRASE],
    ];
    const variations = {
        "Windows line ends": (/** @type {string} */ key) => key.replaceAll("\n", "\r\n"),
        "a byte order mark": (/** @type {string} */ key) => `\uFEFF${key}`,
        "a byte order mark and Windows line ends": (/** @type {string} */ key) => `\uFEFF${key.replaceAll("\n", "\r\n")}`,
        "text before the block": (/** @type {string} */ key) => `these are my keys\n${key}`,
        "blank lines before the block": (/** @type {string} */ key) => `\n\n${key}`,
        "text after the block": (/** @type {string} */ key) => `${key}the end\n`,
        "no final line end": (/** @type {string} */ key) => key.trimEnd(),
        "spaces after the BEGIN line": (/** @type {string} */ key) => key.replace("KEY-----\n", "KEY----- \t\n"),
    };
    for (const [key, certificate, passphrase] of forms) {
        const observation = observationOf(certificate ?? "");
        for (const [what, vary] of Object.entries(variations)) {
            await t.test(`${key} with ${what}`, () => {
                const material = vary(text(key ?? ""));
                for (const given of [material, Buffer.from(material, "utf8"), new Uint8Array(Buffer.from(material, "utf8"))]) {
                    const result = matchesPrivateKey(observation, { material: given, passphrase });
                    assert.equal(result.code, "KEY_MISMATCH", `${typeof given}`);
                    assert.equal(result.status, "pass");
                }
            });
        }
    }
});

test("a key written the way other tools write it is read: the attributes of openssl pkcs12, a body that is indented or has blank lines, and lines that are not text before it", async (t) => {
    const key = text("leaf-p256.key");
    /** @type {Record<string, string>} */
    const forms = {
        "the attributes openssl pkcs12 prints": `Bag Attributes\n    localKeyID: 01 02 03\nKey Attributes: <No Attributes>\n${key}`,
        "the certificate and its key as openssl pkcs12 prints them": `Bag Attributes\n    friendlyName: x\nsubject=CN = x\nissuer=CN = y\n${text("leaf-p256.pem")}Bag Attributes\n${key}`,
        "a line with a NUL before": `\0\n${key}`,
        "a line with a lone surrogate before": `\ud800\n${key}`,
        "a body indented with tabs": key.replace(/^(?!-----)(.)/gm, "\t$1"),
        "a body indented with spaces": key.replace(/^(?!-----)(.)/gm, "  $1"),
        "a blank line inside the body": key.replace("\n", "\n\n"),
        "white space at the end of every line": key.replaceAll("\n", " \n"),
        "a NUL after the END line": `${key}\0`,
    };
    for (const [what, material] of Object.entries(forms)) {
        await t.test(what, () => {
            assert.doesNotThrow(() => createPrivateKey({ key: material, format: "pem" }), "Node.js reads it");
            assert.equal(resultFor(material).status, "pass");
            assert.equal(resultFor(Buffer.from(material, "utf8")).status, "pass");
        });
    }
});

test("the target of the observation is the certificate the key is checked against, whatever its place, and a CA certificate has a key like any other", () => {
    // The leaf is not the first certificate of the bundle, and the observation says which one it is.
    const bundle = observationOf("bundle-shuffled.pem");
    assert.notEqual(bundle.target, 0);
    assert.equal(matchesPrivateKey(bundle, { material: text("leaf-p256.key") }).status, "pass");
    assert.equal(matchesPrivateKey(bundle, { material: text("root-ca.key") }).status, "fail");
    for (const name of ["root-ca", "intermediate", "selfsigned-leaf"]) {
        assert.equal(matchesPrivateKey(observationOf(`${name}.pem`), { material: text(`${name}.key`) }).status, "pass", name);
    }
    assert.equal(matchesPrivateKey(observationOf("intermediate.pem"), { material: text("root-ca.key") }).status, "fail");
});

test("bytes that are a view into a larger buffer are read as the view and not as the buffer", () => {
    const key = Buffer.from(text("leaf-p256.key"));
    const around = Buffer.concat([Buffer.from("-----BEGIN PRIVATE KEY-----\njunk\n"), key, Buffer.from("-----BEGIN PRIVATE KEY-----\njunk\n")]);
    const view = around.subarray(around.indexOf(key), around.indexOf(key) + key.length);
    assert.equal(resultFor(view).status, "pass");
    assert.equal(resultFor(around).code, "KEY_UNREADABLE", "the whole buffer holds three blocks");
});

// ---------------------------------------------------------------------------------------------
// A key that could not be read

test("a key that could not be read gives KEY_UNREADABLE with the status of the severity, no actual and no expected, and a fixed message for each reason", async (t) => {
    const encrypted = ["leaf-rsa.pkcs8-encrypted.key", "leaf-p256.pkcs8-encrypted.key", "leaf-rsa.pkcs1-encrypted.key"];
    /** @type {[string, string | Uint8Array, string | undefined, string][]} */
    const cases = [
        ["empty.key", text("empty.key"), undefined, REASON.noKey],
        ["not-a-key.key", text("not-a-key.key"), undefined, REASON.unsupported],
        ["leaf-rsa.truncated.key", text("leaf-rsa.truncated.key"), undefined, REASON.unsupported],
        ["leaf-rsa.public.key", text("leaf-rsa.public.key"), undefined, REASON.publicKey],
        ["leaf-rsa.certificate.key", text("leaf-rsa.certificate.key"), undefined, REASON.certificate],
        ["two-keys.key", text("two-keys.key"), undefined, REASON.several],
        ...encrypted.map(/** @returns {[string, string, undefined, string]} */ (file) => [`${file} without a passphrase`, text(file), undefined, REASON.encrypted]),
        ...encrypted.map(/** @returns {[string, string, string, string]} */ (file) => [`${file} with a wrong passphrase`, text(file), "not the passphrase", REASON.decrypt]),
        ...encrypted.map(/** @returns {[string, string, string, string]} */ (file) => [`${file} with an empty passphrase`, text(file), "", REASON.decrypt]),
        ...encrypted.map(/** @returns {[string, string, string, string]} */ (file) => [`${file} with its passphrase in another case`, text(file), PASSPHRASE.toUpperCase(), REASON.decrypt]),
        ["a certificate chain", text("bundle-ordered.pem"), undefined, REASON.certificate],
        ["plain text", "these are my keys\n", undefined, REASON.noKey],
        ["only blank lines", "\n\r\n \n", undefined, REASON.noKey],
    ];
    for (const [what, material, passphrase, message] of cases) {
        await t.test(what, () => {
            assertUnreadable(resultFor(material, passphrase), message);
            assertUnreadable(resultFor(material, passphrase, { severity: "warn" }), message, "warn");
            assertUnreadable(resultFor(typeof material === "string" ? Buffer.from(material) : material, passphrase), message);
            assert.deepEqual(errorsOf(wrapped(resultFor(material, passphrase))), []);
        });
    }
});

test("only PEM is read: a DER key, a binary file and a text in UTF-16 are KEY_UNREADABLE because their format is not supported, and not because they hold no key", () => {
    const der = createPrivateKey(text("leaf-p256.key")).export({ format: "der", type: "pkcs8" });
    assertUnreadable(resultFor(der), REASON.unsupported);
    assertUnreadable(resultFor(Buffer.from([0x30, 0x82, 0x0a, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0d, 0xff, 0xfe])), REASON.unsupported);
    assertUnreadable(resultFor(Buffer.from(`\uFEFF${text("leaf-p256.key")}`, "utf16le")), REASON.unsupported);
    // A DER certificate has no PEM block either.
    assertUnreadable(resultFor(bytes("leaf-p256.der")), REASON.unsupported);
    // Text with no block is not binary, and says so.
    assertUnreadable(resultFor("0w\t\n\r hello"), REASON.noKey);
});

test("the reason comes from the labels of the blocks and never from what is inside one", () => {
    // The same error code from Node.js (checked below), four different reasons.
    const files = { certificate: text("leaf-rsa.certificate.key"), publicKey: text("leaf-rsa.public.key"), noKey: "", unsupported: text("leaf-rsa.truncated.key") };
    for (const material of Object.values(files)) assert.throws(() => createPrivateKey(material));
    const codes = new Set(Object.values(files).map((material) => {
        try {
            createPrivateKey(material);
        } catch (error) {
            return /** @type {any} */ (error).code;
        }
    }));
    assert.equal(codes.size, 1, "Node.js cannot tell them apart");
    assert.deepEqual(Object.values(files).map((material) => resultFor(material).message), [REASON.certificate, REASON.publicKey, REASON.noKey, REASON.unsupported]);

    // A block that holds nothing like a certificate or a key is what its label says.
    assertUnreadable(resultFor(block("CERTIFICATE", "this is not a certificate")), REASON.certificate);
    assertUnreadable(resultFor(block("PUBLIC KEY", "this is not a key")), REASON.publicKey);
    assertUnreadable(resultFor(block("PRIVATE KEY", "this is not a key")), REASON.unsupported);
    // The labels OpenSSL writes for a certificate and for a public key.
    for (const label of ["CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE"]) assertUnreadable(resultFor(block(label)), REASON.certificate);
    for (const label of ["PUBLIC KEY", "RSA PUBLIC KEY"]) assertUnreadable(resultFor(block(label)), REASON.publicKey);
    // Other blocks hold neither.
    for (const label of ["CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST", "X509 CRL", "EC PARAMETERS", "DH PARAMETERS", "PKCS7", "CERTIFICATE PAIR"]) {
        assertUnreadable(resultFor(block(label)), REASON.noKey);
    }
    // A label is read as OpenSSL writes it.
    for (const label of ["private key", "Private Key", "PRIVATE  KEY", "PRIVATE KEYS", "PRIVATE KEY X", "KEY", "certificate", "rsa PRIVATE KEY", "MY-CERTIFICATE", "rsa CERTIFICATE", "CERTIFICATES", "CERTIFICATE X", "MY-PUBLIC KEY", "rsa PUBLIC KEY", "PUBLIC KEYS", "PUBLIC KEY X", "public key"]) {
        assertUnreadable(resultFor(block(label)), REASON.noKey);
    }
});

test("an encrypted key is one whose label is ENCRYPTED PRIVATE KEY or whose first line after BEGIN is Proc-Type: 4,ENCRYPTED, and the header is read as OpenSSL reads it", () => {
    const traditional = text("leaf-rsa.pkcs1-encrypted.key");
    assertUnreadable(resultFor(traditional), REASON.encrypted);
    // Windows line ends, spaces at the end and a space after the comma are accepted by Node.js and by this.
    assertUnreadable(resultFor(traditional.replaceAll("\n", "\r\n")), REASON.encrypted);
    assertUnreadable(resultFor(traditional.replace("ENCRYPTED\n", "ENCRYPTED \t\n")), REASON.encrypted);
    assertUnreadable(resultFor(traditional.replace("4,ENCRYPTED", "4, ENCRYPTED")), REASON.encrypted);
    assert.equal(matchesPrivateKey(observationOf("leaf-rsa.pem"), { material: traditional.replace("4,ENCRYPTED", "4, ENCRYPTED"), passphrase: PASSPHRASE }).status, "pass", "Node.js reads it");
    // Not encrypted for OpenSSL: not first, not the same case, not a key that is encrypted.
    assertUnreadable(resultFor(traditional.replace("KEY-----\n", "KEY-----\n\n")), REASON.unsupported);
    assertUnreadable(resultFor(traditional.replace("Proc-Type", "proc-type")), REASON.unsupported);
    assertUnreadable(resultFor(traditional.replace("4,ENCRYPTED", "4,MIC-ONLY")), REASON.unsupported);
    // A label of another case or another kind of key is not the label of an encrypted key.
    assertUnreadable(resultFor(block("ENCRYPTED PRIVATE KEY", "AAAA")), REASON.encrypted);
    assertUnreadable(resultFor(block("ENCRYPTED PRIVATE KEY", "AAAA"), "x"), REASON.decrypt);
    assertUnreadable(resultFor(block("RSA PRIVATE KEY", "AAAA"), "x"), REASON.unsupported);
    assertUnreadable(resultFor(block("X ENCRYPTED PRIVATE KEY", "AAAA")), REASON.unsupported);
    assertUnreadable(resultFor(block("ENCRYPTED RSA PRIVATE KEY", "AAAA")), REASON.unsupported);
    assertUnreadable(resultFor(block("ENCRYPTED PRIVATE KEYS", "AAAA")), REASON.noKey);
    // A BEGIN line that ends the text has no header to read.
    assertUnreadable(resultFor("-----BEGIN PRIVATE KEY-----"), REASON.unsupported);
    assertUnreadable(resultFor("-----BEGIN RSA PRIVATE KEY-----"), REASON.unsupported);
    // The header of a block that is not the first one decides nothing: the first is the one read.
    assertUnreadable(resultFor(`${block("PRIVATE KEY")}${traditional}`), REASON.several);
});

// ---------------------------------------------------------------------------------------------
// More than one private key, and what is skipped

test("a file with more than one private key block is KEY_UNREADABLE, even when the first one is encrypted and unreadable", () => {
    const encrypted = text("leaf-rsa.pkcs8-encrypted.key");
    const plain = text("leaf-p256.key");
    assertUnreadable(resultFor(plain + text("leaf-6-days.key")), REASON.several);
    assertUnreadable(resultFor(text("two-keys.key"), PASSPHRASE), REASON.several);
    assertUnreadable(resultFor(encrypted + plain), REASON.several);
    assertUnreadable(resultFor(encrypted + plain, PASSPHRASE), REASON.several);
    assertUnreadable(resultFor(plain + encrypted, "x"), REASON.several);
    assertUnreadable(resultFor(`${plain}\n${text("leaf-p256.sec1.key")}`), REASON.several);
    assertUnreadable(resultFor(`${plain}${text("leaf-p256.sec1.key")}${plain}`), REASON.several);
    // The same key twice is two blocks.
    assertUnreadable(resultFor(plain + plain), REASON.several);
    // Whatever the first one is.
    assertUnreadable(resultFor(text("not-a-key.key") + plain), REASON.several);
    assertUnreadable(resultFor(`${text("leaf-rsa.truncated.key")}\n${plain}`), REASON.several);
    assertUnreadable(resultFor(plain + text("leaf-rsa.truncated.key")), REASON.several);
    // A key cut in the middle of a line has no line end, so the next BEGIN is not on a line of its
    // own: Node.js does not see it either, and the file is one block that cannot be read.
    assertUnreadable(resultFor(text("leaf-rsa.truncated.key") + plain), REASON.unsupported);
    assert.throws(() => createPrivateKey(text("leaf-rsa.truncated.key") + plain));
});

test("what counts as a private key block is a BEGIN line whose label ends in PRIVATE KEY, so a key Node.js cannot read next to one it can is more than one, and a block that is not a key is a block", () => {
    const plain = text("leaf-p256.key");
    for (const label of ["OPENSSH PRIVATE KEY", "DSA PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "PRIVATE KEY", "X PRIVATE KEY", "SM2 PRIVATE KEY"]) {
        assertUnreadable(resultFor(block(label, "AAAA") + plain), REASON.several);
        assertUnreadable(resultFor(plain + block(label, "AAAA")), REASON.several);
    }
    // Alone, a block of any of them is a key that could not be read and not a file with no key.
    for (const label of ["OPENSSH PRIVATE KEY", "DSA PRIVATE KEY", "X PRIVATE KEY"]) assertUnreadable(resultFor(block(label, "AAAA")), REASON.unsupported);
    // A traditional label over a PKCS#8 body of another type is not read by Node.js.
    assertUnreadable(resultFor(block("DSA PRIVATE KEY", text("leaf-p256.key").split("\n").slice(1, -2).join("\n"))), REASON.unsupported);
    // A block that is cut short is one block, which is not a key; not "no key" and not nothing.
    assertUnreadable(resultFor(text("leaf-rsa.truncated.key")), REASON.unsupported);
    assertUnreadable(resultFor("-----BEGIN PRIVATE KEY-----\n"), REASON.unsupported);
    // An END line alone is not a block.
    assertUnreadable(resultFor("-----END PRIVATE KEY-----\n"), REASON.noKey);
    assert.equal(resultFor(`-----END PRIVATE KEY-----\n${plain}`).status, "pass");
});

test("the label rule that counts a private key block is the one scripts/package-contents.mjs applies to keep keys out of the tarball", () => {
    const labels = [
        "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "OPENSSH PRIVATE KEY", "X PRIVATE KEY", "A B PRIVATE KEY", "X9 PRIVATE KEY",
        "CERTIFICATE", "PUBLIC KEY", "RSA PUBLIC KEY", "TRUSTED CERTIFICATE", "CERTIFICATE REQUEST", "EC PARAMETERS", "PRIVATE KEYS", "PRIVATE KEY X", "KEY", "PRIVATE", "PRIVATE  KEY",
        "private key", "RSA private key", "rsa PRIVATE KEY", "PRIVATE-KEY", "RSA-PRIVATE KEY", "",
    ];
    for (const label of labels) {
        const material = `-----BEGIN ${label}-----\nAAAA\n-----END ${label}-----\n`;
        // Two of them are "more than one" exactly when the label counts.
        const counts = resultFor(material + material).message === REASON.several;
        assert.equal(counts, holdsPrivateKey(material), JSON.stringify(label));
    }
});

test("a certificate, a public key or text before or after a private key is skipped, and a file that holds a chain and its key is accepted", async (t) => {
    const key = text("leaf-p256.key");
    const before = {
        "a certificate": text("leaf-rsa.certificate.key"),
        "a public key": text("leaf-rsa.public.key"),
        "a certificate chain": text("bundle-ordered.pem"),
        "a certificate followed by a key's public half": text("leaf-p256.pem") + text("leaf-rsa.public.key"),
        "a public key written for RSA alone": block("RSA PUBLIC KEY", "AAAA"),
        "a certificate OpenSSL marks as trusted": block("TRUSTED CERTIFICATE", "AAAA"),
        "an old style certificate": block("X509 CERTIFICATE", "AAAA"),
        "parameters": block("EC PARAMETERS", "BggqhkjOPQMBBw=="),
        "a request": block("CERTIFICATE REQUEST", "AAAA"),
        "text": "these are my keys\n",
        "blank lines": "\n\n",
    };
    for (const [what, other] of Object.entries(before)) {
        await t.test(`${what} before and after`, () => {
            for (const material of [other + key, key + other, other + key + other]) {
                const result = resultFor(material);
                assert.equal(result.code, "KEY_MISMATCH");
                assert.equal(result.status, "pass");
            }
        });
    }
    // The chain and the key of a deployment, in the order people paste them.
    const chain = text("leaf-p256.pem") + text("intermediate.pem") + text("root-ca.pem");
    assert.equal(resultFor(chain + key).status, "pass");
    assert.equal(resultFor(key + chain).status, "pass");
    assert.equal(resultFor(`${chain}\n${text("leaf-p256.pkcs8-encrypted.key")}`, PASSPHRASE).status, "pass");
    // A key that is not the certificate's, in the same file, is a mismatch and not an unreadable key.
    assert.equal(resultFor(chain + text("leaf-rsa.key")).code, "KEY_MISMATCH");
    assert.equal(resultFor(chain + text("leaf-rsa.key")).status, "fail");
});

test("when a file matches several reasons, a private key block decides, then a certificate, then a public key, whatever the order of the blocks", () => {
    const certificate = text("leaf-rsa.certificate.key");
    const publicKey = text("leaf-rsa.public.key");
    const truncated = text("leaf-rsa.truncated.key");
    const encrypted = text("leaf-rsa.pkcs8-encrypted.key");
    const notAKey = text("not-a-key.key");
    // A certificate and a public key: the certificate.
    assertUnreadable(resultFor(certificate + publicKey), REASON.certificate);
    assertUnreadable(resultFor(publicKey + certificate), REASON.certificate);
    // A certificate and a key that is cut short, or is not a key: the key block, which is what was asked for.
    assertUnreadable(resultFor(certificate + notAKey), REASON.unsupported);
    assertUnreadable(resultFor(notAKey + certificate), REASON.unsupported);
    assertUnreadable(resultFor(`${certificate}\n${truncated}`), REASON.unsupported);
    // A public key and an encrypted key: the key needs its passphrase.
    assertUnreadable(resultFor(publicKey + encrypted), REASON.encrypted);
    assertUnreadable(resultFor(encrypted + publicKey), REASON.encrypted);
    assertUnreadable(resultFor(publicKey + encrypted, "wrong"), REASON.decrypt);
    assertUnreadable(resultFor(certificate + publicKey + encrypted), REASON.encrypted);
    // More than one private key beats all of them, the passphrase and what the first one is.
    assertUnreadable(resultFor(certificate + publicKey + encrypted + encrypted), REASON.several);
    assertUnreadable(resultFor(encrypted + certificate + text("leaf-p256.key"), PASSPHRASE), REASON.several);
    // Nothing but a certificate and a public key and no passphrase asked of them.
    assertUnreadable(resultFor(certificate + publicKey, PASSPHRASE), REASON.certificate);
});

// ---------------------------------------------------------------------------------------------
// The lines that are boundaries

test("a boundary line is read as Node.js reads it: at the start of a line, with one byte order mark at most, and with \\n as the only line end", () => {
    const key = text("leaf-p256.key");
    // Each of these loads in Node.js or does not, and the answer here is the same.
    /** @type {Record<string, string>} */
    const forms = {
        "an indented BEGIN line": `  ${key}`,
        "text on the line before the BEGIN": `text ${key}`,
        "carriage returns alone": key.replaceAll("\n", "\r"),
        "two byte order marks": `\uFEFF\uFEFF${key}`,
        "a byte order mark after a line": `x\n\uFEFF${key}`,
        "a line separator before": `\u2028${key}`,
        "a form feed before": `\f${key}`,
        "four dashes": key.replace("-----BEGIN", "----BEGIN"),
        "the body on the BEGIN line": key.replace("KEY-----\n", "KEY-----"),
        "a different END label": key.replace("END PRIVATE KEY", "END RSA PRIVATE KEY"),
    };
    for (const [what, material] of Object.entries(forms)) {
        const readable = (() => {
            try {
                createPrivateKey({ key: material, format: "pem" });
                return true;
            } catch {
                return false;
            }
        })();
        const result = resultFor(material);
        assert.equal(result.code === "KEY_MISMATCH", readable, what);
    }
    // Not boundaries, so not blocks: two of them are not "more than one".
    for (const material of [`  ${key}  ${key}`, `text ${key}text ${key}`, `${key.replaceAll("\n", "\r")}${key.replaceAll("\n", "\r")}`, `\u2028${key}\u2028${key}`]) {
        assertUnreadable(resultFor(material), REASON.noKey);
    }
    // Whatever follows the dashes of a line, as long as it is white space: Node.js accepts these and so does this, so two
    // of them are two blocks and not one.
    for (const space of [" ", "\t", "\r", " \r ", "\r\r", "\f", "\v", "\u00a0", "\u2003", "\0", " \r"]) {
        const spaced = key.replaceAll("KEY-----\n", `KEY-----${space}\n`);
        assert.doesNotThrow(() => createPrivateKey({ key: spaced, format: "pem" }), JSON.stringify(space));
        assert.equal(resultFor(spaced).status, "pass", JSON.stringify(space));
        assertUnreadable(resultFor(spaced + spaced), REASON.several);
    }
    assertUnreadable(resultFor(key.replace("KEY-----\n", "KEY----- x\n")), REASON.noKey);
    assert.throws(() => createPrivateKey({ key: key.replace("KEY-----\n", "KEY----- x\n"), format: "pem" }));
    // One of them is, and the other is not.
    assert.equal(resultFor(`${key}  ${key}`).status, "pass");
    assert.equal(resultFor(`\uFEFF${key}`).status, "pass");
    // A carriage return before the line end belongs to the line.
    assertUnreadable(resultFor(key.replaceAll("\n", "\r\n") + key.replaceAll("\n", "\r\n")), REASON.several);
});

test("a byte order mark is accepted only at the very start of the text, before the first block", () => {
    const key = text("leaf-p256.key");
    // Node.js loads the first key and does not see a second block that a byte order mark precedes.
    assert.doesNotThrow(() => createPrivateKey({ key: `${key}\uFEFF${key}`, format: "pem" }));
    assert.equal(resultFor(`${key}\uFEFF${key}`).status, "pass");
    assert.equal(resultFor(`\uFEFF${key}\uFEFF${key}`).status, "pass");
    assertUnreadable(resultFor(`\uFEFF${key}${key}`), REASON.several);
    // And a certificate behind one is not one either.
    assertUnreadable(resultFor(`x\n\uFEFF${text("leaf-rsa.certificate.key")}`), REASON.noKey);
    assertUnreadable(resultFor(`\uFEFF${text("leaf-rsa.certificate.key")}`), REASON.certificate);
    assertUnreadable(resultFor(`\uFEFF${text("leaf-rsa.public.key")}`), REASON.publicKey);
});

test("a file that is not text and holds no block is a format that is not supported, whichever control character or byte shows it, and a text with none is a file with no key", async (t) => {
    const control = { NUL: "\u0000", SOH: "\u0001", BS: "\u0008", VT: "\u000b", FF: "\u000c", SO: "\u000e", US: "\u001f", DEL: "\u007f", "a replacement character": "\uFFFD" };
    for (const [what, character] of Object.entries(control)) {
        await t.test(what, () => {
            assertUnreadable(resultFor(`hello ${character} world`), REASON.unsupported);
            assertUnreadable(resultFor(character), REASON.unsupported);
        });
    }
    // Bytes that are not UTF-8, which become the replacement character.
    assertUnreadable(resultFor(Buffer.from([0x68, 0x69, 0x80, 0x0a])), REASON.unsupported);
    assertUnreadable(resultFor(Buffer.from([0xff])), REASON.unsupported);
    // Tab, line feed, carriage return, printable characters and text that is not ASCII are text.
    for (const character of ["\t", "\n", "\r", " ", "~", "\u00e9", "\u20ac", "\u{1F511}"]) {
        assertUnreadable(resultFor(`my keys ${character} are in the safe`), REASON.noKey);
    }
    assertUnreadable(resultFor(Buffer.from("claves \u00e9 \u20ac")), REASON.noKey);
});

test("a Proc-Type line is the whole of the first line after the BEGIN line, in this case and with this value", () => {
    const traditional = text("leaf-rsa.pkcs1-encrypted.key");
    for (const header of ["X Proc-Type: 4,ENCRYPTED", "Proc-Type: 4,ENCRYPTED X", "Proc-Type: 4,ENCRYPTEDX", "Proc-Type: 3,ENCRYPTED", "Proc-Type: 4;ENCRYPTED", "Proc-Type 4,ENCRYPTED"]) {
        assertUnreadable(resultFor(traditional.replace("Proc-Type: 4,ENCRYPTED", header)), REASON.unsupported);
    }
    // The header is looked for right after the BEGIN line, however long the lines of the body are.
    assertUnreadable(resultFor(`${traditional.replace("\n", `\n${"x".repeat(5000)}\n`)}`), REASON.unsupported);
    assertUnreadable(resultFor(`-----BEGIN RSA PRIVATE KEY-----\n${"A".repeat(300)}\nProc-Type: 4,ENCRYPTED\n`), REASON.unsupported);
});

test("a very long text with no line end, or with millions of them, is scanned without trouble", () => {
    assertUnreadable(resultFor("a".repeat(5_000_000)), REASON.noKey);
    assertUnreadable(resultFor("\n".repeat(5_000_000)), REASON.noKey);
    assertUnreadable(resultFor(`${"-----BEGIN ".repeat(200_000)}x`), REASON.noKey);
    assertUnreadable(resultFor(`-----BEGIN ${"-----".repeat(200_000)} \n`), REASON.noKey);
    assert.equal(resultFor(`${"a\n".repeat(2_000_000)}${text("leaf-p256.key")}${"b\n".repeat(2_000_000)}`).status, "pass");
});

// ---------------------------------------------------------------------------------------------
// A wrong call

test("a material that is neither text nor bytes, and a passphrase that is not text, are a TypeError and not an unreadable key", async (t) => {
    const key = text("leaf-p256.key");
    const materials = [undefined, null, 5, true, {}, [], [key], { key }, new String(key), Symbol("key"), 10n, () => key, new ArrayBuffer(8), new DataView(new ArrayBuffer(8)), new Uint16Array(4), new Int8Array(4)];
    for (const [position, material] of materials.entries()) {
        await t.test(`material number ${position}`, () => {
            const error = thrown(() => matchesPrivateKey(P256, { material }));
            assert.ok(error instanceof TypeError);
            assert.equal(error.message, "privateKey.material must be a string, a Buffer or a Uint8Array");
            assert.equal(/** @type {any} */ (error).code, undefined, "it is not an error of Node.js");
        });
    }
    const passphrases = [null, 12345, true, {}, { secret: "hunter2-pass" }, ["hunter2-pass"], Buffer.from("hunter2-pass"), new Uint8Array(4), new String("hunter2-pass"), Symbol("hunter2-pass"), 10n, () => "hunter2-pass"];
    for (const [position, passphrase] of passphrases.entries()) {
        await t.test(`passphrase number ${position}`, () => {
            for (const material of [text("leaf-p256.pkcs8-encrypted.key"), key]) {
                const error = thrown(() => matchesPrivateKey(P256, { material, passphrase }));
                assert.ok(error instanceof TypeError);
                assert.equal(error.message, "privateKey.passphrase must be text");
                assert.equal(/** @type {any} */ (error).code, undefined, "it is not an error of Node.js, which quotes the passphrase");
            }
        });
    }
    // An empty passphrase is text.
    assert.equal(resultFor(key, "").status, "pass");

    for (const given of [undefined, null, "-----BEGIN PRIVATE KEY-----", key, 5, [], [key]]) {
        const error = thrown(() => matchesPrivateKey(P256, given));
        assert.ok(error instanceof TypeError);
        assert.equal(error.message, "privateKey must be an object with a material and, optionally, a passphrase");
    }
    // Properties are read as data, so nothing the caller owns runs, and a proxy that throws is a wrong call.
    let ran = false;
    const accessor = { get material() { ran = true; return key; } };
    assert.equal(thrown(() => matchesPrivateKey(P256, accessor)).message, "privateKey.material must be a string, a Buffer or a Uint8Array");
    const secret = { material: key, get passphrase() { ran = true; return "x"; } };
    assert.equal(thrown(() => matchesPrivateKey(P256, secret)).message, "privateKey.passphrase must be text" );
    assert.equal(ran, false);
    const revoked = Proxy.revocable({}, {});
    revoked.revoke();
    assert.equal(thrown(() => matchesPrivateKey(P256, revoked.proxy)).message, "privateKey cannot be read");
    const trapped = new Proxy({}, { getOwnPropertyDescriptor() { throw new Error(key); } });
    const trappedError = thrown(() => matchesPrivateKey(P256, trapped));
    assert.ok(trappedError instanceof TypeError);
    assert.ok(!trappedError.message.includes("BEGIN"));
    // A class instance is an object, and its own fields are read.
    class Held {
        material = key;
        passphrase = undefined;
    }
    assert.equal(matchesPrivateKey(P256, new Held()).status, "pass");
});

test("an observation that has no target with a spkiSha256 is a TypeError that names the field", () => {
    const key = { material: text("leaf-p256.key") };
    const base = () => JSON.parse(library.serializeObservation(P256));
    /** @type {[string, (observation: any) => any, string][]} */
    const wrong = [
        ["no observation", () => undefined, "observation must be an object"],
        ["null", () => null, "observation must be an object"],
        ["a list", () => [], "observation must be an object"],
        ["a string", () => "x", "observation must be an object"],
        ["another contract", (o) => ({ ...o, contract: 2 }), "observation.contract must be 1"],
        ["no certificates", (o) => ({ ...o, certificates: undefined }), "observation.target must be the position of a certificate in observation.certificates"],
        ["a target that is text", (o) => ({ ...o, target: "0" }), "observation.target must be the position of a certificate in observation.certificates"],
        ["a spkiSha256 that is a list holding a hash", (o) => { o.certificates[0].spkiSha256 = [o.certificates[0].spkiSha256]; return o; }, "observation.certificates[0].spkiSha256 must be 64 lowercase hexadecimal characters"],
        ["a spkiSha256 that is an object that reads as a hash", (o) => { const hash = o.certificates[0].spkiSha256; o.certificates[0].spkiSha256 = { toString: () => hash }; return o; }, "observation.certificates[0].spkiSha256 must be 64 lowercase hexadecimal characters"],
        ["a target past the end", (o) => ({ ...o, target: 1 }), "observation.target must be the position of a certificate in observation.certificates"],
        ["a target that is not a whole number", (o) => ({ ...o, target: 0.5 }), "observation.target must be the position of a certificate in observation.certificates"],
        ["a certificate that is not an object", (o) => ({ ...o, certificates: [null] }), "observation.target must be the position of a certificate in observation.certificates"],
        ["no spkiSha256", (o) => { delete o.certificates[0].spkiSha256; return o; }, "observation.certificates[0].spkiSha256 must be 64 lowercase hexadecimal characters"],
        ["a spkiSha256 in capitals", (o) => { o.certificates[0].spkiSha256 = o.certificates[0].spkiSha256.toUpperCase(); return o; }, "observation.certificates[0].spkiSha256 must be 64 lowercase hexadecimal characters"],
        ["a short spkiSha256", (o) => { o.certificates[0].spkiSha256 = "ab"; return o; }, "observation.certificates[0].spkiSha256 must be 64 lowercase hexadecimal characters"],
    ];
    for (const [what, make, message] of wrong) {
        const error = thrown(() => matchesPrivateKey(make(base()), key));
        assert.ok(error instanceof TypeError, what);
        assert.equal(error.message, message, what);
    }
    // The target is the certificate the observation says, and not the first.
    const observation = { ...base(), certificates: [{ ...base().certificates[0], spkiSha256: "0".repeat(64) }, base().certificates[0]], target: 1 };
    assert.equal(matchesPrivateKey(observation, key).status, "pass");
    assert.equal(matchesPrivateKey({ ...observation, target: 0 }, key).status, "fail");
    // The arguments are checked in order: observation, key, options.
    assert.equal(thrown(() => matchesPrivateKey(null, null, null)).message, "observation must be an object");
    assert.equal(thrown(() => matchesPrivateKey(P256, null, null)).message, "privateKey must be an object with a material and, optionally, a passphrase");
    assert.equal(thrown(() => matchesPrivateKey(P256, key, null)).message, "options must be an object");
});

test("matchesPrivateKey changes nothing it is given, and the same arguments give equal results", () => {
    const observation = observationOf("leaf-p256.pem");
    const before = library.serializeObservation(observation);
    const material = Buffer.from(text("leaf-p256.pkcs8-encrypted.key"));
    const given = Object.freeze({ material, passphrase: PASSPHRASE });
    const copy = Buffer.from(material);
    const first = matchesPrivateKey(observation, given);
    assert.deepEqual(matchesPrivateKey(observation, given), first);
    assert.equal(library.serializeObservation(observation), before);
    assert.ok(material.equals(copy));
    assert.deepEqual(Object.keys(given), ["material", "passphrase"]);
    const options = Object.freeze({ severity: "warn" });
    assert.deepEqual(matchesPrivateKey(observation, given, options), matchesPrivateKey(observation, given, options));
});

// ---------------------------------------------------------------------------------------------
// What Node.js does today with these files, which the reasons rely on or do not

test("today Node.js reads a private key under the label RSA PUBLIC KEY, so such a block is compared and not called a public key", () => {
    const body = text("leaf-rsa.pkcs1.key").split("\n").slice(1, -2).join("\n");
    const mislabelled = block("RSA PUBLIC KEY", body);
    assert.equal(matchesPrivateKey(observationOf("leaf-rsa.pem"), { material: mislabelled }).status, "pass");
    // It is a rule of the labels that a block under a public key label is not a private key block,
    // so a real key after it is not "more than one", and Node.js uses the first block: the mislabelled one.
    assert.equal(matchesPrivateKey(observationOf("leaf-rsa.pem"), { material: mislabelled + text("leaf-p256.key") }).status, "pass");
    assert.equal(matchesPrivateKey(observationOf("leaf-p256.pem"), { material: mislabelled + text("leaf-p256.key") }).status, "fail");
});

test("today Node.js reads an unencrypted body under the label ENCRYPTED PRIVATE KEY without a passphrase, so the key is compared and not called encrypted", () => {
    const body = text("leaf-p256.key").split("\n").slice(1, -2).join("\n");
    assert.equal(resultFor(block("ENCRYPTED PRIVATE KEY", body)).status, "pass");
    assert.equal(resultFor(block("EC PRIVATE KEY", body)).status, "pass");
    assertUnreadable(resultFor(block("RSA PRIVATE KEY", body)), REASON.unsupported);
});

test("today a passphrase longer than a kilobyte does not decrypt a key", () => {
    assertUnreadable(resultFor(text("leaf-rsa.pkcs8-encrypted.key"), PASSPHRASE.padEnd(2000, "x")), REASON.decrypt);
});

// ---------------------------------------------------------------------------------------------
// The README

test("the README documents matchesPrivateKey, its option, options.privateKey and each reason of KEY_UNREADABLE with the message the library writes", () => {
    const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
    const rows = readme.split("\n").filter((line) => line.startsWith("| ")).map((line) => line.split("|").slice(1, -1).map((cell) => cell.trim()));
    const start = rows.findIndex((row) => row[0] === "Reason" && row[1] === "The message goes on");
    assert.ok(start >= 0, "the README has no table of reasons");
    // The separator line does not start with a space, so the rows that follow the header are the reasons.
    const reasons = rows.slice(start + 1, start + 8).map((row) => row[1].replaceAll("`", ""));
    // Every message the library writes is in the README.
    assert.deepEqual([...reasons].sort(), Object.values(REASON).map((message) => message.slice("the private key could not be read: ".length)).sort());

    const text = readme.replace(/\s+/g, " ").replaceAll("`", "");
    assert.match(text, /matchesPrivateKey\(observation, privateKey, options\) says whether a private key is the key of the certificate an observation targets/);
    assert.match(text, /options\.severity is fail unless it says warn, and any other value is a TypeError/);
    assert.match(text, /Only PEM is read, so a DER file or a PKCS#12 file is a key that could not be read/);
    assert.match(text, /The library never reads a file: whoever calls it does/);
    assert.match(text, /options\.privateKey is \{ material, passphrase \}/);
    assert.match(text, /it is evaluated even when the policy does not list it, with severity fail/);
    assert.match(text, /and also when the policy lists matchesPrivateKey and no options\.privateKey is given/);
    assert.match(text, /that problem has the path \/matchesPrivateKey/);
    assert.match(text, /never from the error Node\.js gives/);
    assert.match(text, /The key and the passphrase are not in the result, in a message or in an error/);
    assert.doesNotMatch(text, /that evaluate is not given/);
});
