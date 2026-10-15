import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { types } from "node:util";
import { dataOf, isPlain } from "./json.js";
import { SHA256 } from "./policy.js";

/** @import { PrivateKey, Result } from "./index.js" */

// Matching a private key with a certificate. The key is read with Node.js (`createPrivateKey`) and
// nothing else: no DER is parsed here and no base64 is decoded. What is read of the text is its
// PEM boundary lines and the `Proc-Type` header, which is reading text.
//
// Node.js says the same thing (`ERR_OSSL_UNSUPPORTED`) for a certificate, a public key, an empty
// file, a truncated key and a block that is not a key, and the codes of OpenSSL change between
// versions. So the reason a key could not be read is chosen from the labels of the PEM blocks and
// never from the error, and no error of Node.js leaves this file: a key or a passphrase could
// be quoted in one.

/** The name of the rule, and of the entry of a policy that asks for it. */
const RULE = "matchesPrivateKey";

const UNREADABLE = "the private key could not be read: ";

const REASONS = {
    certificate: "the file holds a certificate",
    publicKey: "the file holds a public key",
    noKey: "the file holds no private key",
    encrypted: "it is encrypted and no passphrase was given",
    decrypt: "it could not be decrypted with the passphrase given",
    several: "the file holds more than one private key",
    unsupported: "its format or algorithm is not supported, or the key is damaged",
};

// A boundary line as Node.js reads it, which is not what a multiline pattern reads: it starts a
// line (after one byte order mark at the very start of the text), `\n` is the only line end, and
// whitespace (a carriage return, a form feed, a no-break space and a NUL are accepted too) may
// follow the dashes. An indented line, one that starts in
// the middle of a line, a second byte order mark and lines ended by `\r` alone are not
// boundaries to it, so they are not here either. `/m` is not used because it also breaks lines at
// `\r`, U+2028 and U+2029.
const BEGIN = /(?:(?<![^\n])|(?<=^\uFEFF))-----BEGIN ([^\n]*?)-----(?:[^\S\n]|\0)*(?![^\n])/g;

// The labels that count. A private key is any label that ends in `PRIVATE KEY`, which is the rule
// `scripts/package-contents.mjs` applies to keep keys out of the tarball: `PRIVATE KEY`,
// `RSA PRIVATE KEY`, `EC PRIVATE KEY`, `DSA PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`, and also
// `OPENSSH PRIVATE KEY`, which Node.js cannot read and skips. Counting what Node.js reads would
// mean decoding each block, and it uses only the first one.
const PRIVATE_KEY = /^(?:[A-Z0-9]+ )*PRIVATE KEY$/;
const CERTIFICATE = /^(?:[A-Z0-9]+ )*CERTIFICATE$/;
const PUBLIC_KEY = /^(?:[A-Z0-9]+ )*PUBLIC KEY$/;

// The first line of a traditional encrypted key. Node.js accepts a space after the comma.
const PROC_TYPE = /^Proc-Type:[ \t]*4,[ \t]*ENCRYPTED[ \t\r]*$/;

// Anything but tab, line feed, carriage return and printable characters: DER and PKCS#12 have
// bytes like these, and a text that is not UTF-8 has the replacement character.
const NOT_TEXT = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\uFFFD]/;

/**
 * What a rule that reads a private key found. The same shape as the other findings of
 * `src/rules.js`, with the code, which here is one of two.
 * @typedef {object} KeyFinding
 * @property {boolean} holds
 * @property {"KEY_MISMATCH" | "KEY_UNREADABLE"} code
 * @property {string} message
 * @property {string} [actual] Public: the SHA-256 of the key's public key.
 * @property {string} [expected] Public: the target's `spkiSha256`.
 */

/**
 * Checks that a private key is the key of the certificate an observation targets.
 *
 * The key matches when the SHA-256 of the public key derived from it (as SubjectPublicKeyInfo DER)
 * is the target's `spkiSha256`. Only PEM is read. A key that cannot be read is a result with code
 * `KEY_UNREADABLE` and a fixed message that says why, never an exception. The key and the
 * passphrase are not in the result, the message, or an error.
 *
 * @param {import("./index.js").Observation} observation As `inspect()` returns it.
 * @param {PrivateKey} privateKey The file's `material` as text or bytes, and its `passphrase` as text if
 *   it has one.
 * @param {import("./index.js").MatchesPrivateKeyOptions} [options]
 * @returns {Result}
 * @throws {TypeError} The observation has no target with a `spkiSha256`, `material` is neither text
 *   nor bytes, `passphrase` is not text, or `options` is wrong.
 */
export function matchesPrivateKey(observation, privateKey, options) {
    const spkiSha256 = spkiOf(observation);
    const key = privateKeyOf(privateKey, "privateKey");
    const severity = severityOf(options);

    const found = findKey(spkiSha256, key);
    /** @type {Result} */
    const result = { code: found.code, status: found.holds ? "pass" : severity, rule: { name: RULE }, message: found.message };
    if (found.actual !== undefined) result.actual = found.actual;
    if (found.expected !== undefined) result.expected = found.expected;
    return result;
}

/**
 * A key and its passphrase as the caller gave them, checked. They are read as own data properties,
 * so nothing the caller owns runs. A wrong type is a wrong call, and it is refused here because
 * Node.js would quote a passphrase that is not text in its own error.
 * @param {unknown} given
 * @param {string} name What the caller called it, for the message.
 * @returns {PrivateKey}
 * @throws {TypeError} The message never holds a value.
 */
export function privateKeyOf(given, name) {
    let read;
    try {
        read = propertiesOf(given);
    } catch {
        // A proxy that throws when it is asked, or one that has been revoked.
        throw new TypeError(`${name} cannot be read`);
    }
    if (read === null) throw new TypeError(`${name} must be an object with a material and, optionally, a passphrase`);
    const { material, passphrase } = read;
    if (typeof material !== "string" && !types.isUint8Array(material)) {
        throw new TypeError(`${name}.material must be a string, a Buffer or a Uint8Array`);
    }
    if (passphrase !== undefined && typeof passphrase !== "string") {
        throw new TypeError(`${name}.passphrase must be text`);
    }
    return { material, passphrase };
}

/**
 * The two properties of a key as the caller wrote them, or `null` for something that is not an
 * object that could hold them. An accessor is never called: it reads as a passphrase that is not
 * text, so it is a wrong call and not a missing passphrase.
 * @param {unknown} given
 * @returns {{ material: unknown, passphrase: unknown } | null}
 */
function propertiesOf(given) {
    if (typeof given !== "object" || given === null || Array.isArray(given)) return null;
    const descriptor = Object.getOwnPropertyDescriptor(given, "passphrase");
    return {
        material: dataOf(given, "material"),
        passphrase: descriptor === undefined ? undefined : "value" in descriptor ? descriptor.value : null,
    };
}

/**
 * @param {unknown} options
 * @returns {"fail" | "warn"}
 * @throws {TypeError}
 */
function severityOf(options) {
    if (options !== undefined && (typeof options !== "object" || options === null)) {
        throw new TypeError("options must be an object");
    }
    const severity = /** @type {{ severity?: unknown } | undefined} */ (options)?.severity;
    // `fail` unless it says `warn`; a word that is neither is a wrong call, not a quiet `fail`.
    if (severity !== undefined && severity !== "fail" && severity !== "warn") {
        throw new TypeError(`options.severity must be "fail" or "warn"`);
    }
    return severity === "warn" ? "warn" : "fail";
}

/**
 * The SHA-256 of the target's public key, read from what the rule needs of an observation.
 * @param {unknown} observation
 * @returns {string}
 * @throws {TypeError} Names what is wrong.
 */
function spkiOf(observation) {
    if (!isPlain(observation)) throw new TypeError("observation must be an object");
    if (dataOf(observation, "contract") !== 1) throw new TypeError("observation.contract must be 1");
    const certificates = dataOf(observation, "certificates");
    const index = dataOf(observation, "target");
    const certificate = Array.isArray(certificates) && Number.isInteger(index) ? dataOf(certificates, String(index)) : undefined;
    if (!isPlain(certificate)) {
        throw new TypeError("observation.target must be the position of a certificate in observation.certificates");
    }
    const spkiSha256 = dataOf(certificate, "spkiSha256");
    assertSpki(spkiSha256, `observation.certificates[${index}]`);
    return /** @type {string} */ (spkiSha256);
}

/**
 * @param {unknown} value A certificate's `spkiSha256`.
 * @param {string} name Where it was found.
 * @throws {TypeError}
 */
export function assertSpki(value, name) {
    if (typeof value !== "string" || !SHA256.test(value)) {
        throw new TypeError(`${name}.spkiSha256 must be 64 lowercase hexadecimal characters`);
    }
}

/**
 * Whether a key is the one of a certificate, or why it cannot be said.
 * @param {string} spkiSha256 The target's.
 * @param {PrivateKey} key Checked by `privateKeyOf`.
 * @returns {KeyFinding}
 */
export function findKey(spkiSha256, { material, passphrase }) {
    const text = typeof material === "string" ? material : Buffer.from(material.buffer, material.byteOffset, material.byteLength).toString("utf8");
    const blocks = scan(text);
    // Node.js uses the first key of a file and says nothing of the others.
    if (blocks.keys.length > 1) return unreadable(REASONS.several);

    const derived = derive(material, passphrase);
    if (derived !== null) {
        const holds = derived === spkiSha256;
        return {
            holds,
            code: "KEY_MISMATCH",
            message: holds ? "the private key corresponds to the certificate's public key" : "the private key does not correspond to the certificate's public key",
            actual: derived,
            expected: spkiSha256,
        };
    }
    return unreadable(reasonOf(text, blocks, passphrase !== undefined));
}

/**
 * The SHA-256 of the public key of a private key, or `null` when Node.js cannot read it. Only the
 * calls into Node.js are inside the `try`: a mistake in this file must not read as an unreadable
 * key.
 * @param {string | Uint8Array} material
 * @param {string | undefined} passphrase
 * @returns {string | null}
 */
function derive(material, passphrase) {
    try {
        const publicKey = createPublicKey(createPrivateKey({ key: /** @type {string | Buffer} */ (material), format: "pem", passphrase }));
        return createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
    } catch {
        return null;
    }
}

/**
 * @param {string} reason
 * @returns {KeyFinding}
 */
function unreadable(reason) {
    return { holds: false, code: "KEY_UNREADABLE", message: `${UNREADABLE}${reason}` };
}

/**
 * What the boundary lines of a text say it holds: its private key blocks, in order, and whether it
 * has a certificate and a public key.
 * @param {string} text
 * @returns {{ keys: { label: string, end: number }[], certificate: boolean, publicKey: boolean }}
 */
function scan(text) {
    /** @type {{ label: string, end: number }[]} */
    const keys = [];
    let certificate = false;
    let publicKey = false;
    for (const match of text.matchAll(BEGIN)) {
        const label = match[1];
        if (PRIVATE_KEY.test(label)) keys.push({ label, end: match.index + match[0].length });
        else if (CERTIFICATE.test(label)) certificate = true;
        else if (PUBLIC_KEY.test(label)) publicKey = true;
    }
    return { keys, certificate, publicKey };
}

/**
 * Why Node.js could not read the key, from the labels alone.
 *
 * A private key block decides, whatever else the file holds: a certificate or a public key beside
 * it is skipped, as Node.js skips it. Without one, a certificate comes before a public key, so
 * the answer does not depend on the order of the blocks.
 * @param {string} text
 * @param {ReturnType<typeof scan>} blocks
 * @param {boolean} hasPassphrase
 * @returns {string}
 */
function reasonOf(text, blocks, hasPassphrase) {
    const [key] = blocks.keys;
    if (key !== undefined) {
        if (!isEncrypted(text, key)) return REASONS.unsupported;
        // With a passphrase, a wrong one cannot be told from damage or an unsupported cipher
        // without the error code, which changes between versions.
        return hasPassphrase ? REASONS.decrypt : REASONS.encrypted;
    }
    if (blocks.certificate) return REASONS.certificate;
    if (blocks.publicKey) return REASONS.publicKey;
    return NOT_TEXT.test(text) ? REASONS.unsupported : REASONS.noKey;
}

/**
 * Whether a private key block is encrypted, from its label or its first header line. A key
 * without encryption loads with any passphrase, so loading proves nothing about this.
 * @param {string} text
 * @param {{ label: string, end: number }} block The BEGIN line of the block.
 */
function isEncrypted(text, { label, end }) {
    if (label === "ENCRYPTED PRIVATE KEY") return true;
    const header = /^\n([^\n]*)/.exec(text.slice(end, end + 200));
    return header !== null && PROC_TYPE.test(header[1]);
}
