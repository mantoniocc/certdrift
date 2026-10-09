import { X509Certificate, createHash } from "node:crypto";
import { ParseError } from "./errors.js";

// Node.js reads only the first certificate of a PEM bundle and only the first one of
// concatenated DER, without an error, and it skips characters that are not base64. Passing
// it the whole material would let certificates vanish, so the material is split into blocks
// here, each block is decoded here, and Node.js is handed exactly one DER certificate at a
// time. Anything that would be dropped instead throws a ParseError naming the input block.

/**
 * One certificate read from the material.
 * @typedef {object} CertificateRead
 * @property {number} block Position of its input block, counting every PEM block from 1.
 * @property {X509Certificate} certificate
 * @property {Buffer} spki The public key as SubjectPublicKeyInfo DER, as Node.js exports it.
 * @property {string} sha256 Fingerprint of the whole certificate (DER), lowercase hexadecimal.
 */

// Something that looks like a boundary line: three or more dashes, then BEGIN or END in any
// case. The dashes are what separate a boundary from ordinary text such as the `---` lines of
// `openssl s_client` or the word "Extended". Matching loosely and validating strictly means a
// typo in a boundary line is an error, not a certificate that silently turns into text. That
// includes the typographic dashes that word processors and chat tools put in place of "-".
const DASH = String.raw`[-\p{Pd}\u2212]`;
const BOUNDARY_CANDIDATE = new RegExp(String.raw`(?<!${DASH})${DASH}{3,}[ \t]*(?:BEGIN|END)`, "giu");
const BOUNDARY = /^-----(BEGIN|END) ([A-Z0-9]+(?: [A-Z0-9]+)*)-----[ \t]*$/;
const LINE_BREAK = /[\r\n]/g;

const CERTIFICATE_LABELS = new Set(["CERTIFICATE", "X509 CERTIFICATE"]);

// Labels known to hold no certificate. Any other label that is not read could hide one
// (TRUSTED CERTIFICATE, PKCS7), so it is an error.
const NO_CERTIFICATE_LABEL = /(?:^|\s)(?:PRIVATE KEY|PUBLIC KEY|PARAMETERS|CERTIFICATE REQUEST|X509 CRL)$/;

// Padding only at the end, so two padded bodies glued together are not valid.
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/**
 * Every certificate in the material, in input order.
 * @param {string | Uint8Array} material A string is PEM. Bytes are DER when they start with
 *   a SEQUENCE with a long-form length, which every certificate does, and PEM otherwise.
 * @returns {CertificateRead[]}
 * @throws {ParseError}
 */
export function certificatesIn(material) {
    if (material.length === 0) throw new ParseError("the material is empty", null);

    // The view keeps byteOffset and byteLength: a Buffer or Uint8Array may be a slice of a
    // larger ArrayBuffer.
    const bytes = typeof material === "string" ? null : Buffer.from(material.buffer, material.byteOffset, material.byteLength);

    if (bytes !== null && bytes[0] === 0x30 && bytes[1] >= 0x80) {
        return [readCertificate(1, "DER", bytes)];
    }

    // Only the boundary lines and the base64 bodies mean anything, and both are ASCII; bytes that
    // are not UTF-8 become U+FFFD, which is not base64 and so cannot pass as part of a body.
    const text = bytes === null ? /** @type {string} */ (material) : bytes.toString("utf8");
    const certificates = [];
    for (const { number, label, body } of pemBlocks(text)) {
        if (CERTIFICATE_LABELS.has(label)) {
            certificates.push(readCertificate(number, label, decode(number, label, body)));
        } else if (!NO_CERTIFICATE_LABEL.test(label)) {
            throw new ParseError(`input block ${number} has the label ${label}, which may hold certificates and is not read`, number);
        }
    }
    if (certificates.length === 0) {
        throw new ParseError("the material holds no certificate: it has no PEM certificate block and is not DER", null);
    }
    return certificates;
}

/**
 * Splits text into PEM blocks. Text outside blocks is ignored.
 * @param {string} text
 * @returns {{ number: number, label: string, body: string }[]}
 */
function pemBlocks(text) {
    const blocks = [];
    /** @type {{ number: number, label: string, bodyStart: number } | null} */
    let open = null;
    let count = 0;

    for (const candidate of text.matchAll(BOUNDARY_CANDIDATE)) {
        const start = candidate.index;
        LINE_BREAK.lastIndex = start;
        const end = LINE_BREAK.exec(text)?.index ?? text.length;
        const line = text.slice(start, end);
        const boundary = BOUNDARY.exec(line);
        if (boundary === null) {
            throw new ParseError(`input block ${open?.number ?? count + 1} has a malformed boundary line: ${JSON.stringify(line.slice(0, 60))}`, open?.number ?? count + 1);
        }

        const [, kind, label] = boundary;
        if (kind === "BEGIN") {
            if (open !== null) {
                throw new ParseError(`input block ${open.number} (${open.label}) has no END line before the next BEGIN line`, open.number);
            }
            count += 1;
            open = { number: count, label, bodyStart: end };
        } else if (open === null) {
            throw new ParseError(`input block ${count + 1} has an END ${label} line but no BEGIN line`, count + 1);
        } else if (open.label !== label) {
            throw new ParseError(`input block ${open.number} begins as ${open.label} and ends as ${label}`, open.number);
        } else {
            blocks.push({ number: open.number, label, body: text.slice(open.bodyStart, start) });
            open = null;
        }
    }

    if (open !== null) {
        throw new ParseError(`input block ${open.number} (${open.label}) has no END line`, open.number);
    }
    return blocks;
}

/**
 * The bytes a certificate block's base64 body stands for. Only whitespace is forgiven.
 * @param {number} block
 * @param {string} label
 * @param {string} body
 */
function decode(block, label, body) {
    const compact = body.replace(/\s+/g, "");
    if (compact === "") throw new ParseError(`input block ${block} (${label}) is empty`, block);
    if (!BASE64.test(compact)) throw new ParseError(`input block ${block} (${label}) is not valid base64`, block);
    return Buffer.from(compact, "base64");
}

/**
 * Reads one DER certificate through Node.js and checks that it is the whole input.
 * @param {number} block
 * @param {string} label
 * @param {Buffer} der
 * @returns {CertificateRead}
 */
function readCertificate(block, label, der) {
    /** @type {X509Certificate} */
    let certificate;
    try {
        certificate = new X509Certificate(der);
    } catch (cause) {
        throw new ParseError(`input block ${block} (${label}) is not a valid certificate`, block, { cause });
    }

    // Node.js accepts bytes after the certificate, re-encodes BER, and given a PEM block on a
    // line of its own anywhere in the bytes it returns that certificate instead of the DER one.
    // So `raw` differs from the input exactly when something would be dropped, rewritten or
    // replaced.
    const raw = certificate.raw;
    if (!raw.equals(der)) {
        if (raw.length < der.length && raw.equals(der.subarray(0, raw.length))) {
            throw new ParseError(`input block ${block} (${label}) holds ${der.length - raw.length} bytes after its certificate`, block);
        }
        throw new ParseError(`input block ${block} (${label}) is not exactly one DER-encoded certificate`, block);
    }

    // A key OpenSSL cannot load still parses as a certificate, but it cannot be fingerprinted.
    // Rejecting it names the block; skipping it would drop the certificate.
    /** @type {Buffer} */
    let spki;
    try {
        spki = certificate.publicKey.export({ type: "spki", format: "der" });
    } catch (cause) {
        throw new ParseError(`input block ${block} (${label}) has a public key Node.js cannot read`, block, { cause });
    }
    return { block, certificate, spki, sha256: createHash("sha256").update(raw).digest("hex") };
}
