import { createHash } from "node:crypto";
import { types } from "node:util";
import { certificatesIn } from "./material.js";

/**
 * Where the material came from. The CLI and the TLS layer fill `ref` and `servername`.
 * @typedef {object} Source
 * @property {string} kind
 * @property {string} [ref]
 * @property {string | null} [servername]
 * @property {string} [provider]
 */

/**
 * @typedef {object} DistinguishedName
 * @property {string | null} cn
 * @property {string} dn
 */

/**
 * @typedef {object} CertificateObservation
 * @property {number} index
 * @property {string} kind
 * @property {boolean} selfSigned
 * @property {number[]} issuedBy
 * @property {DistinguishedName} subject
 * @property {DistinguishedName} issuer
 * @property {string} serial
 * @property {string} notBefore
 * @property {string} notAfter
 * @property {{ dns: string[], ip: string[], email: string[], uri: string[] }} san
 * @property {string[] | null} eku
 * @property {{ algorithm: string | null, size: number | null, curve: string | null }} key
 * @property {string} sha256
 * @property {string} spkiSha256
 * @property {{ daysRemaining: number, lifetimeFraction: number | null }} derived
 */

/**
 * @typedef {object} Warning
 * @property {string} code
 * @property {number | null} certificate
 * @property {string} message
 */

/**
 * The observation of some certificate material, as described by `schema/observation.schema.json`.
 * @typedef {object} Observation
 * @property {1} contract
 * @property {"x509"} format
 * @property {{ at: string, source: Source }} observation
 * @property {number} target
 * @property {CertificateObservation[]} certificates
 * @property {Warning[]} warnings
 */

/**
 * Turns certificate material into an observation. Reads no files and opens no sockets.
 *
 * @param {string | Uint8Array} material One certificate or several, as PEM (a string, or bytes)
 *   or as a single DER certificate (bytes). Text between PEM blocks is ignored, so the output
 *   of `openssl s_client -showcerts` works as it is.
 * @param {{ source?: Source, at?: Date }} [options]
 *   `source` defaults to `{ kind: "bytes" }`. `at` defaults to the moment of the call and is
 *   cut to the whole second, which is all a certificate date can express.
 * @returns {Observation}
 * @throws {import("./errors.js").ParseError} The material is empty, or one of its blocks is not
 *   a readable certificate. The message says which input block, counting from 1.
 * @throws {TypeError} An argument has the wrong type.
 */
export function inspect(material, options) {
    if (typeof material !== "string" && !types.isUint8Array(material)) {
        throw new TypeError("material must be a string, a Buffer or a Uint8Array");
    }
    if (options !== undefined && (typeof options !== "object" || options === null)) {
        throw new TypeError("options must be an object");
    }
    const at = instantOf(options?.at);
    const source = sourceOf(options?.source);

    const certificates = certificatesIn(material).map(describe);

    return {
        contract: 1,
        format: "x509",
        observation: { at: timestamp(at), source },
        target: 0, // PENDING: the certificate that signs no other one in the material
        certificates,
        warnings: [], // PENDING: one warning per duplicate dropped and per SAN type not represented
    };
}

/**
 * One certificate's entry in the observation.
 *
 * Fields marked PENDING are not read from the certificate yet. They all follow one rule: a
 * constant that says "nothing found" — null where the schema allows it, otherwise the empty or
 * zero value of the type — except `kind`, which has no empty value and gets the one for a
 * certificate that is not marked as a CA. Each is valid against the schema and none of them is
 * a claim about the certificate. To replace one, read the value where its line is.
 * @param {import("./material.js").CertificateRead} read
 * @param {number} index
 * @returns {CertificateObservation}
 */
function describe({ certificate, spki }, index) {
    return {
        index,
        kind: "end-entity", // PENDING: "ca" when basicConstraints marks a CA
        selfSigned: false, // PENDING: issuer equals subject and the signature verifies with its own key
        issuedBy: [], // PENDING: indices of the certificates in the material that verify its signature
        subject: { cn: null, dn: "" }, // PENDING: the subject name
        issuer: { cn: null, dn: "" }, // PENDING: the issuer name
        serial: "0", // PENDING: the serial number in uppercase hexadecimal
        notBefore: "1970-01-01T00:00:00Z", // PENDING: the start of validity
        notAfter: "1970-01-01T00:00:00Z", // PENDING: the end of validity
        san: { dns: [], ip: [], email: [], uri: [] }, // PENDING: the subject alternative names by type
        eku: null, // PENDING: the extended key usages, sorted
        key: { algorithm: null, size: null, curve: null }, // PENDING: the public key's algorithm, size and curve
        sha256: sha256(certificate.raw),
        spkiSha256: sha256(spki),
        derived: { daysRemaining: 0, lifetimeFraction: null }, // PENDING: values computed from the observation instant
    };
}

/** @param {Uint8Array} bytes */
function sha256(bytes) {
    return createHash("sha256").update(bytes).digest("hex");
}

/**
 * ISO 8601 UTC with second precision. `toISOString()` appends `.000` to a whole second, and
 * that is all this removes: a date with a fraction keeps it and fails the contract's pattern
 * instead of being rounded behind the caller's back.
 * @param {Date} date A valid date in years 0 to 9999.
 */
function timestamp(date) {
    return date.toISOString().replace(".000Z", "Z");
}

/**
 * The instant of the observation: the given date, or now, cut to the whole second.
 * @param {Date | undefined} given
 */
function instantOf(given) {
    const date = given === undefined ? new Date() : given;
    if (!types.isDate(date) || Number.isNaN(date.getTime())) {
        throw new TypeError("options.at must be a valid Date");
    }
    const whole = new Date(Math.floor(date.getTime() / 1000) * 1000);
    // Outside years 0 to 9999 toISOString() writes a signed six-digit year, which the contract rejects.
    if (!/^\d{4}-/.test(whole.toISOString())) {
        throw new TypeError("options.at must fall between the years 0 and 9999");
    }
    return whole;
}

/**
 * A copy of the given source, so later changes to the caller's object do not reach the result.
 * @param {Source | undefined} given
 * @returns {Source}
 */
function sourceOf(given) {
    if (given === undefined) return { kind: "bytes" };
    if (typeof given !== "object" || given === null || Array.isArray(given) || typeof given.kind !== "string" || given.kind === "") {
        throw new TypeError("options.source must be an object with a non-empty string kind");
    }
    return { ...given };
}
