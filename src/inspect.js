import { createHash } from "node:crypto";
import { types } from "node:util";
import { certificatesIn } from "./material.js";
import { chainOf } from "./chain.js";
import { subjectAltNames } from "./san.js";
import { commonName, distinguishedName } from "./names.js";
import { extendedKeyUsage } from "./usage.js";
import { publicKeyOf } from "./key.js";
import { derivedOf, timestampOf } from "./derived.js";
import { validityDate } from "./dates.js";
import { kindWarning } from "./kind-warning.js";

/** @import { CertificateObservation, Observation, Source, SubjectAltNames } from "./index.js" */

/**
 * Turns certificate material into an observation. Reads no files and opens no sockets.
 *
 * @param {string | Uint8Array} material One certificate or several, as PEM (a string, or bytes)
 *   or as a single DER certificate (bytes). Text between PEM blocks is ignored, so the output
 *   of `openssl s_client -showcerts` works as it is.
 * @param {{ source?: Source, at?: Date, select?: string }} [options]
 *   `source` defaults to `{ kind: "bytes" }`. `at` defaults to the moment of the call and is
 *   cut to the whole second, which is all a certificate date can express. `select` is the
 *   start of the sha256 of the certificate the observation is about, in either case: it
 *   resolves a material that has several candidates, and it must also match the target of one
 *   that has a single candidate. It only chooses `target`; the observation does not record it.
 * @returns {Observation}
 * @throws {import("./errors.js").ParseError} The material is empty, or one of its blocks is not
 *   a readable certificate. The message says which input block, counting from 1.
 * @throws {import("./errors.js").AmbiguousTargetError} More than one certificate signs no other
 *   one, or every one signs another, and `select` is absent or does not pick exactly one of
 *   them. It lists the candidates.
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
    const select = selectionOf(options?.select);

    const chain = chainOf(certificatesIn(material), select);
    const names = chain.members.map(({ certificate, block }) => subjectAltNames(certificate.subjectAltName, block));
    const certificates = chain.members.map((read, index) => describe(read, index, chain.issuedBy[index], names[index].names, at));
    const unrepresented = names.flatMap(({ unrepresented: found }, index) => found.map(({ type, count }) => ({
        code: "SAN_TYPE_UNREPRESENTED",
        certificate: index,
        message: `the subject alternative names hold ${count} ${type} ${count === 1 ? "entry" : "entries"}, which the observation does not represent`,
    })));

    // `kind` is Node.js's `ca`, which is false for a CA whose extensions it cannot read; the
    // warning says for which certificates that may have happened.
    const unreliable = chain.members.flatMap(({ certificate }, index) => kindWarning(certificate.raw, certificate.ca, index) ?? []);

    return {
        contract: 1,
        format: "x509",
        observation: { at: timestamp(at), source },
        target: chain.target,
        certificates,
        warnings: [...chain.warnings, ...unrepresented, ...unreliable],
    };
}

/**
 * One certificate's entry in the observation.
 *
 * `kind` follows Node.js's `ca`, which is false for a certificate marked CA whose Key Usage
 * lacks `keyCertSign`: that bit is what lets a key sign certificates, and verifiers such as
 * OpenSSL do not accept such a certificate as a CA either. It is also false for a CA that
 * carries a known extension twice or one that does not decode, and `kind` keeps that value:
 * `inspect()` adds a KIND_UNRELIABLE warning for those certificates.
 * @param {import("./material.js").CertificateRead} read
 * @param {number} index
 * @param {number[]} issuedBy
 * @param {SubjectAltNames} san
 * @param {Date} at
 * @returns {CertificateObservation}
 * @throws {import("./errors.js").ParseError} A validity date that is not a real instant.
 */
function describe({ certificate, block, spki, sha256: fingerprint }, index, issuedBy, san, at) {
    const notBefore = validityDate(certificate.validFromDate, certificate.validFrom, block, "notBefore");
    const notAfter = validityDate(certificate.validToDate, certificate.validTo, block, "notAfter");
    return {
        index,
        kind: certificate.ca ? "ca" : "end-entity",
        selfSigned: issuedBy.includes(index),
        issuedBy,
        subject: { cn: commonName(certificate.subject), dn: distinguishedName(certificate.subject) },
        issuer: { cn: commonName(certificate.issuer), dn: distinguishedName(certificate.issuer) },
        serial: certificate.serialNumber,
        notBefore: timestamp(notBefore),
        notAfter: timestamp(notAfter),
        san,
        eku: extendedKeyUsage(certificate.keyUsage),
        key: publicKeyOf(certificate.publicKey),
        sha256: fingerprint,
        spkiSha256: sha256(spki),
        derived: derivedOf(notBefore, notAfter, at),
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
    const seconds = Math.floor(date.getTime() / 1000);
    // The instant is written out, so the years the contract can write are the years it may have.
    timestampOf(seconds, "options.at");
    return new Date(seconds * 1000);
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

/**
 * An empty prefix would match every candidate, which is what an unset variable in a caller
 * produces, so it is refused instead of picking the only candidate by accident.
 * @param {string | undefined} given
 */
function selectionOf(given) {
    if (given === undefined) return undefined;
    if (typeof given !== "string" || given === "") {
        throw new TypeError("options.select must be a non-empty string");
    }
    return given;
}
