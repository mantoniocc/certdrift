import { X509Certificate, createHash } from "node:crypto";
import { ParseError } from "./errors.js";
import { splitMaterial } from "./material.js";

/**
 * @typedef {object} Source
 * @property {string} kind
 * @property {string} [ref]
 * @property {string | null} [servername]
 * @property {string} [provider]
 */

/**
 * @typedef {object} InspectOptions
 * @property {Source} [source] Where the material came from. Defaults to `{ kind: "bytes" }`.
 * @property {Date} [at] The instant of the observation. Defaults to the moment of the call.
 */

/**
 * An observation, as defined by `schema/observation.schema.json` (contract 1).
 * @typedef {ReturnType<typeof observationOf>} Observation
 */

const DAY_MS = 86_400_000;

/**
 * Inspects certificate material and describes it as an observation.
 *
 * Reads no files and opens no sockets: the caller supplies the bytes.
 *
 * @param {string | Uint8Array} material PEM text, or PEM or DER bytes, holding one certificate
 *   or several PEM blocks concatenated. Text between blocks is ignored.
 * @param {InspectOptions} [options]
 * @returns {Observation}
 * @throws {ParseError} when the material is empty or a block is not a valid certificate.
 * @throws {TypeError} when an argument has the wrong type.
 */
export function inspect(material, options = {}) {
    if (typeof material !== "string" && !(material instanceof Uint8Array)) {
        throw new TypeError("material must be a string, a Buffer or a Uint8Array");
    }
    const { source = { kind: "bytes" }, at = new Date() } = options;
    if (!(at instanceof Date) || Number.isNaN(at.getTime())) {
        throw new TypeError("options.at must be a valid Date");
    }

    const certificates = splitMaterial(material).map(({ block, data }) => {
        try {
            return new X509Certificate(data);
        } catch (cause) {
            throw new ParseError(`input block ${block} is not a valid certificate`, { block, cause });
        }
    });

    return observationOf(certificates, sourceOf(source), toSeconds(at));
}

/**
 * @param {X509Certificate[]} certificates
 * @param {Source} source
 * @param {Date} at
 */
function observationOf(certificates, source, at) {
    return {
        contract: /** @type {const} */ (1),
        format: /** @type {const} */ ("x509"),
        observation: { at: timestamp(at), source },
        // Provisional: the chain issue picks the target from the signatures between certificates.
        target: 0,
        certificates: certificates.map((certificate, index) => certificateOf(certificate, index, at)),
        warnings: /** @type {{ code: string, certificate: number | null, message: string }[]} */ ([]),
    };
}

/**
 * Only the fields the contract defines, in the contract's order.
 * @param {Source} source
 * @returns {Source}
 */
function sourceOf(source) {
    /** @type {Source} */
    const copy = { kind: source.kind };
    if (source.ref !== undefined) copy.ref = source.ref;
    if (source.servername !== undefined) copy.servername = source.servername;
    if (source.provider !== undefined) copy.provider = source.provider;
    return copy;
}

/**
 * Key order follows the examples in `schema/examples/observation/`.
 * @param {X509Certificate} certificate
 * @param {number} index
 * @param {Date} at
 */
function certificateOf(certificate, index, at) {
    const notBefore = certificate.validFromDate;
    const notAfter = certificate.validToDate;
    return {
        index,
        kind: certificate.ca ? "ca" : "end-entity",
        // Provisional: the chain issue decides both from verified signatures.
        selfSigned: false,
        issuedBy: /** @type {number[]} */ ([]),
        subject: nameOf(certificate.subject),
        issuer: nameOf(certificate.issuer),
        serial: certificate.serialNumber,
        notBefore: timestamp(notBefore),
        notAfter: timestamp(notAfter),
        // Provisional: the SAN issue parses the names.
        san: { dns: names(), ip: names(), email: names(), uri: names() },
        // Despite its name, `keyUsage` holds the OIDs of the Extended Key Usage extension.
        eku: certificate.keyUsage ? [...certificate.keyUsage].sort() : null,
        key: keyOf(certificate),
        sha256: sha256(certificate.raw),
        spkiSha256: sha256(certificate.publicKey.export({ type: "spki", format: "der" })),
        derived: {
            daysRemaining: round((notAfter.getTime() - at.getTime()) / DAY_MS, 1),
            lifetimeFraction: lifetimeFraction(notBefore, notAfter, at),
        },
    };
}

/** @returns {string[]} */
function names() {
    return [];
}

/**
 * Fields are picked one by one: `publicExponent` is a BigInt, which `JSON.stringify` rejects.
 * @param {X509Certificate} certificate
 */
function keyOf(certificate) {
    const { publicKey } = certificate;
    const details = publicKey.asymmetricKeyDetails;
    return {
        algorithm: publicKey.asymmetricKeyType ?? null,
        size: details?.modulusLength ?? null,
        curve: details?.namedCurve ?? null,
    };
}

/**
 * Node.js separates the components of a name with newlines and keeps a backslash before a comma
 * inside a value. A certificate without a subject gives `undefined`.
 * @param {string | undefined} name
 */
function nameOf(name) {
    const components = name ? name.split("\n") : [];
    const common = components.findLast((component) => component.startsWith("CN="));
    return {
        cn: common === undefined ? null : common.slice("CN=".length).replace(/\\(.)/g, "$1"),
        dn: components.join(", "),
    };
}

/**
 * `null` when the validity period has no duration (notAfter is not after notBefore).
 * @param {Date} notBefore
 * @param {Date} notAfter
 * @param {Date} at
 */
function lifetimeFraction(notBefore, notAfter, at) {
    const lifetime = notAfter.getTime() - notBefore.getTime();
    if (lifetime <= 0) return null;
    return round((at.getTime() - notBefore.getTime()) / lifetime, 2);
}

/**
 * @param {number} value
 * @param {number} decimals
 */
function round(value, decimals) {
    const factor = 10 ** decimals;
    // `|| 0` turns a rounded -0 into 0, so it serializes and compares as plain zero.
    return Math.round(value * factor) / factor || 0;
}

/** @param {Date} date */
function toSeconds(date) {
    return new Date(Math.floor(date.getTime() / 1000) * 1000);
}

/**
 * ISO 8601 UTC with second precision: certificates store no fraction, and `toISOString()`
 * would add `.000`.
 * @param {Date} date
 */
function timestamp(date) {
    return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

/** @param {string | Buffer} data */
function sha256(data) {
    return createHash("sha256").update(data).digest("hex");
}
