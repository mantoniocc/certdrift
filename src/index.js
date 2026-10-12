export { inspect } from "./inspect.js";
export { serializeObservation } from "./serialize.js";
export { ParseError, AmbiguousTargetError } from "./errors.js";
export { EXTENDED_KEY_USAGE_OIDS } from "./usage.js";

// The types of the package's public API. They are declared here, in the entry point, and not
// in the modules that build them and re-exported by alias: a consumer that emits declarations
// (`declaration: true`) and infers a value from `inspect()` gets error TS2883 for a type that
// is only an alias of one declared in another file, because the compiler cannot name that file
// from outside the package. Declared here, it writes `import("certdrift").Observation`. Only
// the types a consumer needs to name are declared here: `DistinguishedName` and
// `SubjectAltNames` are there because `subject`, `issuer` and `san` cannot be named without
// them. The shapes of `key`, `derived` and `observation` are written inline by the compiler.
// Adding a type here is additive for the people who use the package; removing or renaming one
// is not.
//
// Where the schema says a value is open (`kind`, `code`, `algorithm`), the type is `string`,
// never a union of the values known today.

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
 * @property {SubjectAltNames} san
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
 * @typedef {object} SubjectAltNames
 * @property {string[]} dns Lowercase, sorted.
 * @property {string[]} ip Canonical form, sorted.
 * @property {string[]} email Sorted.
 * @property {string[]} uri Sorted.
 */
