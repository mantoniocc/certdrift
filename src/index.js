export { inspect } from "./inspect.js";
export { serializeObservation, serializeCheckResult, serializeDelta } from "./serialize.js";
export { outsideValidity } from "./derived.js";
export { policyProblems, entryOfCode, POLICY_ENTRIES } from "./policy.js";
export { evaluate } from "./evaluate.js";
export { matchesPrivateKey } from "./private-key.js";
export { ParseError, AmbiguousTargetError, PolicyError } from "./errors.js";
export { EXTENDED_KEY_USAGE_OIDS } from "./usage.js";

// The types of the package's public API. They are declared here, in the entry point, and not
// in the modules that build them and re-exported by alias: a consumer that emits declarations
// (`declaration: true`) and infers a value from `inspect()` gets error TS2883 for a type that
// is only an alias of one declared in another file, because the compiler cannot name that file
// from outside the package. Declared here, it writes `import("certdrift").Observation`. Only
// the types a consumer needs to name are declared here: `DistinguishedName` and
// `SubjectAltNames` are there because `subject`, `issuer` and `san` cannot be named without
// them, `PolicyProblem` because `policyProblems()` returns a list of them, and `Rule` and
// `EvaluateOptions` because a rule of the caller's own and the options of `evaluate()` have to be
// written down by whoever passes them, `PrivateKey` and `MatchesPrivateKeyOptions` because a key
// and the options of `matchesPrivateKey()` are built by the caller, and `Delta` and `Change`
// because `serializeDelta()` takes a delta that a consumer builds and reads. The shapes of
// `key`, `derived` and `observation` are written inline by the compiler.
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

/**
 * What a policy requires, as described by `schema/policy.schema.json`: a contract number and one
 * optional entry per kind of rule. An entry says how severe a failure is (`fail` unless it says
 * `warn`) and, where the rule takes a parameter, the `value`. `validityStarted`,
 * `validityNotEnded` and `matchesPrivateKey` take only a severity.
 * @typedef {object} Policy
 * @property {1} contract
 * @property {{ severity?: "fail" | "warn" }} [validityStarted]
 * @property {{ severity?: "fail" | "warn" }} [validityNotEnded]
 * @property {{ value: string, severity?: "fail" | "warn" }} [expiresWithin] Days or hours: `30d`, `72h`.
 * @property {{ value: number, severity?: "fail" | "warn" }} [maxLifetimeUsed] From 0 to 1.
 * @property {{ value: string[], severity?: "fail" | "warn" }} [expectEku]
 * @property {{ value: string[], severity?: "fail" | "warn" }} [ekuAllows]
 * @property {{ value: string[], severity?: "fail" | "warn" }} [rejectEku]
 * @property {{ value: string[], severity?: "fail" | "warn" }} [expectSan] DNS names and IP addresses.
 * @property {{ value: string, severity?: "fail" | "warn" }} [expectFingerprint] SHA-256, 64 lowercase hexadecimal characters.
 * @property {{ value: "end-entity", severity?: "fail" | "warn" }} [expectKind]
 * @property {{ severity?: "fail" | "warn" }} [matchesPrivateKey]
 */

/**
 * What one rule found. `code` is open: a rule of the consumer's own chooses its own. `status` is
 * closed on purpose, because a consumer that does not know one cannot tell a pass from a failure.
 * @typedef {object} Result
 * @property {string} code
 * @property {"pass" | "fail" | "warn"} status
 * @property {{ name: string, value?: unknown } | null} rule `null` only for `POLICY_EMPTY`.
 * @property {string} message
 * @property {unknown} [actual]
 * @property {unknown} [expected]
 */

/**
 * The output of a check, as described by `schema/check-result.schema.json`.
 * @typedef {object} CheckResult
 * @property {1} contract
 * @property {string} now The instant the rules were evaluated against.
 * @property {{ status: "pass" | "fail" | "warn", pass: number, warn: number, fail: number }} summary
 * @property {Result[]} results
 * @property {Policy} policy
 * @property {Observation} observation
 */

/**
 * One thing wrong with a policy, as `policyProblems` lists it. The message never quotes a value of
 * the policy other than a number in `contract`, because a policy may be shared and a value in the
 * wrong place may be a secret.
 * @typedef {object} PolicyProblem
 * @property {string} path Where, as a JSON Pointer (RFC 6901): "" is the policy itself.
 * @property {string} message What is wrong, in English.
 */

/**
 * A rule of the caller's own, passed to `evaluate` in `options.rules`. It gets the observation,
 * frozen all the way down, and `now`, the timestamp the result records. It answers at once: a
 * promise is not a result. What it returns is a result as above, except that `rule` may be left out
 * (`evaluate` writes `{ name }` with the function's name, or `rule-<n>` for an anonymous one). A rule
 * that throws, or returns something else, gives a `RULE_ERROR` result under its name. `POLICY_EMPTY`
 * and `RULE_ERROR` are the library's own codes, and a rule that returns one gets `RULE_ERROR`.
 * @typedef {(observation: Observation, now: string) => { code: string, status: "pass" | "fail" | "warn", rule?: { name: string, value?: unknown } | null, message: string, actual?: unknown, expected?: unknown }} Rule
 */

/**
 * @typedef {object} EvaluateOptions
 * @property {Date | string} [now] The instant to evaluate at, as a `Date` or a timestamp in the form
 *   the contract writes. It defaults to the observation's `at`, and is recorded cut to the whole second.
 * @property {readonly Rule[]} [rules] Rules of the caller's own, evaluated after the policy's in the
 *   order given.
 * @property {PrivateKey} [privateKey] Asks for the rule `matchesPrivateKey`: it is evaluated even when
 *   the policy does not list it, with severity `fail` unless the policy says otherwise. A policy that
 *   lists it needs this. It is read by that rule alone and is never in the result.
 */

/**
 * A private key as a file holds it. Only PEM is read.
 * @typedef {object} PrivateKey
 * @property {string | Uint8Array} material The text or the bytes of the file.
 * @property {string | undefined} [passphrase] Text, for a key that is encrypted. An empty string is a passphrase.
 */

/**
 * @typedef {object} MatchesPrivateKeyOptions
 * @property {"fail" | "warn"} [severity] `fail` unless it says `warn`; anything else is a `TypeError`.
 */

/**
 * One difference between the two sides of a delta, as described by `schema/delta.schema.json`.
 * `added` has only `after`, `removed` has only `before` and `changed` has both, and `null` is a
 * value. What the sides hold depends on the field (a string for the element of a set, a link of
 * the chain, the value of the observation), which is why they are `unknown`. `field` is open: it
 * names a field of the target certificate, or `chain`. `direction` is closed on purpose, because a
 * consumer that does not know one cannot tell which side holds the value.
 * @typedef {object} Change
 * @property {string} field
 * @property {"added" | "removed" | "changed"} direction
 * @property {unknown} [before]
 * @property {unknown} [after]
 */

/**
 * What changed between two observations, as described by `schema/delta.schema.json`. `before` is
 * the observation that was given first and `after` the one given second, for the whole document;
 * neither says which is older. `identical` is about the two targets only. A delta describes: it
 * has no class, no reason code and no status.
 * @typedef {object} Delta
 * @property {1} contract
 * @property {boolean} identical
 * @property {{ at: string, source: Source }} before
 * @property {{ at: string, source: Source }} after
 * @property {Change[]} changes
 */
