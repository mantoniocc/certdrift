import { types } from "node:util";
import { instant, timestampOf } from "./derived.js";
import { PolicyError } from "./errors.js";
import { copyJson, dataOf, isPlain } from "./json.js";
import { ENTRIES, policyProblems } from "./policy.js";
import { assertSpki, privateKeyOf } from "./private-key.js";
import { RULES } from "./rules.js";

/** @import { CheckResult, Observation, Result } from "./index.js" */
/** @import { Target } from "./rules.js" */

/** The two entries evaluated whether the policy lists them or not. */
const ALWAYS = ["validityStarted", "validityNotEnded"];

/** The codes `evaluate` keeps for itself: an own rule cannot give them. */
const RESERVED = ["POLICY_EMPTY", "RULE_ERROR"];

const CODE = /^[A-Z][A-Z0-9_]*$/;

/**
 * Applies a policy to an observation and says, for each requirement, what was found.
 *
 * Every rule is about the target of the observation. The time rules decide from the certificate's
 * original dates and `now`, which is the observation's `at` unless `options.now` says another
 * instant. A failed rule is a result with status `fail` (or `warn`, if its entry says so), never an
 * exception: it throws only for a wrong call.
 *
 * Nothing the caller passed is modified, and nothing in the result is shared with it. A rule of
 * the caller's own gets a frozen copy of the observation, so it cannot change what the next rule
 * or the result sees. The same arguments give the same result, as nothing here reads the clock;
 * a rule that does is the caller's own.
 *
 * What a result may hold is what `serializeCheckResult` writes and the schema validates: JSON.
 * A rule of the caller's own that gives anything else (a function, a BigInt, `NaN`, a value that
 * contains itself) is answered by a `RULE_ERROR` result under its name, and the check goes on.
 *
 * With `options.privateKey` the rule `matchesPrivateKey` is evaluated, whether the policy lists it
 * or not (with severity `fail` unless it does). The key and its passphrase are read by that rule
 * alone: they are not copied, not given to a rule of the caller's own and not in the result.
 *
 * @param {Observation} observation As `inspect()` returns it.
 * @param {import("./index.js").Policy} policy A valid policy, as `policyProblems` says. The entry
 *   `matchesPrivateKey` needs a private key, so a policy that lists it is refused unless
 *   `options.privateKey` is given.
 * @param {import("./index.js").EvaluateOptions} [options]
 * @returns {CheckResult}
 * @throws {PolicyError} The policy is not valid, or it lists `matchesPrivateKey` and no key is
 *   given. `problems` says what is wrong and where.
 * @throws {TypeError} `observation` is not an observation this function can read, `options.now`
 *   is not an instant between the years 0 and 9999, `options.rules` is not a list of functions, or
 *   `options.privateKey` is not a `{ material, passphrase }` with text or bytes and text.
 */
export function evaluate(observation, policy, options) {
    if (options !== undefined && (typeof options !== "object" || options === null)) {
        throw new TypeError("options must be an object");
    }
    // Each property is read once: a getter that answers differently each time would otherwise
    // make the names, the instant and the rules disagree.
    const givenNow = options?.now;
    const own = ownRulesOf(options?.rules);
    const givenKey = options?.privateKey;
    const key = givenKey === undefined ? undefined : privateKeyOf(givenKey, "options.privateKey");
    const { copy, frozen, target, at } = observationOf(observation, key !== undefined);

    const now = givenNow === undefined ? at : instant(givenNow, "options.now");
    const nowText = timestampOf(now, "options.now");
    const read = policyOf(policy, key !== undefined);

    /** @type {Result[]} */
    const results = [];
    /** @type {Record<string, unknown>} */
    const applied = { contract: 1 };
    let listed = 0;
    for (const [entry, kind, [code]] of ENTRIES) {
        const always = ALWAYS.includes(entry);
        // A key asks for its rule, which a policy that does not list it gets with severity `fail`.
        // A policy that lists it without a key was refused above.
        const asked = entry === "matchesPrivateKey" && key !== undefined;
        if (read[entry] === undefined && !always && !asked) continue;
        if (!always) listed += 1;

        const written = /** @type {{ value?: unknown, severity?: string }} */ (read[entry] ?? {});
        const severity = written.severity === "warn" ? "warn" : "fail";
        const hasValue = kind !== "none";
        applied[entry] = hasValue ? { value: clone(written.value), severity } : { severity };

        const found = RULES[entry]({
            target: /** @type {Target} */ (target.certificate),
            notBefore: target.notBefore,
            notAfter: target.notAfter,
            now,
            nowText,
            value: written.value,
            privateKey: key,
        });
        // The entry's first code is the one of a rule that has only one. A rule with more says
        // which it found.
        /** @type {Result} */
        const result = {
            code: found.code ?? code,
            status: found.holds ? "pass" : severity,
            rule: hasValue ? { name: entry, value: clone(written.value) } : { name: entry },
            message: found.message,
        };
        if (found.actual !== undefined) result.actual = clone(found.actual);
        if (found.expected !== undefined) result.expected = clone(found.expected);
        results.push(result);
    }

    for (const rule of own) results.push(run(rule, frozen, nowText));

    if (listed === 0 && own.length === 0) {
        results.push({
            code: "POLICY_EMPTY",
            status: "warn",
            rule: null,
            message: "the policy lists no rule besides the validity of the certificate, so almost nothing was checked",
        });
    }

    const count = (/** @type {string} */ status) => results.filter((result) => result.status === status).length;
    const fail = count("fail");
    const warn = count("warn");
    return {
        contract: 1,
        now: nowText,
        summary: { status: fail > 0 ? "fail" : warn > 0 ? "warn" : "pass", pass: count("pass"), warn, fail },
        results,
        policy: /** @type {import("./index.js").Policy} */ (applied),
        observation: /** @type {Observation} */ (copy),
    };
}

/**
 * A copy that shares nothing with the original, of a value this module wrote itself and that
 * therefore holds only JSON.
 * @param {unknown} value
 * @returns {unknown}
 */
function clone(value) {
    return /** @type {{ ok: true, value: unknown }} */ (copyJson(value)).value;
}

// ---------------------------------------------------------------------------------------------
// The policy

/**
 * The entries of the policy, read once and checked again on what was read.
 *
 * `policyProblems` refuses what JSON cannot hold, so the entries can be read without worrying
 * about a function or an accessor. They are read into new objects and checked once more, so that
 * what the rules decide on is what was checked even if the policy is an object that answers
 * differently each time it is read.
 * @param {unknown} given
 * @param {boolean} hasKey Whether a private key was given, which `matchesPrivateKey` needs.
 * @returns {Record<string, unknown>} The entries the policy lists, each with only the properties this
 *   version reads.
 * @throws {PolicyError}
 */
function policyOf(given, hasKey) {
    let problems = policyProblems(given);
    /** @type {Record<string, unknown>} */
    let read = {};
    if (problems.length === 0) {
        const entries = entriesOf(given);
        if (entries === null) {
            problems = [{ path: "", message: "the policy cannot be read as a JSON object" }];
        } else {
            read = entries;
            problems = policyProblems({ contract: 1, ...entries });
        }
    }
    // Reported with the other problems, so that fixing the policy takes one pass.
    if (!hasKey && listsPrivateKey(given) && !problems.some((problem) => problem.path === "/matchesPrivateKey")) {
        problems = [...problems, { path: "/matchesPrivateKey", message: "needs a private key, and none is given" }];
    }
    if (problems.length > 0) throw new PolicyError(problems);
    return read;
}

/**
 * @param {unknown} given
 * @returns {Record<string, unknown> | null} `null` when the policy cannot be read.
 */
function entriesOf(given) {
    try {
        const policy = /** @type {Record<string, unknown>} */ (given);
        /** @type {Record<string, unknown>} */
        const read = {};
        for (const [name, kind] of ENTRIES) {
            if (!Object.hasOwn(policy, name)) continue;
            const entry = /** @type {Record<string, unknown>} */ (dataOf(policy, name));
            /** @type {Record<string, unknown>} */
            const copy = {};
            if (Object.hasOwn(entry, "severity")) copy.severity = dataOf(entry, "severity");
            if (kind !== "none") {
                const value = copyJson(dataOf(entry, "value"));
                if (!value.ok) return null;
                copy.value = value.value;
            }
            read[name] = copy;
        }
        return read;
    } catch {
        return null;
    }
}

/**
 * @param {unknown} given
 * @returns {boolean}
 */
function listsPrivateKey(given) {
    try {
        return isPlain(given) && Object.hasOwn(given, "matchesPrivateKey");
    } catch {
        return false;
    }
}

// ---------------------------------------------------------------------------------------------
// The observation

/**
 * What `evaluate` reads of an observation, checked, and a copy for the result and a frozen one for
 * the rules of the caller's own.
 *
 * Only what the rules read is checked here: the schema is the place that says whether an
 * observation is well formed, and a copy of it would be a second one that drifts. What is
 * checked is whether a rule could read it, so a wrong value is an error that names it and not a
 * wrong verdict.
 * @param {unknown} given
 * @param {boolean} hasKey Whether a private key was given, which reads `spkiSha256`.
 * @returns {{ copy: unknown, frozen: unknown, target: { certificate: unknown, notBefore: number, notAfter: number }, at: number }}
 * @throws {TypeError}
 */
function observationOf(given, hasKey) {
    if (typeof given !== "object" || given === null || Array.isArray(given)) {
        throw new TypeError("observation must be an object");
    }
    const copy = copyJson(given);
    if (!copy.ok) {
        throw new TypeError(`observation holds something JSON cannot, at ${copy.path === "" ? "the top" : copy.path}: it ${copy.reason}`);
    }
    const observation = /** @type {Record<string, any>} */ (copy.value);
    if (observation.contract !== 1) throw new TypeError("observation.contract must be 1");

    const at = timestampField(isPlain(observation.observation) ? observation.observation.at : undefined, "observation.observation.at");
    const { certificates, target: index } = observation;
    if (!Array.isArray(certificates) || !Number.isInteger(index) || !isPlain(certificates[index])) {
        throw new TypeError("observation.target must be the position of a certificate in observation.certificates");
    }
    const certificate = /** @type {Record<string, any>} */ (certificates[index]);
    const name = `observation.certificates[${index}]`;
    const notBefore = timestampField(certificate.notBefore, `${name}.notBefore`);
    const notAfter = timestampField(certificate.notAfter, `${name}.notAfter`);
    const strings = (/** @type {unknown} */ list) => Array.isArray(list) && list.every((item) => typeof item === "string");
    if (typeof certificate.kind !== "string") throw new TypeError(`${name}.kind must be a string`);
    if (typeof certificate.sha256 !== "string") throw new TypeError(`${name}.sha256 must be a string`);
    if (certificate.eku !== null && !strings(certificate.eku)) throw new TypeError(`${name}.eku must be null or a list of strings`);
    if (!isPlain(certificate.san) || !strings(certificate.san.dns) || !strings(certificate.san.ip)) {
        throw new TypeError(`${name}.san must hold dns and ip as lists of strings`);
    }

    if (hasKey) assertSpki(certificate.spkiSha256, name);

    const frozen = /** @type {{ ok: true, value: unknown }} */ (copyJson(copy.value, { freeze: true }));
    return { copy: copy.value, frozen: frozen.value, target: { certificate, notBefore, notAfter }, at };
}

/**
 * @param {unknown} value
 * @param {string} name
 * @returns {number} Whole seconds.
 * @throws {TypeError}
 */
function timestampField(value, name) {
    try {
        return instant(value, name);
    } catch {
        // Said in the observation's words and not the argument's: a Date is an instant to
        // `instant`, and the observation only holds text, which the copy has already shown.
        throw new TypeError(`${name} must be a timestamp such as 2026-09-15T14:02:11Z`);
    }
}

// ---------------------------------------------------------------------------------------------
// Rules of the caller's own

/**
 * @typedef {object} Own
 * @property {Function} rule
 * @property {string} name
 */

/**
 * The rules of the caller's own with the names they run under, read before any of them runs.
 * @param {unknown} given
 * @returns {Own[]}
 * @throws {TypeError}
 */
function ownRulesOf(given) {
    if (given === undefined) return [];
    if (!Array.isArray(given)) throw new TypeError("options.rules must be a list of functions");
    return Array.from({ length: given.length }, (_, position) => {
        const rule = given[position];
        if (typeof rule !== "function") throw new TypeError(`options.rules[${position}] must be a function`);
        return { rule, name: nameOf(rule, position + 1) };
    });
}

/**
 * The name a rule runs under: the function's own, without the `bound ` that binding adds, or
 * `rule-<n>` counting from 1 when it has none, as a function written inline in a list has not.
 * @param {Function} rule
 * @param {number} number
 */
function nameOf(rule, number) {
    let name;
    try {
        name = dataOf(rule, "name");
    } catch {
        // A proxy that throws when it is asked about its name.
    }
    const plain = typeof name === "string" ? name.replace(/^(?:bound )+/, "") : "";
    return plain === "" ? `rule-${number}` : plain;
}

/**
 * Runs one rule of the caller's own and gives what it returned as a result, or `RULE_ERROR`.
 * @param {Own} own
 * @param {unknown} observation Frozen.
 * @param {string} now
 * @returns {Result}
 */
function run({ rule, name }, observation, now) {
    /** @type {unknown} */
    let returned;
    try {
        returned = rule(observation, now);
    } catch {
        return ruleError(name, "the rule threw an error instead of giving a result");
    }
    if (types.isPromise(returned)) {
        // A rule answers at once. Its rejection is not read and must not end the process, either.
        try {
            Promise.prototype.then.call(returned, undefined, () => {});
        } catch {
            // A promise whose species constructor throws: nothing is waiting for it.
        }
        return ruleError(name, "the rule returned a promise, and a rule must answer at once");
    }
    try {
        return resultOf(returned, name);
    } catch (error) {
        return ruleError(name, error instanceof Unusable ? error.message : "the result could not be read");
    }
}

/**
 * @param {string} name
 * @param {string} message
 * @returns {Result}
 */
function ruleError(name, message) {
    return { code: "RULE_ERROR", status: "fail", rule: { name }, message };
}

/** What is wrong with what a rule returned. The message is fixed text: it never holds a value. */
class Unusable extends Error {}

/**
 * What a rule of the caller's own returned, as a result of the shape every result has.
 *
 * Only own data properties are read, and a getter is never run: a result with one is refused, as
 * its answer could change from one read to the next. Anything but the five properties of a result
 * is left out, and `rule` with no `value`, and `actual` or `expected` that are `undefined`, are
 * written as an absent property, which is what a rule that has nothing to show means. `null` is a
 * value.
 * @param {unknown} returned
 * @param {string} name What to call the rule when its result does not say.
 * @returns {Result}
 * @throws {Unusable}
 */
function resultOf(returned, name) {
    if (typeof returned !== "object" || returned === null || Array.isArray(returned)) {
        throw new Unusable("the rule did not return a result: it must be an object with a code, a status and a message");
    }
    const code = read(returned, "code");
    if (typeof code !== "string" || !CODE.test(code)) {
        throw new Unusable("the rule did not return a result: its code must be capital letters, digits and underscores, starting with a letter");
    }
    if (RESERVED.includes(code)) {
        throw new Unusable(`the rule did not return a result: its code is one ${RESERVED.join(" and ")} keep for the library`);
    }
    const status = read(returned, "status");
    if (status !== "pass" && status !== "fail" && status !== "warn") {
        throw new Unusable("the rule did not return a result: its status must be pass, fail or warn");
    }
    const message = read(returned, "message");
    if (typeof message !== "string") {
        throw new Unusable("the rule did not return a result: its message must be a string");
    }

    /** @type {Result} */
    const result = { code, status, rule: { name }, message };
    const given = read(returned, "rule");
    if (given !== undefined && given !== null) {
        const ruleName = typeof given === "object" && !Array.isArray(given) ? read(given, "name") : undefined;
        if (typeof ruleName !== "string" || ruleName === "") {
            throw new Unusable("the rule did not return a result: its rule must be an object with a name");
        }
        result.rule = { name: ruleName };
        const value = /** @type {object} */ (given);
        const parameter = read(value, "value");
        if (parameter !== undefined) result.rule.value = writable(parameter, "rule.value");
    }
    const actual = read(returned, "actual");
    if (actual !== undefined) result.actual = writable(actual, "actual");
    const expected = read(returned, "expected");
    if (expected !== undefined) result.expected = writable(expected, "expected");
    return result;
}

/**
 * The value of an own property of a result, or `undefined` where it has none.
 * @param {object} object
 * @param {string} key
 * @returns {unknown}
 * @throws {Unusable} The property is an accessor.
 */
function read(object, key) {
    const descriptor = Object.getOwnPropertyDescriptor(object, key);
    if (descriptor === undefined) return undefined;
    if (!("value" in descriptor)) throw new Unusable("the rule did not return a result: a property of it is an accessor, which is never called");
    return descriptor.value;
}

/**
 * @param {unknown} value
 * @param {string} where
 * @returns {unknown}
 * @throws {Unusable}
 */
function writable(value, where) {
    const copy = copyJson(value);
    if (!copy.ok) throw new Unusable(`the rule did not return a result: its ${where} cannot be written as JSON`);
    return copy.value;
}
