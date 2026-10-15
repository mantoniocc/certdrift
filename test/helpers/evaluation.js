import { readFileSync } from "node:fs";
import { evaluate as evaluateObservation, inspect } from "../../src/index.js";

// What the tests of `evaluate` share: an observation whose target has the dates and usages a test
// needs, and the instants built from them. No test reads the clock, and none depends on a fixture's
// exact bytes, because `npm run fixtures` replaces them.

/**
 * `evaluate` with the arguments of a test: they are often wrong on purpose, and what comes back is
 * read property by property. The declared types are checked by the consumer in `npm run package:check`.
 * @type {(observation: any, policy: any, options?: any) => any}
 */
export const evaluate = evaluateObservation;

/** The instant the observations below are made at. */
export const AT = "2026-09-15T14:02:11Z";

/** @param {string} name File name in test/fixtures/. */
export function fixture(name) {
    return readFileSync(new URL(`../fixtures/${name}`, import.meta.url));
}

/**
 * An instant as text, moved by whole seconds.
 * @param {string} timestamp
 * @param {number} seconds
 */
export function shifted(timestamp, seconds) {
    return new Date(Date.parse(timestamp) + seconds * 1000).toISOString().replace(".000Z", "Z");
}

/**
 * An observation of `leaf-p256.pem` whose target has the given fields instead of its own, and, unless
 * the fields say otherwise, a validity that has started and not ended at `AT`: the fixtures' own
 * dates move with the day they are generated. Nothing else is changed, so `derived` keeps what the
 * real dates gave and disagrees with the new ones: the rules must not read it.
 * @param {Record<string, unknown>} [fields]
 * @param {string} [at]
 * @returns {any}
 */
export function observed(fields = {}, at = AT) {
    const observation = inspect(fixture("leaf-p256.pem"), { at: new Date(at), source: { kind: "file", ref: "leaf-p256.pem" } });
    Object.assign(observation.certificates[observation.target], { notBefore: "2026-08-01T00:00:00Z", notAfter: "2026-10-30T00:00:00Z" }, fields);
    return observation;
}

/**
 * A policy made of the given entries.
 * @param {Record<string, unknown>} [entries]
 * @returns {any}
 */
export function policyOf(entries = {}) {
    return { contract: 1, ...entries };
}

/**
 * The result of one rule of the policy, by the name of its entry.
 * @param {any} check
 * @param {string} name
 * @returns {any}
 */
export function resultOf(check, name) {
    return check.results.find((/** @type {any} */ result) => result.rule?.name === name);
}
