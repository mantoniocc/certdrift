import { readFileSync } from "node:fs";
import { AmbiguousTargetError, diff, inspect } from "../../src/index.js";
import { validatorFor } from "./schema.js";

// The comparison material: a reference certificate and variants that each change one thing about
// it (`scripts/generate-certs.sh`, "Comparison material"). They are generated again with new keys
// and dates, so a test reads their observations and compares fields of those, and writes down
// only what the generator writes as text: the names, the usages and the common name.

export const fixtures = new URL("../fixtures/", import.meta.url);

/** The instant every observation of the material is made at. */
export const AT = new Date("2026-09-15T14:02:11Z");

/**
 * The observation of a fixture, whose source is the file.
 * @param {string} name
 * @param {{ select?: string }} [options]
 */
export function observe(name, options) {
    return inspect(readFileSync(new URL(name, fixtures)), { at: AT, source: { kind: "file", ref: name }, ...options });
}

/**
 * The observation of a fixture whose target is ambiguous, resolved with its first candidate.
 * @param {string} name
 */
export function observeResolved(name) {
    try {
        return observe(name);
    } catch (error) {
        if (!(error instanceof AmbiguousTargetError)) throw error;
        return observe(name, { select: error.candidates[0].sha256.slice(0, 16) });
    }
}

const delta = validatorFor("delta");

/**
 * The delta of two observations, which must validate against the schema.
 * @param {import("../../src/index.js").Observation} before
 * @param {import("../../src/index.js").Observation} after
 */
export function compare(before, after) {
    const result = diff(before, after);
    const errors = delta(result);
    if (errors.length > 0) throw new Error(`the delta does not validate: ${errors.join("; ")}\n${JSON.stringify(result, null, 2)}`);
    return result;
}
