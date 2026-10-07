import { readFileSync } from "node:fs";
import Ajv2020 from "ajv/dist/2020.js";

// One Ajv instance for every schema, so every test validates with the same rules.
// strict: a misspelled keyword in a schema is an error, not something silently ignored.
// allErrors: report every failure in a document, not only the first one.

const ajv = new Ajv2020.default({strict: true, allErrors: true});

/** @type {Map<string, (document: unknown) => string[]>} */
const cache = new Map();

/**
 * Returns a function that lists every reason a document fails `schema/<name>.schema.json`.
 * An empty list means the document is valid.
 *
 * Each schema is compiled once and reused: Ajv registers a schema under its `$id` and
 * throws if asked to compile a second schema with the same `$id`.
 *
 * @param {string} name Schema file name without `.schema.json`, e.g. `"observation"`.
 * @returns {(document: unknown) => string[]}
 */
export function validatorFor(name) {
    const cached = cache.get(name);
    if (cached) return cached;

    // import.meta.url is this file (test/helpers/), so schema/ is two levels up.
    const url = new URL(`../../schema/${name}.schema.json`, import.meta.url);
    const validate = ajv.compile(JSON.parse(readFileSync(url, "utf8")));

    /** @param {unknown} document */
    const errorsOf = (document) => {
        if (validate(document)) return [];
        return (validate.errors ?? []).map((e) => `${e.instancePath || "/"} ${e.message}`);
    };

    cache.set(name, errorsOf);
    return errorsOf;
}

