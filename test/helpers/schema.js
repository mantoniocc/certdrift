import { readFileSync, readdirSync } from "node:fs";
import Ajv2020 from "ajv/dist/2020.js";

// One Ajv instance for every schema, so every test validates with the same rules.
// strict: a misspelled keyword in a schema is an error, not something silently ignored.
// allErrors: report every failure in a document, not only the first one.

const ajv = new Ajv2020.default({strict: true, allErrors: true});

// import.meta.url is this file (test/helpers/), so schema/ is two levels up.
const schemaDirectory = new URL("../../schema/", import.meta.url);

// Every schema is registered before any is compiled, because a schema refers to the others by
// file name (the check result includes the observation and the policy) and Ajv resolves a
// reference against the schemas it already holds. Registering is not compiling: a schema is
// compiled, strictly, the first time a test asks for it.
/** @type {Map<string, string>} */
const ids = new Map();
for (const file of readdirSync(schemaDirectory).filter((name) => name.endsWith(".schema.json")).sort()) {
    const schema = JSON.parse(readFileSync(new URL(file, schemaDirectory), "utf8"));
    ajv.addSchema(schema);
    ids.set(file.slice(0, -".schema.json".length), schema.$id);
}

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

    const id = ids.get(name);
    if (id === undefined) throw new Error(`there is no schema/${name}.schema.json`);
    const validate = ajv.getSchema(id);
    if (validate === undefined) throw new Error(`schema/${name}.schema.json did not compile`);

    /** @param {unknown} document */
    const errorsOf = (document) => {
        if (validate(document)) return [];
        return (validate.errors ?? []).map((e) => `${e.instancePath || "/"} ${e.message}`);
    };

    cache.set(name, errorsOf);
    return errorsOf;
}
