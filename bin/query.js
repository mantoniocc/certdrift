// The path language of --query and what it is checked against. Nothing here knows which
// document is printed: the schema and the document arrive as data, so every command that prints
// a document with its own schema can use the same functions.
//
// The schema is only navigated, never applied. There is no JSON Schema validator at run time
// (Ajv is a development dependency), and a subset written here would prove nothing about the
// schema. A path is "declared" when `properties`, `items` and local `$ref` lead to it; every
// other keyword is ignored, so a path that would need one of them is treated as unknown.

/**
 * A segment of a path: a field name, or a numeric index. `text` is the segment as typed and
 * `through` is the path as typed up to and including it, which is what messages quote.
 * @typedef {{ name: string, text: string, through: string } | { index: number, text: string, through: string }} Step
 */

/** The path is not made of field names, dots and numeric indices. */
export class PathSyntaxError extends Error {
    /** @param {string} message */
    constructor(message) {
        super(message);
        this.name = "PathSyntaxError";
    }
}

// Sticky, so each match starts exactly where the last one ended and nothing is skipped over.
// A name is anything but the characters that structure the path: what a field may be called is
// the schema's business, and a path that is not in it is rejected there.
const NAME = /[^.[\]]+/y;
const INDEX = /\[([0-9]+)\]/y;

/**
 * Reads a path: names separated by dots, each followed by any number of indices in square
 * brackets. Nothing else is part of the language: no filters, functions, expressions, slices,
 * negative indices or quoted names.
 * @param {string} text
 * @returns {Step[]}
 * @throws {PathSyntaxError}
 */
export function parsePath(text) {
    if (text === "") throw new PathSyntaxError("the path is empty");
    /** @type {Step[]} */
    const steps = [];
    let position = 0;
    for (;;) {
        NAME.lastIndex = position;
        const name = NAME.exec(text);
        if (name === null) throw new PathSyntaxError(`expected a field name at character ${position + 1}`);
        position = NAME.lastIndex;
        steps.push({ name: name[0], text: name[0], through: text.slice(0, position) });

        while (text[position] === "[") {
            INDEX.lastIndex = position;
            const index = INDEX.exec(text);
            if (index === null) throw new PathSyntaxError(`expected a number and "]" after "[" at character ${position + 1}`);
            position = INDEX.lastIndex;
            // Digits beyond the safe integers become a huge number, which is just past the end of any list.
            steps.push({ index: Number(index[1]), text: index[0], through: text.slice(0, position) });
        }

        if (position === text.length) return steps;
        if (text[position] !== ".") throw new PathSyntaxError(`expected "." or "[" at character ${position + 1}`);
        position += 1;
    }
}

/**
 * @param {unknown} value
 * @returns {value is Record<string, unknown>}
 */
function isObject(value) {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

const DEFS = "#/$defs/";

/**
 * The schema a local `$ref` into `$defs` points to, or `undefined` when the reference is
 * anything else: another document, `#/definitions`, a fragment that is not a pointer.
 * The pointer is read as RFC 6901 says (`~1` is `/`, `~0` is `~`) and not percent-decoded.
 * @param {unknown} root
 * @param {string} reference
 */
function resolve(root, reference) {
    if (!reference.startsWith(DEFS)) return undefined;
    let node = root;
    for (const token of ["$defs", ...reference.slice(DEFS.length).split("/")]) {
        const key = token.replaceAll("~1", "/").replaceAll("~0", "~");
        if (!isObject(node) && !Array.isArray(node)) return undefined;
        if (!Object.hasOwn(node, key)) return undefined;
        node = /** @type {Record<string, unknown>} */ (node)[key];
    }
    return node;
}

/**
 * The schema objects that apply at a node: itself and whatever its `$ref` leads to, which in
 * this draft sits beside the other keywords instead of replacing them. A reference that points
 * back to a schema already visited adds nothing.
 * @param {unknown} node
 * @param {unknown} root
 * @param {Set<unknown>} [visited]
 * @returns {Record<string, unknown>[]}
 */
function applying(node, root, visited = new Set()) {
    if (!isObject(node) || visited.has(node)) return [];
    visited.add(node);
    const referenced = typeof node.$ref === "string" ? applying(resolve(root, node.$ref), root, visited) : [];
    return [node, ...referenced];
}

/**
 * Where a path stops being declared by the schema.
 *
 * Only `properties`, `items` and local `$ref` into `$defs` are followed. A name step is declared
 * when `properties` has it as its own key; an index step when `items` is a schema. `allOf`,
 * `if`/`then`, `anyOf`, `oneOf`, `additionalProperties`, `patternProperties`, `prefixItems` and
 * the rest contribute nothing, so what they would allow is unknown here.
 * @param {unknown} schema
 * @param {Step[]} steps
 * @returns {number} The position of the first step that is not declared, or -1 when all are.
 */
export function undeclaredAt(schema, steps) {
    /** @type {unknown[]} */
    let nodes = [schema];
    for (const [position, step] of steps.entries()) {
        /** @type {unknown[]} */
        const next = [];
        for (const node of nodes.flatMap((candidate) => applying(candidate, schema))) {
            if ("name" in step) {
                if (isObject(node.properties) && Object.hasOwn(node.properties, step.name)) next.push(node.properties[step.name]);
            } else if (isObject(node.items)) {
                next.push(node.items);
            }
        }
        // `false` declares that the field can not exist. `true` declares it with nothing to walk into.
        nodes = next.filter((node) => node !== false);
        if (nodes.length === 0) return position;
    }
    return -1;
}

/**
 * How a schema is named in messages: its file's name and the contract version it fixes.
 * @param {string} name The schema's file name without `.schema.json`.
 * @param {unknown} schema
 */
export function labelOf(name, schema) {
    const contract = isObject(schema) && isObject(schema.properties) && isObject(schema.properties.contract) ? schema.properties.contract.const : undefined;
    return typeof contract === "number" ? `${name} v${contract}` : name;
}

/** @param {unknown} value */
function describe(value) {
    if (value === null) return "null";
    if (Array.isArray(value)) return "an array";
    return typeof value === "object" ? "an object" : `a ${typeof value}`;
}

/**
 * Follows a path through a document. A path the schema declares can still lead nowhere in one
 * document: the list is shorter, an optional field is absent, or a value on the way is null.
 * @param {unknown} document
 * @param {Step[]} steps
 * @returns {{ found: true, value: unknown } | { found: false, reason: string }}
 */
export function valueAt(document, steps) {
    let value = document;
    let where = "the document";
    for (const step of steps) {
        if ("name" in step) {
            if (!isObject(value)) return { found: false, reason: `${where} is ${describe(value)}, which has no field "${step.name}"` };
            if (!Object.hasOwn(value, step.name)) return { found: false, reason: `${where} has no field "${step.name}"` };
            value = value[step.name];
        } else {
            if (!Array.isArray(value)) return { found: false, reason: `${where} is ${describe(value)}, which has no index ${step.text}` };
            if (!(step.index < value.length)) return { found: false, reason: `${where} has ${value.length} ${value.length === 1 ? "item" : "items"}, so ${step.text} is out of range` };
            value = value[step.index];
        }
        where = step.through;
    }
    return { found: true, value };
}

/**
 * What a value prints as: a string as it is, without quotes; anything else as compact JSON.
 * The text of a string is not touched, because a script captures exactly what is printed.
 * @param {unknown} value
 */
export function printable(value) {
    return `${typeof value === "string" ? value : JSON.stringify(value)}\n`;
}
