import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { PathSyntaxError, labelOf, parsePath, printable, undeclaredAt, valueAt } from "../bin/query.js";
import { validatorFor } from "./helpers/schema.js";

// The path parser and the schema walk take the schema as data, so they are tested on the real
// observation schema and on small schemas written here that use exactly one keyword each.

const schemaUrl = new URL("../schema/observation.schema.json", import.meta.url);
const examplesUrl = new URL("../schema/examples/observation/", import.meta.url);
const observationSchema = JSON.parse(readFileSync(schemaUrl, "utf8"));
const errorsOf = validatorFor("observation");

/** @param {string} path */
const declared = (path) => undeclaredAt(observationSchema, parsePath(path)) === -1;

/**
 * The examples are the reference documents of the contract.
 * @returns {{ name: string, document: any }[]}
 */
function examples() {
    const names = readdirSync(examplesUrl).filter((name) => name.endsWith(".json")).sort();
    assert.ok(names.length >= 9, `found ${names.length} examples`);
    return names.map((name) => ({ name, document: JSON.parse(readFileSync(new URL(name, examplesUrl), "utf8")) }));
}

/**
 * Every path a document has, as a person would type it: each field, each index, at every depth.
 * @param {unknown} value
 * @param {string} prefix
 * @returns {string[]}
 */
function pathsIn(value, prefix = "") {
    if (Array.isArray(value)) return value.flatMap((item, index) => [`${prefix}[${index}]`, ...pathsIn(item, `${prefix}[${index}]`)]);
    if (typeof value !== "object" || value === null) return [];
    return Object.entries(value).flatMap(([key, item]) => {
        const path = prefix === "" ? key : `${prefix}.${key}`;
        return [path, ...pathsIn(item, path)];
    });
}

// ---------------------------------------------------------------------------------------------
// The grammar

test("--query grammar: field names separated by dots, numeric indices in square brackets, and nothing else", () => {
    const steps = (/** @type {string} */ path) => parsePath(path).map((step) => ("name" in step ? step.name : step.index));
    assert.deepEqual(steps("target"), ["target"]);
    assert.deepEqual(steps("observation.source.kind"), ["observation", "source", "kind"]);
    assert.deepEqual(steps("certificates[0].san.dns[12]"), ["certificates", 0, "san", "dns", 12]);
    assert.deepEqual(steps("a[0][1][2]"), ["a", 0, 1, 2]);
    assert.deepEqual(steps("a[007]"), ["a", 7], "leading zeros are digits");

    // A step keeps the path as typed up to itself, which is what messages quote.
    assert.deepEqual(parsePath("certificates[0].san").map((step) => step.through), ["certificates", "certificates[0]", "certificates[0].san"]);

    // Nothing else is part of the language. Each of these is something a person may expect from
    // another tool, and reading it as a field name would turn a wish into a silent empty value.
    const refused = [
        "", ".", "a.", ".a", "a..b", "a[", "a[]", "a[0", "a[0]b", "a[0]]", "a]", "[0]", "a.[0]", "a[0].", "a[0]..b",
        "a[-1]", "a[+1]", "a[1.5]", "a[1e2]", "a[0x1]", "a[ 1 ]", "a[*]", "a[]x", "a[1:2]", "a[1,2]", 'a["b"]', "a['b']",
        "a[?(@.b)]", "a[?@.b==1]", "a[b]", "a[0][x]", "a.b[0].[1]", "a[0]x[1]", ".a == 1", "a[0]xy", "a]b", "a[0]]b", "a[0]b.c",
    ];
    for (const path of refused) assert.throws(() => parsePath(path), PathSyntaxError, JSON.stringify(path));

    // A function or an expression has no syntax of its own: it reads as field names with odd
    // characters in them, which the schema then rejects.
    for (const path of ["a|length", "length(a)", "select(.a)", "a == 1", "a + b", "a, b", "$.a", "@.a", "a b", "*", "a.*"]) {
        assert.doesNotThrow(() => parsePath(path), path);
        assert.notEqual(undeclaredAt(observationSchema, parsePath(path)), -1, path);
    }
});

test("an index too large to be a number is still an index, and it is past the end of every list", () => {
    const steps = parsePath(`a[${"9".repeat(400)}]`);
    assert.deepEqual(valueAt({ a: [1, 2] }, steps).found, false);
});

// ---------------------------------------------------------------------------------------------
// The schema walk

test("the schema walk follows only properties, items and local $ref to #/$defs, and anything else is unknown", () => {
    /** @param {unknown} schema @param {string} path */
    const walk = (schema, path) => undeclaredAt(schema, parsePath(path));

    // What it follows.
    assert.equal(walk({ properties: { a: { properties: { b: {} } } } }, "a.b"), -1);
    assert.equal(walk({ properties: { a: { items: { properties: { b: {} } } } } }, "a[3].b"), -1);
    assert.equal(walk({ properties: { a: { $ref: "#/$defs/x" } }, $defs: { x: { properties: { b: {} } } } }, "a.b"), -1);
    assert.equal(walk({ properties: { a: { $ref: "#/$defs/x" } }, $defs: { x: { items: { $ref: "#/$defs/y" } }, y: { properties: { b: {} } } } }, "a[0].b"), -1);
    // A $ref sits beside the other keywords in this draft, and both count.
    assert.equal(walk({ properties: { a: { $ref: "#/$defs/x", properties: { c: {} } } }, $defs: { x: { properties: { b: {} } } } }, "a.b"), -1);
    assert.equal(walk({ properties: { a: { $ref: "#/$defs/x", properties: { c: {} } } }, $defs: { x: { properties: { b: {} } } } }, "a.c"), -1);
    // The pointer is read as RFC 6901 reads it.
    assert.equal(walk({ properties: { a: { $ref: "#/$defs/a~1b~0c" } }, $defs: { "a/b~c": { properties: { b: {} } } } }, "a.b"), -1);
    // The step that is not declared is the one reported, wherever it is.
    assert.equal(walk({ properties: { a: { properties: { b: {} } } } }, "a.c"), 1);
    assert.equal(walk({ properties: { a: {} } }, "x.y.z"), 0);
    assert.equal(walk({ properties: { a: { items: {} } } }, "a[0][1]"), 2);

    // What it does not follow: each keyword alone would make `a.b` or `a[0]` reachable in a
    // schema validator, and none of them is interpreted here.
    const inner = { properties: { b: {} } };
    /** @type {Record<string, unknown>} */
    const ignored = {
        allOf: { properties: { a: { allOf: [inner] } } },
        anyOf: { properties: { a: { anyOf: [inner] } } },
        oneOf: { properties: { a: { oneOf: [inner] } } },
        "if/then": { properties: { a: { if: { type: "object" }, then: inner } } },
        else: { properties: { a: { if: { type: "string" }, else: inner } } },
        not: { properties: { a: { not: inner } } },
        additionalProperties: { properties: { a: { additionalProperties: {} } } },
        "additionalProperties schema": { properties: { a: { additionalProperties: inner } } },
        patternProperties: { properties: { a: { patternProperties: { "^b$": {} } } } },
        propertyNames: { properties: { a: { propertyNames: { const: "b" } } } },
        dependentSchemas: { properties: { a: { dependentSchemas: { x: inner } } } },
        unevaluatedProperties: { properties: { a: { unevaluatedProperties: inner } } },
        "required without properties": { properties: { a: { required: ["b"] } } },
        "enum of names": { properties: { a: { enum: ["b"] } } },
    };
    for (const [keyword, schema] of Object.entries(ignored)) {
        assert.equal(walk(schema, "a.b"), 1, `${keyword} is not interpreted`);
    }
    assert.equal(walk({ properties: { a: { prefixItems: [{}] } } }, "a[0]"), 1, "prefixItems is not interpreted");
    assert.equal(walk({ properties: { a: { items: [{}] } } }, "a[0]"), 1, "an array in items is not a schema");
    assert.equal(walk({ properties: { a: { contains: {} } } }, "a[0]"), 1, "contains is not interpreted");
    assert.equal(walk({ properties: { a: { items: false } } }, "a[0]"), 1, "items: false declares no item");
    assert.equal(walk({ properties: { a: false } }, "a"), 0, "a property that is false does not exist");
    assert.equal(walk({ properties: { a: true } }, "a"), -1, "a property that is true is declared");
    assert.equal(walk({ properties: { a: true } }, "a.b"), 1, "and there is nothing to walk into");

    // A reference that is not a local pointer into $defs leads nowhere, and does not throw.
    const references = [
        "https://example.com/schema.json#/$defs/x", "other.json", "#", "#/", "#/properties/x", "#/definitions/x", "#/$defs", "#/$defs/",
        "#/$defs/missing", "#/$defs/x/properties/missing", "#/$defs/%78", "#x", "#/$defs/x#", "",
        // The same length as the prefix of a local reference into $defs, with something else in it.
        "#/other/x", "#/$defz/x", "x/$defs/x", "$defs/x",
    ];
    for (const $ref of references) {
        const schema = { properties: { a: { $ref } }, $defs: { x: inner }, definitions: { x: inner } };
        assert.equal(walk(schema, "a.b"), 1, JSON.stringify($ref));
    }
    assert.equal(walk({ properties: { a: { $ref: 5 } } }, "a.b"), 1, "a $ref that is not a string");
    assert.equal(walk({ $ref: "#/$defs/x", $defs: { x: { properties: { a: {} } } } }, "a"), -1, "a reference at the root");
    assert.equal(walk({ $dynamicRef: "#x", properties: { a: {} } }, "a.b"), 1, "$dynamicRef is not interpreted");

    // A reference that leads back to itself ends instead of looping, and still gives what it holds.
    assert.equal(walk({ properties: { a: { $ref: "#/$defs/self" } }, $defs: { self: { $ref: "#/$defs/self", properties: { b: {} } } } }, "a.b"), -1);
    assert.equal(walk({ properties: { a: { $ref: "#/$defs/one" } }, $defs: { one: { $ref: "#/$defs/two" }, two: { $ref: "#/$defs/one" } } }, "a.b"), 1);
    // A recursive structure is walked as far as the path goes, and no further.
    const tree = { properties: { child: { $ref: "#/$defs/node" } }, $defs: { node: { properties: { child: { $ref: "#/$defs/node" } } } } };
    assert.equal(walk(tree, `child${".child".repeat(200)}`), -1);
    assert.equal(walk(tree, `child${".child".repeat(200)}.other`), 201);

    // What is not a schema at all does not throw either.
    for (const schema of [null, undefined, 1, "x", [], true, false, {}, { properties: null }, { properties: [] }, { properties: "a" }]) {
        assert.equal(walk(schema, "a"), 0, JSON.stringify(schema));
    }
});

test("a name that every object has in JavaScript is not a field unless the schema declares it", () => {
    const schema = { properties: { a: { properties: { b: { items: {} } } } } };
    for (const name of ["__proto__", "constructor", "toString", "hasOwnProperty", "valueOf", "prototype", "length"]) {
        assert.equal(undeclaredAt(schema, parsePath(name)), 0, name);
        assert.equal(undeclaredAt(schema, parsePath(`a.${name}`)), 1, `a.${name}`);
        assert.equal(undeclaredAt(schema, parsePath(`a.b[0].${name}`)), 3, `a.b[0].${name}`);
    }
    // A schema that does declare one of them is believed, and its own `__proto__` is an own key.
    const declaring = JSON.parse('{"properties":{"__proto__":{},"constructor":{}}}');
    assert.equal(undeclaredAt(declaring, parsePath("__proto__")), -1);
    assert.equal(undeclaredAt(declaring, parsePath("constructor")), -1);
    assert.equal(undeclaredAt(declaring, parsePath("toString")), 0);

    // The same holds for the document: only its own fields and indices are values.
    const document = JSON.parse('{"__proto__":"own","list":[1]}');
    assert.deepEqual(valueAt(document, parsePath("__proto__")), { found: true, value: "own" });
    assert.equal(valueAt({}, parsePath("__proto__")).found, false);
    assert.equal(valueAt({}, parsePath("constructor")).found, false);
    assert.equal(valueAt({ list: [1] }, parsePath("list.length")).found, false);
});

test("the observation schema declares every field of every example, and what it does not declare is unknown", () => {
    for (const { name, document } of examples()) {
        const paths = pathsIn(document);
        assert.ok(paths.length > 30, `${name} has ${paths.length} paths`);
        for (const path of paths) assert.ok(declared(path), `${name}: ${path} is in the document and the schema does not declare it`);
    }

    // The ones that run through $ref, and through $ref inside $ref.
    for (const path of ["observation.at", "observation.source.kind", "certificates[0].subject.cn", "certificates[1].issuer.dn", "certificates[0].san.ip[0]",
        "certificates[0].key.curve", "certificates[0].derived.daysRemaining", "warnings[0].code", "certificates[0].issuedBy[0]", "certificates[0].eku[0]"]) {
        assert.ok(declared(path), path);
    }
    for (const path of ["certificates[0].subject.cnn", "certificate", "Certificates", "certificates.sha256", "certificates[0][0]", "certificates[0].san.dns.x",
        "certificates[0].san.dns[0][0]", "certificates[0].sha256[0]", "target[0]", "target.x", "contract.x", "observation.source.kind.x", "warnings[0].code.x",
        "certificates[0].subject.dn.x", "certificates[0].derived.x", "certificates[0].key.x", "length", "$defs", "$defs.timestamp", "properties", "certificates.items"]) {
        assert.ok(!declared(path), path);
    }
});

test("a field the contract tolerates but the schema does not declare is valid in a document and unknown to the walk", () => {
    const { document } = /** @type {{ document: any }} */ (examples().find(({ name }) => name === "file-bundle-chain.json"));
    const extra = structuredClone(document);
    extra.certificates[0].customField = "kept";
    extra.observation.source.note = "kept";
    extra.future = { nested: [1] };

    // The schema validates the document with its extra fields, as the contract promises.
    assert.deepEqual(errorsOf(extra), []);
    // The walk is checked against the same schema, and it does not know them.
    for (const path of ["certificates[0].customField", "observation.source.note", "future", "future.nested[0]"]) {
        assert.deepEqual(pathsIn(extra).includes(path), true, `${path} is in the document`);
        assert.ok(!declared(path), path);
    }
    // The document still has them, so resolving the path would have found a value: only the check says no.
    assert.deepEqual(valueAt(extra, parsePath("certificates[0].customField")), { found: true, value: "kept" });
});

test("the label of a schema is its name and the contract version it fixes", () => {
    assert.equal(labelOf("observation", observationSchema), "observation v1");
    assert.equal(labelOf("delta", { properties: { contract: { const: 3 } } }), "delta v3");
    for (const schema of [{}, null, { properties: {} }, { properties: { contract: {} } }, { properties: { contract: { const: "1" } } }]) {
        assert.equal(labelOf("check-result", schema), "check-result", JSON.stringify(schema));
    }
});

// ---------------------------------------------------------------------------------------------
// Values

test("a path the schema declares leads nowhere in a document that is shorter, lacks the field or holds null on the way", () => {
    const document = { list: [10, 20], nothing: null, text: "x", object: { a: 1 }, empty: [] };
    const reason = (/** @type {string} */ path) => {
        const found = valueAt(document, parsePath(path));
        assert.equal(found.found, false, path);
        return "reason" in found ? found.reason : "";
    };

    assert.deepEqual(valueAt(document, parsePath("list[1]")), { found: true, value: 20 });
    assert.deepEqual(valueAt(document, parsePath("nothing")), { found: true, value: null }, "a null that is the value is a value");
    assert.equal(reason("list[2]"), "list has 2 items, so [2] is out of range");
    assert.equal(reason("empty[0]"), "empty has 0 items, so [0] is out of range");
    assert.equal(reason("list[99999]"), "list has 2 items, so [99999] is out of range");
    assert.equal(reason("missing"), 'the document has no field "missing"');
    assert.equal(reason("object.b"), 'object has no field "b"');
    assert.equal(reason("nothing[0]"), "nothing is null, which has no index [0]");
    assert.equal(reason("nothing.a"), 'nothing is null, which has no field "a"');
    assert.equal(reason("text.a"), 'text is a string, which has no field "a"');
    assert.equal(reason("object[0]"), "object is an object, which has no index [0]");
    assert.equal(reason("list.a"), 'list is an array, which has no field "a"');
    assert.equal(valueAt(null, parsePath("a")).found, false);
    assert.equal(valueAt(undefined, parsePath("a")).found, false);
});

test("--query prints a string as it is and anything else as compact JSON, with one newline", () => {
    assert.equal(printable("abc"), "abc\n");
    assert.equal(printable(""), "\n");
    assert.equal(printable('quote " and \\ and\ttab'), 'quote " and \\ and\ttab\n');
    assert.equal(printable("é ‮ \u001b"), "é ‮ \u001b\n", "the text of a string is not touched");
    assert.equal(printable(42), "42\n");
    assert.equal(printable(-0.5), "-0.5\n");
    assert.equal(printable(true), "true\n");
    assert.equal(printable(false), "false\n");
    assert.equal(printable(null), "null\n");
    assert.equal(printable([]), "[]\n");
    assert.equal(printable(["a", 1, null]), '["a",1,null]\n');
    assert.equal(printable({ a: 1, b: { c: ["d é"] } }), '{"a":1,"b":{"c":["d é"]}}\n');
    assert.equal(printable("two\nlines"), "two\nlines\n");
});
