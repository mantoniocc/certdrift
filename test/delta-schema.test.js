import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { validatorFor } from "./helpers/schema.js";
import { AmbiguousTargetError, inspect, serializeDelta } from "../src/index.js";

const examplesUrl = new URL("../schema/examples/delta/", import.meta.url);
const schemaUrl = new URL("../schema/delta.schema.json", import.meta.url);
const observationUrl = new URL("../schema/observation.schema.json", import.meta.url);
const readmeUrl = new URL("../README.md", import.meta.url);

/** @param {URL} url */
function readJson(url) {
    return JSON.parse(readFileSync(url, "utf8"));
}

const errorsOf = validatorFor("delta");
const schema = readJson(schemaUrl);
const observationSchema = readJson(observationUrl);
const readme = readFileSync(readmeUrl, "utf8");

/** @param {string} text @param {RegExp} pattern */
function says(text, pattern) {
    assert.match(text.replace(/\s+/g, " "), pattern);
}

/** @param {string} name */
const example = (name) => readJson(new URL(name, examplesUrl));

const exampleFiles = readdirSync(examplesUrl).filter((name) => name.endsWith(".json")).sort();

// The fields the schema lists, in the order it lists them: the order of `changes`.
const KNOWN_FIELDS = /** @type {string[]} */ (
    /Known values: (.*?), and chain,/.exec(schema.$defs.change.properties.field.description)?.[1].split(", ")
).concat("chain");
const SETS = ["san.dns", "san.ip", "san.email", "san.uri", "eku"];
const DIRECTIONS = ["removed", "added", "changed"];

const SHA = (/** @type {string} */ digit) => digit.repeat(64);
const side = () => ({ at: "2026-09-15T14:02:11Z", source: { kind: "file", ref: "deployed.pem" } });

/**
 * A valid delta around some changes.
 * @param {unknown[]} changes
 * @param {boolean} [identical]
 * @returns {any}
 */
function delta(changes, identical = false) {
    return { contract: 1, identical, before: side(), after: side(), changes };
}

/** @param {unknown} change */
const errorsOfChange = (change) => errorsOf(delta([change]));

test("the delta schema compiles in strict mode, is draft 2020-12 with its own $id, tolerates unknown properties and requires contract 1", () => {
    assert.equal(typeof errorsOf, "function");
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
    assert.match(schema.$id, /\/schema\/delta\.schema\.json$/);
    assert.deepEqual(
        schema.$id.replace("delta", "observation"),
        observationSchema.$id,
        "the $id follows the pattern of the others",
    );
    assert.equal(schema.properties.contract.const, 1);
    assert.ok(schema.required.includes("contract"));

    // Unknown properties are tolerated at every level the contract names.
    const document = example("san-added.json");
    document.future = { nested: [1] };
    document.before.note = "kept";
    document.before.source.future = true;
    document.changes[0].note = "kept";
    document.changes[1].future = [1];
    assert.deepEqual(errorsOf(document), []);

    for (const contract of [2, 0, "1", 1.5, null, undefined]) {
        const wrong = example("san-added.json");
        wrong.contract = contract;
        assert.ok(errorsOf(wrong).some((error) => error.startsWith("/contract ") || error.includes("contract")), String(contract));
    }
});

test("a Delta without contract, identical, before, after or changes is rejected, and so is a side without at or source", () => {
    assert.deepEqual(schema.required, ["contract", "identical", "before", "after", "changes"]);
    for (const field of schema.required) {
        const document = example("san-added.json");
        delete document[field];
        assert.ok(errorsOf(document).some((error) => error.includes(field)), field);
    }
    for (const side of ["before", "after"]) {
        for (const field of ["at", "source"]) {
            const document = example("san-added.json");
            delete document[side][field];
            assert.ok(errorsOf(document).some((error) => error.startsWith(`/${side} `) && error.includes(field)), `${side}.${field}`);
        }
    }
    for (const identical of ["true", 1, null]) {
        const document = example("san-added.json");
        document.identical = identical;
        assert.ok(errorsOf(document).some((error) => error.startsWith("/identical ")), String(identical));
    }
    assert.ok(errorsOf({ ...example("san-added.json"), changes: {} }).some((error) => error.startsWith("/changes ")));
});

test("the side of a Delta is the observation's own at and source, so a source of a kind that needs a ref without one is rejected", () => {
    const wrongAt = example("san-added.json");
    wrongAt.before.at = "2026-09-15";
    assert.ok(errorsOf(wrongAt).some((error) => error.startsWith("/before/at ")));
    const noRef = example("san-added.json");
    delete noRef.after.source.ref;
    assert.ok(errorsOf(noRef).some((error) => error.startsWith("/after/source ")));
    const noKind = example("san-added.json");
    delete noKind.after.source.kind;
    assert.ok(errorsOf(noKind).some((error) => error.startsWith("/after/source ")));
    const host = example("identical.json");
    assert.equal(host.before.source.kind, "host");
    delete host.before.source.servername;
    assert.ok(errorsOf(host).some((error) => error.startsWith("/before/source ")));
});

const REQUIRED_EXAMPLES = [
    "identical.json", "reissue-same-key.json", "key-rotated.json", "key-algorithm.json", "key-smaller.json",
    "san-added.json", "san-removed.json", "san-added-and-removed.json", "san-repeat-only.json",
    "eku-added.json", "eku-removed.json", "eku-emptied.json", "eku-to-null.json", "eku-from-null.json", "eku-null-to-empty.json", "eku-empty-to-null.json",
    "subject.json",
    "chain-replaced.json", "chain-dropped.json", "chain-added.json", "chain-reordered.json", "chain-dropped-and-reordered.json",
];

test("the delta examples cover the same certificate, a reissue that keeps the key, a rotated key, another algorithm, a smaller key, SAN names, Extended Key Usage in both directions between a list and null, the subject and the chain", () => {
    assert.deepEqual(exampleFiles, [...REQUIRED_EXAMPLES].sort());
});

for (const name of exampleFiles) {
    test(`delta example ${name} validates against the schema`, () => {
        assert.deepEqual(errorsOf(example(name)), []);
    });
}

test("the schema rejects a change with no field, one with a direction that is not added, removed or changed, and one with a side its direction says it does not have", () => {
    assert.deepEqual(schema.$defs.change.required, ["field", "direction"]);
    assert.deepEqual(schema.$defs.change.properties.direction.enum, ["added", "removed", "changed"]);

    assert.ok(errorsOfChange({ direction: "added", after: 1 }).some((error) => error.startsWith("/changes/0 ") && error.includes("field")), "no field");
    assert.ok(errorsOfChange({ field: "", direction: "added", after: 1 }).some((error) => error.startsWith("/changes/0/field ")), "empty field");
    assert.ok(errorsOfChange({ field: 1, direction: "added", after: 1 }).some((error) => error.startsWith("/changes/0/field ")), "field that is not text");
    assert.ok(errorsOfChange({ field: "serial", after: 1 }).some((error) => error.includes("direction")), "no direction");
    for (const direction of ["moved", "ADDED", "add", "", null, 1, ["added"], "replaced", "unchanged"]) {
        assert.ok(errorsOfChange({ field: "serial", direction, before: "a", after: "b" }).some((error) => error.startsWith("/changes/0/direction ")), JSON.stringify(direction));
    }

    // A side its direction says it does not have: added has no before, removed has no after.
    assert.ok(errorsOfChange({ field: "serial", direction: "added", before: "A", after: "B" }).some((error) => error.startsWith("/changes/0/before ")), "added with before");
    assert.ok(errorsOfChange({ field: "serial", direction: "added", before: null, after: "B" }).some((error) => error.startsWith("/changes/0/before ")), "added with a null before");
    assert.ok(errorsOfChange({ field: "serial", direction: "removed", before: "A", after: "B" }).some((error) => error.startsWith("/changes/0/after ")), "removed with after");
    assert.ok(errorsOfChange({ field: "serial", direction: "removed", before: "A", after: null }).some((error) => error.startsWith("/changes/0/after ")), "removed with a null after");

    // A side its direction says it has, missing.
    assert.ok(errorsOfChange({ field: "serial", direction: "added" }).some((error) => error.includes("after")), "added without after");
    assert.ok(errorsOfChange({ field: "serial", direction: "added", before: undefined }).some((error) => error.includes("after")), "added with neither");
    assert.ok(errorsOfChange({ field: "serial", direction: "removed" }).some((error) => error.includes("before")), "removed without before");
    assert.ok(errorsOfChange({ field: "serial", direction: "changed", before: "A" }).some((error) => error.includes("after")), "changed without after");
    assert.ok(errorsOfChange({ field: "serial", direction: "changed", after: "B" }).some((error) => error.includes("before")), "changed without before");
    assert.ok(errorsOfChange({ field: "serial", direction: "changed" }).some((error) => error.includes("before")), "changed with neither");

    // And the valid ones, null being a value on a side that exists.
    for (const change of [
        { field: "serial", direction: "added", after: "B" },
        { field: "serial", direction: "added", after: null },
        { field: "serial", direction: "removed", before: null },
        { field: "key.size", direction: "changed", before: null, after: 2048 },
        { field: "key.size", direction: "changed", before: 2048, after: null },
        { field: "kind", direction: "changed", before: "ca", after: "end-entity" },
    ]) {
        assert.deepEqual(errorsOfChange(change), [], JSON.stringify(change));
    }
});

test("a field this version does not know is a valid change, and the direction still decides which sides it has", () => {
    assert.deepEqual(errorsOfChange({ field: "future.field", direction: "added", after: { any: ["thing"] } }), []);
    assert.deepEqual(errorsOfChange({ field: "future.field", direction: "changed", before: 1, after: [2] }), []);
    assert.ok(errorsOfChange({ field: "future.field", direction: "added", before: 1, after: 2 }).length > 0);
    assert.ok(errorsOfChange({ field: "future.field", direction: "moved", after: 2 }).length > 0);
});

// ---------------------------------------------------------------------------------------------
// before and after

test("before is the observation given first and after the one given second, for the whole document; they say nothing about which is older, and the schema and the README say so", () => {
    const { description: before } = schema.properties.before;
    says(before, /the first observation given is before and the second is after, and a change's direction reads in that same sense \(removed means it was in before and is not in after\)/);
    says(before, /They say nothing about which observation is older: the at of before may be later than the at of after/);
    says(schema.properties.after.description, /See before/);
    says(schema.$defs.change.properties.direction.description, /Read in the sense of before and after, which says nothing about which is older/);

    says(readme, /The first observation given is `before` and the second is `after`, for the whole document\./);
    says(readme, /`removed` means the value was in `before` and is not in `after`/);
    says(readme, /`before` and `after` say nothing about which observation is older: `before\.at` can be later than `after\.at`/);

    // An example whose before was observed after its after, and one whose instants run the usual way.
    const later = example("chain-reordered.json");
    assert.ok(Date.parse(later.before.at) > Date.parse(later.after.at));
    assert.ok(Date.parse(example("san-added.json").before.at) < Date.parse(example("san-added.json").after.at));
    assert.deepEqual(errorsOf(later), []);
});

test("the properties declared beside the $ref to the observation's source are exactly the source's own properties", () => {
    const declared = schema.$defs.side.properties.source;
    assert.equal(declared.$ref, "observation.schema.json#/$defs/source");
    assert.equal(declared.type, "object");
    assert.deepEqual(Object.keys(declared.properties).sort(), Object.keys(observationSchema.$defs.source.properties).sort());
    assert.equal(schema.$defs.side.properties.at.$ref, "observation.schema.json#/$defs/timestamp");
    assert.deepEqual(schema.$defs.side.required, ["at", "source"]);
});

// ---------------------------------------------------------------------------------------------
// identical

/** @param {any} document */
const targetChanged = (document) => document.changes.some((/** @type {any} */ change) => change.field === "sha256");

test("identical is true exactly when the sha256 of both targets is the same: every example agrees, and an identical Delta can still have a chain change", () => {
    let identical = 0;
    let withChain = 0;
    for (const name of exampleFiles) {
        const document = example(name);
        assert.equal(document.identical, !targetChanged(document), name);
        if (document.identical) {
            identical += 1;
            // The same target has the same fields: only what was sent after it can differ.
            assert.ok(document.changes.every((/** @type {any} */ change) => change.field === "chain"), `${name}: an identical delta has a change of the target`);
            if (document.changes.length > 0) withChain += 1;
        } else {
            const change = document.changes.find((/** @type {any} */ item) => item.field === "sha256");
            assert.equal(change.direction, "changed");
            assert.notEqual(change.before, change.after, name);
        }
    }
    assert.ok(identical >= 4 && withChain >= 4, `${identical} identical, ${withChain} with a chain change`);

    // The same certificate on both sides: nothing about validity, serial or fingerprint.
    const same = example("identical.json");
    assert.equal(same.identical, true);
    assert.deepEqual(same.changes, []);

    // The same target with its intermediate on one side only.
    const dropped = example("chain-dropped.json");
    assert.equal(dropped.identical, true);
    assert.deepEqual(dropped.changes.map((/** @type {any} */ change) => `${change.field} ${change.direction}`), ["chain removed"]);

    says(schema.properties.identical.description, /true exactly when the sha256 of both targets is the same/);
    says(schema.properties.identical.description, /it can be true while changes is not empty/);
    says(readme, /`true` exactly when the `sha256` of both targets is the same/);
});

// ---------------------------------------------------------------------------------------------
// What a change is

test("a change names a field as a path in the target certificate, a direction, and only the sides its direction has; the always-there changes are ordinary", () => {
    for (const name of exampleFiles) {
        for (const change of example(name).changes) {
            assert.ok(KNOWN_FIELDS.includes(change.field), `${name}: ${change.field}`);
            assert.ok(DIRECTIONS.includes(change.direction), name);
            assert.deepEqual(
                Object.keys(change),
                ["field", "direction", ...(change.direction === "added" ? [] : ["before"]), ...(change.direction === "removed" ? [] : ["after"])],
                `${name}: ${change.field}`,
            );
        }
    }

    // Two different certificates always differ in these, and each is a change like any other.
    for (const name of exampleFiles.filter((file) => !example(file).identical)) {
        const fields = example(name).changes.map((/** @type {any} */ change) => change.field);
        assert.ok(fields.includes("sha256"), name);
        if (!name.startsWith("chain-")) for (const field of ["serial", "notBefore", "notAfter"]) assert.ok(fields.includes(field), `${name}: ${field}`);
    }
    // A reissue that keeps the key changes the serial, the validity and the fingerprint, not the key.
    const reissue = example("reissue-same-key.json").changes.map((/** @type {any} */ change) => change.field);
    assert.deepEqual(reissue, ["serial", "notBefore", "notAfter", "sha256"]);
});

test("a field that is not a set and not the chain is always changed, with both values, and each value fits what the observation says the field holds", () => {
    const certificate = observationSchema.$defs.certificate.properties;
    /** @type {Record<string, RegExp>} */
    const patterns = {
        serial: new RegExp(certificate.serial.pattern),
        notBefore: new RegExp(observationSchema.$defs.timestamp.pattern),
        notAfter: new RegExp(observationSchema.$defs.timestamp.pattern),
        sha256: new RegExp(observationSchema.$defs.sha256.pattern),
        spkiSha256: new RegExp(observationSchema.$defs.sha256.pattern),
        "key.algorithm": new RegExp(observationSchema.$defs.key.properties.algorithm.pattern),
    };
    let scalars = 0;
    for (const name of exampleFiles) {
        for (const change of example(name).changes) {
            if (SETS.includes(change.field) || change.field === "chain") continue;
            scalars += 1;
            assert.equal(change.direction, "changed", `${name}: ${change.field}`);
            assert.notDeepEqual(change.before, change.after, `${name}: ${change.field} did not change`);
            const pattern = patterns[change.field];
            if (pattern !== undefined) for (const value of [change.before, change.after]) assert.match(value, pattern, `${name}: ${change.field}`);
        }
    }
    assert.ok(scalars > 40, `${scalars} scalar changes`);

    // null is a value on a side that exists, and a null that becomes a number is a change, not an addition.
    const algorithm = example("key-algorithm.json").changes;
    assert.deepEqual(algorithm.find((/** @type {any} */ change) => change.field === "key.curve"), { field: "key.curve", direction: "changed", before: null, after: "P-256" });
    says(schema.$defs.change.properties.field.description, /key\.size going from null to 2048 is changed, not added/);
    says(readme, /`key\.size` going from `null` to `2048` is `changed`, with both sides present/);
});

test("a key rotated, a key reused, a smaller key and another algorithm are readable from the changes alone", () => {
    /** @param {string} name @param {string} field */
    const change = (name, field) => example(name).changes.find((/** @type {any} */ item) => item.field === field);

    // Rotated: the key's fingerprint changed, and its algorithm and size did not.
    assert.equal(change("key-rotated.json", "spkiSha256").direction, "changed");
    assert.equal(change("key-rotated.json", "key.algorithm"), undefined);
    assert.equal(change("key-rotated.json", "key.size"), undefined);
    // Reused: the targets differ and the key's fingerprint does not appear.
    assert.equal(change("reissue-same-key.json", "sha256").direction, "changed");
    assert.equal(change("reissue-same-key.json", "spkiSha256"), undefined);
    // Smaller, within the same algorithm: the size changed to a lower number and the algorithm did not.
    const smaller = change("key-smaller.json", "key.size");
    assert.ok(smaller.after < smaller.before);
    assert.equal(change("key-smaller.json", "key.algorithm"), undefined);
    // Another algorithm: the change names the algorithm on each side.
    assert.deepEqual(change("key-algorithm.json", "key.algorithm"), { field: "key.algorithm", direction: "changed", before: "rsa", after: "ec" });
    // The subject: its dn changed.
    assert.equal(change("subject.json", "subject.dn").direction, "changed");
    assert.equal(change("subject.json", "subject.cn"), undefined);
});

test("a Delta has no class, no reason code and no status, and the schema says it describes and does not judge", () => {
    /** @param {unknown} node @param {string[]} names */
    const propertyNames = (node, names = []) => {
        if (typeof node !== "object" || node === null) return names;
        if ("properties" in node && typeof node.properties === "object" && node.properties !== null) names.push(...Object.keys(node.properties));
        for (const value of Object.values(node)) propertyNames(value, names);
        return names;
    };
    const declared = new Set(propertyNames(schema));
    assert.deepEqual([...declared].sort(), ["after", "at", "before", "changes", "contract", "direction", "field", "identical", "kind", "position", "provider", "ref", "servername", "sha256", "source"]);
    for (const word of ["class", "code", "status", "severity", "reason", "verdict"]) assert.ok(!declared.has(word), word);

    for (const name of exampleFiles) {
        const document = example(name);
        assert.deepEqual(Object.keys(document), ["contract", "identical", "before", "after", "changes"], name);
    }
    says(schema.description, /A Delta describes and does not judge: it has no class, no reason code and no status/);
    says(readme, /A delta describes and does not judge\. It has no class, no reason code and no status/);
});

// ---------------------------------------------------------------------------------------------
// Sets

test("a set change names one element that differs, a name removed and another added are two changes, and a SAN list is never changed", () => {
    for (const name of exampleFiles) {
        for (const change of example(name).changes.filter((/** @type {any} */ item) => item.field.startsWith("san."))) {
            assert.notEqual(change.direction, "changed", name);
            assert.equal(typeof (change.direction === "added" ? change.after : change.before), "string", name);
        }
    }

    const both = example("san-added-and-removed.json").changes.filter((/** @type {any} */ change) => change.field === "san.dns");
    assert.deepEqual(both, [
        { field: "san.dns", direction: "removed", before: "old.example.com" },
        { field: "san.dns", direction: "added", after: "new.example.com" },
    ]);
    assert.deepEqual(example("san-added.json").changes.filter((/** @type {any} */ change) => change.field.startsWith("san.")).map((/** @type {any} */ change) => `${change.field} ${change.direction}`), ["san.dns added", "san.ip added"]);
    assert.deepEqual(example("san-removed.json").changes.filter((/** @type {any} */ change) => change.field.startsWith("san.")).map((/** @type {any} */ change) => `${change.field} ${change.direction}`), ["san.dns removed"]);

    // The schema refuses the whole list, a replacement, and a SAN list that changed.
    for (const field of ["san.dns", "san.ip", "san.email", "san.uri"]) {
        assert.deepEqual(errorsOfChange({ field, direction: "added", after: "x" }), [], field);
        assert.deepEqual(errorsOfChange({ field, direction: "removed", before: "x" }), [], field);
        assert.ok(errorsOfChange({ field, direction: "changed", before: "x", after: "y" }).some((error) => error.startsWith("/changes/0/direction ")), `${field} changed`);
        assert.ok(errorsOfChange({ field, direction: "added", after: ["x"] }).some((error) => error.startsWith("/changes/0/after ")), `${field} whole list`);
        assert.ok(errorsOfChange({ field, direction: "removed", before: ["x", "y"] }).some((error) => error.startsWith("/changes/0/before ")), `${field} whole list`);
        assert.ok(errorsOfChange({ field, direction: "added", after: null }).some((error) => error.startsWith("/changes/0/after ")), `${field} null`);
    }
    says(schema.$defs.change.properties.field.description, /A change in a set never merges a name that left and a name that arrived into a replacement: they are two changes/);
    says(readme, /a name that left and a name that arrived are two independent changes, `removed` and `added`, and the delta never merges them into a replacement/);
});

test("Extended Key Usage: a usage added or removed is its own change, a list to null is a widening that one changed change carries whole, and null to a list, [] included, is a narrowing, in both directions", () => {
    /** @param {string} name */
    const eku = (name) => example(name).changes.filter((/** @type {any} */ change) => change.field === "eku");

    assert.deepEqual(eku("eku-added.json"), [{ field: "eku", direction: "added", after: "clientAuth" }]);
    assert.deepEqual(eku("eku-removed.json"), [{ field: "eku", direction: "removed", before: "clientAuth" }]);
    // A list that loses all its usages is a removal of the usage, never null.
    assert.deepEqual(eku("eku-emptied.json"), [{ field: "eku", direction: "removed", before: "serverAuth" }]);
    // The extension going from a list to null (absent) is the opposite of a list losing its usages.
    assert.deepEqual(eku("eku-to-null.json"), [{ field: "eku", direction: "changed", before: ["serverAuth"], after: null }]);
    assert.deepEqual(eku("eku-from-null.json"), [{ field: "eku", direction: "changed", before: null, after: ["serverAuth"] }]);
    assert.deepEqual(eku("eku-null-to-empty.json"), [{ field: "eku", direction: "changed", before: null, after: [] }]);
    assert.deepEqual(eku("eku-empty-to-null.json"), [{ field: "eku", direction: "changed", before: [], after: null }]);

    // The two ways the list can end up with nothing are told apart by their direction alone.
    assert.notDeepEqual(eku("eku-emptied.json")[0].direction, eku("eku-to-null.json")[0].direction);

    for (const change of [
        { field: "eku", direction: "changed", before: null, after: [] },
        { field: "eku", direction: "changed", before: [], after: null },
        { field: "eku", direction: "changed", before: ["a", "b"], after: null },
        { field: "eku", direction: "changed", before: null, after: ["a", "b"] },
        { field: "eku", direction: "added", after: "serverAuth" },
        { field: "eku", direction: "removed", before: "1.3.6.1.5.5.7.3.1" },
    ]) {
        assert.deepEqual(errorsOfChange(change), [], JSON.stringify(change));
    }
    for (const change of [
        { field: "eku", direction: "changed", before: null, after: null },
        { field: "eku", direction: "changed", before: ["a"], after: ["b"] },
        { field: "eku", direction: "changed", before: [], after: [] },
        { field: "eku", direction: "changed", before: "a", after: null },
        { field: "eku", direction: "changed", before: null, after: "a" },
        { field: "eku", direction: "changed", before: [1], after: null },
        { field: "eku", direction: "added", after: ["serverAuth"] },
        { field: "eku", direction: "added", after: null },
        { field: "eku", direction: "removed", before: null },
        { field: "eku", direction: "removed", before: "" },
    ]) {
        assert.ok(errorsOfChange(change).length > 0, JSON.stringify(change));
    }
    says(JSON.stringify(schema.$defs.change.allOf), /is one changed change that carries the whole value of each side/);
    says(readme, /so a change between `null` and a list carries the whole value of each side, in one `changed` change/);
});

test("SAN and Extended Key Usage lists are compared as sets: a name that only repeats a different number of times is no change, and the schema and the README say so", () => {
    const document = example("san-repeat-only.json");
    assert.equal(document.identical, false);
    assert.deepEqual(document.changes.map((/** @type {any} */ change) => change.field), ["serial", "notBefore", "notAfter", "sha256"]);
    assert.ok(!document.changes.some((/** @type {any} */ change) => SETS.includes(change.field)));
    // The two sides say what they were: one lists the name twice and the other once.
    assert.match(document.before.source.ref, /twice/);
    assert.match(document.after.source.ref, /once/);

    const text = JSON.stringify(schema.$defs.change.allOf);
    says(text, /It is compared as a set: an element is added or removed only when it is in the list of one side and not in the other's, and how many times a list repeats an element is not compared/);
    says(text, /\[\\"a\.example\\", \\"a\.example\\"\] on one side and \[\\"a\.example\\"\] on the other is no change at all/);
    says(text, /eku is a set too, compared as the SAN lists are/);
    says(readme, /Sets are compared as sets\. An element is `added` or `removed` only when it is in the list of one side and not in the other's, and how many times a list repeats an element is not compared/);
});

// ---------------------------------------------------------------------------------------------
// The chain

test("a link replaced at the same position, a link dropped, a link new and the same links in another order are told apart by sha256 and position", () => {
    /** @param {string} name */
    const chain = (name) => example(name).changes.filter((/** @type {any} */ change) => change.field === "chain");

    const [removed, added] = chain("chain-replaced.json");
    assert.deepEqual([removed.direction, added.direction], ["removed", "added"]);
    assert.equal(removed.before.position, added.after.position, "a replacement keeps the position");
    assert.notEqual(removed.before.sha256, added.after.sha256);

    assert.deepEqual(chain("chain-dropped.json").map((/** @type {any} */ change) => change.direction), ["removed"]);
    assert.deepEqual(chain("chain-added.json").map((/** @type {any} */ change) => change.direction), ["added"]);
    assert.equal(chain("chain-added.json")[0].after.position, 1);

    const [reordered] = chain("chain-reordered.json");
    assert.equal(chain("chain-reordered.json").length, 1);
    assert.equal(reordered.direction, "changed");
    assert.deepEqual([...reordered.before].sort(), [...reordered.after].sort(), "the same links");
    assert.notDeepEqual(reordered.before, reordered.after, "in another order");

    // A link that was dropped is in neither list of the order change.
    const [gone, order] = chain("chain-dropped-and-reordered.json");
    assert.deepEqual([gone.direction, order.direction], ["removed", "changed"]);
    assert.ok(!order.before.includes(gone.before.sha256) && !order.after.includes(gone.before.sha256));
    assert.deepEqual([...order.before].sort(), [...order.after].sort());

    for (const name of exampleFiles) {
        const links = example(name).changes.filter((/** @type {any} */ change) => change.field === "chain" && change.direction !== "changed");
        const shas = links.map((/** @type {any} */ change) => (change.direction === "added" ? change.after : change.before).sha256);
        // A sha256 is never both removed and added: that would be the same link, not a replacement.
        assert.equal(new Set(shas).size, shas.length, name);
    }
    says(JSON.stringify(schema.$defs.change.allOf), /A link replaced by another at the same position is a removed and an added with that position/);
    says(readme, /A link replaced by another at the same position is a `removed` and an `added` with the same `position`/);
});

test("a link without a position or a sha256, with a position that is not a count or a sha256 that is not lowercase hexadecimal, is rejected; so is an order of fewer than two links or of a link twice", () => {
    const link = { position: 0, sha256: SHA("a") };
    assert.deepEqual(errorsOfChange({ field: "chain", direction: "added", after: link }), []);
    assert.deepEqual(errorsOfChange({ field: "chain", direction: "removed", before: link }), []);
    assert.deepEqual(schema.$defs.link.required, ["position", "sha256"]);
    for (const wrong of [
        { sha256: SHA("a") },
        { position: 0 },
        { position: -1, sha256: SHA("a") },
        { position: 1.5, sha256: SHA("a") },
        { position: "0", sha256: SHA("a") },
        { position: 0, sha256: SHA("A") },
        { position: 0, sha256: "a".repeat(63) },
        { position: 0, sha256: 1 },
        SHA("a"),
        null,
        [link],
    ]) {
        assert.ok(errorsOfChange({ field: "chain", direction: "added", after: wrong }).some((error) => error.startsWith("/changes/0/after")), JSON.stringify(wrong));
        assert.ok(errorsOfChange({ field: "chain", direction: "removed", before: wrong }).some((error) => error.startsWith("/changes/0/before")), JSON.stringify(wrong));
    }
    assert.deepEqual(errorsOfChange({ field: "chain", direction: "changed", before: [SHA("a"), SHA("b")], after: [SHA("b"), SHA("a")] }), []);
    for (const [before, after] of [
        [[SHA("a")], [SHA("a")]],
        [[], []],
        [[SHA("a"), SHA("a")], [SHA("a"), SHA("b")]],
        [[SHA("a"), SHA("b")], [SHA("b"), SHA("b")]],
        [[SHA("a"), SHA("b")], link],
        [SHA("a"), SHA("b")],
        [[SHA("a"), SHA("B")], [SHA("a"), SHA("b")]],
    ]) {
        assert.ok(errorsOfChange({ field: "chain", direction: "changed", before, after }).length > 0, JSON.stringify([before, after]));
    }
    // A link where an order belongs, and the other way round.
    assert.ok(errorsOfChange({ field: "chain", direction: "changed", before: link, after: link }).length > 0);
    assert.ok(errorsOfChange({ field: "chain", direction: "added", after: [SHA("a"), SHA("b")] }).length > 0);
});

test("the chain does not use the observation's index, which counts the target, and a changed order holds the same links on both sides", () => {
    says(schema.$defs.link.properties.position.description, /Not the index of the observation, which counts the target too/);
    for (const name of exampleFiles) {
        for (const change of example(name).changes.filter((/** @type {any} */ item) => item.field === "chain" && item.direction === "changed")) {
            assert.deepEqual([...change.before].sort(), [...change.after].sort(), name);
            assert.equal(new Set(change.before).size, change.before.length, name);
        }
    }
});

// ---------------------------------------------------------------------------------------------
// What is not compared, and the order

test("the schema description names the fields a Delta does not compare, derived and observation.at among them", () => {
    const { description } = schema;
    says(description, /Not compared: derived, which follows from the other fields of the observation, and observation\.at, which says when an observation was made and nothing about the certificate/);
    says(description, /observation\.source is not compared either: it says where each side came from and is the legend of before and after/);
    says(description, /Neither are contract, format, target, index and issuedBy/);
    says(readme, /A delta does not compare `derived`, which follows from the other fields, or `observation\.at`, which says when an observation was made and nothing about the certificate/);

    // What a comparison does with warnings is not decided by the Delta.
    assert.ok(!/warning/i.test(JSON.stringify(schema)));
    assert.ok(!/warning/i.test(readme.slice(readme.indexOf("## What changed between two observations"))));
    // And no field of the document is one of those the description says is not compared.
    for (const name of exampleFiles) {
        for (const change of example(name).changes) {
            for (const word of ["derived", "observation", "index", "issuedBy", "target", "format", "contract", "warnings"]) {
                assert.ok(!change.field.split(".").includes(word), `${name}: ${change.field}`);
            }
        }
    }
});

test("changes come in the order of the known fields with chain last, removed before added before changed for one field, and every example is in it", () => {
    assert.equal(KNOWN_FIELDS.at(-1), "chain");
    assert.equal(KNOWN_FIELDS.length, 20);
    assert.equal(new Set(KNOWN_FIELDS).size, 20);
    for (const name of exampleFiles) {
        const changes = example(name).changes;
        const keys = changes.map((/** @type {any} */ change) => KNOWN_FIELDS.indexOf(change.field) * 3 + DIRECTIONS.indexOf(change.direction));
        assert.deepEqual(keys, [...keys].sort((a, b) => a - b), name);
    }
    says(schema.properties.changes.description, /the fields in the order of the list in the description of field, chain last; for one field, removed first, then added, then changed/);
    says(readme, /`removed` before `added` before `changed` for one field/);
});

// ---------------------------------------------------------------------------------------------
// The README

test("the README documents the Delta: before and after, how a set and the chain appear, and every JSON block in it validates", () => {
    const start = readme.indexOf("## What changed between two observations");
    assert.ok(start > 0, "the README has the section");
    const section = readme.slice(start);
    for (const heading of ["### Before and after", "### Changes", "### Sets", "### The chain", "### Order and bytes"]) assert.ok(section.includes(heading), heading);
    for (const name of ["serializeDelta", "schema/delta.schema.json", "schema/examples/delta/"]) assert.ok(section.includes(name), name);

    const blocks = [...section.matchAll(/```json\n([\s\S]*?)```/g)].map((match) => JSON.parse(match[1]));
    assert.equal(blocks.length, 3);
    for (const block of blocks) {
        // A whole delta, or a list of changes to put in one.
        const document = Array.isArray(block) ? delta(block) : block;
        assert.deepEqual(errorsOf(document), [], JSON.stringify(block).slice(0, 80));
    }
    assert.ok(blocks.some((block) => !Array.isArray(block) && block.contract === 1), "one is a whole delta");
    // The example of a set shows a name removed and another added, and one with null.
    const whole = blocks.find((block) => !Array.isArray(block));
    assert.deepEqual(whole.changes.filter((/** @type {any} */ change) => change.field === "san.dns").map((/** @type {any} */ change) => change.direction), ["removed", "added"]);
    assert.ok(blocks.some((block) => Array.isArray(block) && block.some((change) => change.field === "eku" && (change.before === null || change.after === null))));
    assert.ok(blocks.some((block) => Array.isArray(block) && block.some((change) => change.field === "chain" && change.direction === "changed")));
});

test("a Delta is output: nothing in the library checks one, so serializeDelta writes what the schema rejects", () => {
    const invalid = { contract: 2, identical: "yes", before: {}, after: 1, changes: [{ direction: "moved" }] };
    assert.ok(errorsOf(invalid).length > 0);
    const text = serializeDelta(/** @type {any} */ (invalid));
    assert.deepEqual(JSON.parse(text), invalid);
});

// ---------------------------------------------------------------------------------------------
// Real values

test("the values of every fixture, as inspect() builds them, fit a change of their field, and the Delta that holds them validates and serializes to the same bytes again", () => {
    const fixtures = new URL("fixtures/", import.meta.url);
    const at = new Date("2026-09-15T14:02:11Z");
    const observations = readdirSync(fixtures)
        .filter((name) => /\.(pem|der)$/.test(name))
        .sort()
        .flatMap((name) => {
            try {
                return [inspect(readFileSync(new URL(name, fixtures)), { at, source: { kind: "file", ref: name } })];
            } catch (error) {
                if (error instanceof AmbiguousTargetError) return [];
                throw error;
            }
        });
    assert.ok(observations.length > 30, `${observations.length} observations`);

    const scalars = [
        "kind", "selfSigned", "subject.cn", "subject.dn", "issuer.cn", "issuer.dn", "serial", "notBefore", "notAfter",
        "key.algorithm", "key.size", "key.curve", "sha256", "spkiSha256",
    ];
    /** @param {any} certificate @param {string} path */
    const read = (certificate, path) => path.split(".").reduce((value, key) => value[key], certificate);

    let elements = 0;
    let links = 0;
    let nulls = 0;
    for (const [index, before] of observations.entries()) {
        const after = observations[(index + 1) % observations.length];
        const target = before.certificates[before.target];
        const next = after.certificates[after.target];

        /** @type {any[]} */
        const changes = scalars.map((field) => ({ field, direction: "changed", before: read(target, field), after: read(next, field) }));
        nulls += changes.filter((change) => change.before === null || change.after === null).length;
        for (const list of /** @type {const} */ (["dns", "ip", "email", "uri"])) {
            for (const element of target.san[list]) changes.push({ field: `san.${list}`, direction: "removed", before: element });
            for (const element of next.san[list]) changes.push({ field: `san.${list}`, direction: "added", after: element });
        }
        for (const usage of target.eku ?? []) changes.push({ field: "eku", direction: "removed", before: usage });
        changes.push({ field: "eku", direction: "changed", before: target.eku, after: target.eku === null ? [] : null });
        const chain = before.certificates.filter((_, position) => position !== before.target);
        chain.forEach((certificate, position) => changes.push({ field: "chain", direction: "removed", before: { position, sha256: certificate.sha256 } }));
        elements += changes.length;
        links += chain.length;

        const document = /** @type {any} */ ({ contract: 1, identical: target.sha256 === next.sha256, before: before.observation, after: after.observation, changes });
        assert.deepEqual(errorsOf(document), [], before.observation.source.ref);
        const text = serializeDelta(document);
        assert.equal(serializeDelta(JSON.parse(text)), text, before.observation.source.ref);
        assert.deepEqual(JSON.parse(text), JSON.parse(JSON.stringify(document)));
    }
    assert.ok(nulls > 20, `${nulls} null sides`);
    assert.ok(links > 5, `${links} links`);
    assert.ok(elements > 500, `${elements} changes`);
});

test("today the schema does not tie identical to the changes: a Delta that says identical and holds a sha256 change validates, and the examples are what keep the two honest", () => {
    const contradictory = example("reissue-same-key.json");
    contradictory.identical = true;
    assert.deepEqual(errorsOf(contradictory), []);
    const other = example("identical.json");
    other.identical = false;
    assert.deepEqual(errorsOf(other), []);
});
