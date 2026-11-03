import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as library from "../src/index.js";
import { ContractMismatchError, diff, serializeDelta } from "../src/index.js";
import { MAX_VALUES } from "../src/json.js";
import { deepFrozen, hashOf, make, withKeysReversed } from "./helpers/observations.js";
import { validatorFor } from "./helpers/schema.js";

// What `diff` does with two observations, on observations made by hand: nothing here depends on a
// certificate, so nothing changes when the fixtures are generated again. The pairs of real
// certificates are in test/diff-material.test.js.

const errorsOf = validatorFor("delta");

/**
 * The delta of two observations, which must validate against the schema.
 * @param {unknown} before
 * @param {unknown} after
 * @returns {any}
 */
function compare(before, after) {
    const delta = diff(/** @type {any} */ (before), /** @type {any} */ (after));
    assert.deepEqual(errorsOf(delta), []);
    return delta;
}

/**
 * The changes of a pair of observations that differ only in what `replacing` says about the target.
 * @param {Record<string, unknown>} was
 * @param {Record<string, unknown>} is
 */
function changesOf(was, is) {
    return compare(make({ target: was }), make({ target: is })).changes;
}

// ---------------------------------------------------------------------------------------------
// The result

test("diff is exported from the package entry point, takes before then after, and returns a Delta that validates: contract 1, identical, the at and source of each side, and the changes", () => {
    assert.equal(typeof library.diff, "function");
    assert.equal(library.diff.length, 2);

    const before = make({ at: "2026-09-15T14:02:11Z", source: { kind: "file", ref: "old.pem" } });
    const after = make({ at: "2026-01-02T03:04:05Z", source: { kind: "host", ref: "example.test:443", servername: null }, target: { serial: "02" } });
    const delta = compare(before, after);
    assert.deepEqual(Object.keys(delta), ["contract", "identical", "before", "after", "changes"]);
    assert.equal(delta.contract, 1);
    assert.equal(delta.identical, true);
    assert.deepEqual(delta.before, { at: "2026-09-15T14:02:11Z", source: { kind: "file", ref: "old.pem" } });
    assert.deepEqual(delta.after, { at: "2026-01-02T03:04:05Z", source: { kind: "host", ref: "example.test:443", servername: null } });
    assert.deepEqual(delta.changes.map((/** @type {any} */ change) => change.field), ["serial"]);
});

test("the first observation is before and the second is after, for the whole result: swapping the arguments swaps the sides and reverses every direction", () => {
    const old = make({ target: { serial: "01", "san.dns": ["a.example", "b.example"], eku: ["serverAuth"] }, chain: [hashOf(10)], source: { kind: "file", ref: "old.pem" } });
    const renewed = make({ target: { serial: "02", "san.dns": ["b.example", "c.example"], eku: ["serverAuth", "clientAuth"] }, chain: [hashOf(11)], source: { kind: "file", ref: "new.pem" } });
    const forward = compare(old, renewed);
    const backward = compare(renewed, old);
    assert.equal(forward.before.source.ref, "old.pem");
    assert.equal(backward.before.source.ref, "new.pem");

    /** @type {Record<string, string>} */
    const opposite = { added: "removed", removed: "added", changed: "changed" };
    /** @param {any} change */
    const mirrored = (change) => ({
        field: change.field,
        direction: opposite[change.direction],
        ...("after" in change ? { before: change.after } : {}),
        ...("before" in change ? { after: change.before } : {}),
    });
    const key = (/** @type {any} */ change) => JSON.stringify([change.field, change.direction, change.before, change.after]);
    assert.deepEqual(backward.changes.map(key).sort(), forward.changes.map(mirrored).map(key).sort());
    assert.ok(forward.changes.some((/** @type {any} */ change) => change.field === "san.dns" && change.direction === "removed" && change.before === "a.example"));
    assert.ok(backward.changes.some((/** @type {any} */ change) => change.field === "san.dns" && change.direction === "added" && change.after === "a.example"));
});

test("the changes come in the order the schema fixes: the fields as the schema lists them, chain last, and removed, then added, then changed for one field", () => {
    const schema = JSON.parse(readFileSync(new URL("../schema/delta.schema.json", import.meta.url), "utf8"));
    const description = /** @type {string} */ (schema.$defs.change.properties.field.description);
    const known = /Known values: (.*?), and chain,/.exec(description)?.[1].split(", ") ?? assert.fail("the schema lists no known fields");
    const order = [...known, "chain"];
    assert.equal(order.length, 20);

    const before = make({
        chain: [hashOf(10), hashOf(11), hashOf(12)],
        target: {
            kind: "end-entity", selfSigned: false, "subject.cn": "a", "subject.dn": "CN=a", "issuer.cn": "a", "issuer.dn": "CN=a", serial: "01",
            notBefore: "2026-01-01T00:00:00Z", notAfter: "2026-04-01T00:00:00Z",
            "san.dns": ["a"], "san.ip": ["192.0.2.1"], "san.email": ["a@a"], "san.uri": ["https://a"],
            eku: ["serverAuth"], "key.algorithm": "ec", "key.size": 256, "key.curve": "P-256", sha256: hashOf(1), spkiSha256: hashOf(2),
        },
    });
    const after = make({
        chain: [hashOf(13), hashOf(12), hashOf(11)],
        target: {
            kind: "ca", selfSigned: true, "subject.cn": "b", "subject.dn": "CN=b", "issuer.cn": "b", "issuer.dn": "CN=b", serial: "02",
            notBefore: "2026-02-01T00:00:00Z", notAfter: "2026-05-01T00:00:00Z",
            "san.dns": ["b"], "san.ip": ["192.0.2.2"], "san.email": ["b@b"], "san.uri": ["https://b"],
            eku: ["clientAuth"], "key.algorithm": "rsa", "key.size": 2048, "key.curve": null, sha256: hashOf(3), spkiSha256: hashOf(4),
        },
    });
    const delta = compare(before, after);

    const rank = { removed: 0, added: 1, changed: 2 };
    /** @type {number[][]} */
    const positions = delta.changes.map((/** @type {any} */ change) => [order.indexOf(change.field), rank[/** @type {"removed" | "added" | "changed"} */ (change.direction)]]);
    assert.ok(positions.every(([field]) => field >= 0));
    for (let index = 1; index < positions.length; index += 1) {
        const [a, b] = [positions[index - 1], positions[index]];
        assert.ok(a[0] < b[0] || (a[0] === b[0] && a[1] <= b[1]), `${JSON.stringify(delta.changes[index - 1])} comes before ${JSON.stringify(delta.changes[index])}`);
    }
    // Every field of the schema's list changed, so none is missing from the comparison.
    assert.deepEqual([...new Set(delta.changes.map((/** @type {any} */ change) => change.field))], order);
});

test("diff is a pure function: it works on frozen arguments, changes nothing it was given, and shares nothing with the result", () => {
    const before = make({ chain: [hashOf(10)], target: { eku: ["serverAuth"] } });
    const after = make({ chain: [hashOf(11)], target: { eku: null } });
    const snapshots = [structuredClone(before), structuredClone(after)];

    const frozen = diff(deepFrozen(structuredClone(before)), deepFrozen(structuredClone(after)));
    const delta = compare(before, after);
    assert.deepEqual(delta, frozen);
    assert.deepEqual([before, after], snapshots);
    assert.deepEqual(compare(before, after), delta, "the same arguments give the same result");

    // Changing the result changes nothing the arguments hold, and the reverse.
    delta.before.source.ref = "changed";
    /** @type {any} */
    const ekuChange = delta.changes.find((/** @type {any} */ change) => change.field === "eku");
    assert.notEqual(ekuChange.before, before.certificates[0].eku, "the list is a copy");
    ekuChange.before.push("clientAuth");
    /** @type {any} */ (delta.changes.find((/** @type {any} */ change) => change.direction === "removed" && change.field === "chain")).before.sha256 = "changed";
    assert.deepEqual([before, after], snapshots);
});

// ---------------------------------------------------------------------------------------------
// The fields of the target

test("each field of the target is compared by its own value: changed when the two values differ, null included, and absent when they are equal", () => {
    /** @type {[string, unknown, unknown][]} */
    const cases = [
        ["kind", "end-entity", "ca"],
        ["selfSigned", false, true],
        ["subject.cn", "a.example", "b.example"],
        ["subject.cn", "a.example", null],
        ["subject.dn", "CN=a.example", "CN=b.example"],
        ["issuer.cn", "Example CA", "Other CA"],
        ["issuer.cn", null, "Other CA"],
        ["issuer.dn", "CN=Example CA", "CN=Other CA"],
        ["serial", "01", "02"],
        ["notBefore", "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z"],
        ["notAfter", "2026-04-01T00:00:00Z", "2026-05-01T00:00:00Z"],
        ["key.algorithm", "ec", "rsa"],
        ["key.algorithm", "ec", null],
        ["key.size", 256, 384],
        ["key.size", null, 2048],
        ["key.curve", "P-256", "P-384"],
        ["key.curve", "P-256", null],
        ["sha256", hashOf(1), hashOf(3)],
        ["spkiSha256", hashOf(2), hashOf(4)],
    ];
    for (const [field, was, is] of cases) {
        assert.deepEqual(changesOf({ [field]: was }, { [field]: is }), [{ field, direction: "changed", before: was, after: is }], `${field}: ${JSON.stringify(was)} to ${JSON.stringify(is)}`);
        assert.deepEqual(changesOf({ [field]: is }, { [field]: was }), [{ field, direction: "changed", before: is, after: was }], `${field}, reversed`);
        assert.deepEqual(changesOf({ [field]: was }, { [field]: was }), [], `${field} is equal`);
    }
    // null counts as a value: it is never added or removed.
    assert.deepEqual(changesOf({ "key.size": null }, { "key.size": null }), []);
    assert.deepEqual(changesOf({ "key.size": null }, { "key.size": 2048 })[0].direction, "changed");
});

test("identical is true exactly when the sha256 of both targets is the same", () => {
    assert.equal(compare(make(), make()).identical, true);
    assert.equal(compare(make({ target: { sha256: hashOf(1) } }), make({ target: { sha256: hashOf(3) } })).identical, false);
    // Whatever else differs, the fingerprint decides.
    const others = { serial: "09", "san.dns": ["other.example"], eku: null, "key.size": 4096, notAfter: "2027-01-01T00:00:00Z" };
    assert.equal(compare(make(), make({ target: others })).identical, true);
    assert.equal(compare(make(), make({ target: { ...others, sha256: hashOf(5) } })).identical, false);
});

// ---------------------------------------------------------------------------------------------
// The sets

test("a name only in before is removed and one only in after is added, one change each, as the observation lists it, in each of the four lists", () => {
    for (const list of /** @type {const} */ (["dns", "ip", "email", "uri"])) {
        const field = `san.${list}`;
        assert.deepEqual(changesOf({ [field]: ["a", "b", "c"] }, { [field]: ["b"] }), [
            { field, direction: "removed", before: "a" },
            { field, direction: "removed", before: "c" },
        ], field);
        assert.deepEqual(changesOf({ [field]: ["b"] }, { [field]: ["a", "b", "c"] }), [
            { field, direction: "added", after: "a" },
            { field, direction: "added", after: "c" },
        ], field);
        assert.deepEqual(changesOf({ [field]: ["a"] }, { [field]: ["a"] }), [], field);
    }
    // As the observation lists it: no case folding, no trimming, and the order of the list.
    assert.deepEqual(changesOf({ "san.dns": ["Z.example", "a.example"] }, { "san.dns": ["z.example"] }), [
        { field: "san.dns", direction: "removed", before: "Z.example" },
        { field: "san.dns", direction: "removed", before: "a.example" },
        { field: "san.dns", direction: "added", after: "z.example" },
    ]);
    assert.deepEqual(changesOf({ "san.ip": ["2001:db8::1"] }, { "san.ip": [] }), [{ field: "san.ip", direction: "removed", before: "2001:db8::1" }]);
});

test("how many times a name repeats is not a change", () => {
    assert.deepEqual(changesOf({ "san.dns": ["a.example", "a.example", "b.example"] }, { "san.dns": ["a.example", "b.example", "b.example"] }), []);
    assert.deepEqual(changesOf({ "san.dns": ["a.example", "a.example"] }, { "san.dns": ["a.example"] }), []);
    assert.deepEqual(changesOf({ "san.dns": ["a.example"] }, { "san.dns": ["a.example", "a.example"] }), []);
    // A repeated name that is gone is one change, not one per copy.
    assert.deepEqual(changesOf({ "san.dns": ["a.example", "a.example"] }, { "san.dns": [] }), [{ field: "san.dns", direction: "removed", before: "a.example" }]);
    assert.deepEqual(changesOf({ "san.dns": [] }, { "san.dns": ["a.example", "a.example"] }), [{ field: "san.dns", direction: "added", after: "a.example" }]);
});

test("a name that left and a name that arrived are two changes, removed first, and never one replacement", () => {
    assert.deepEqual(changesOf({ "san.dns": ["old.example", "kept.example"] }, { "san.dns": ["kept.example", "new.example"] }), [
        { field: "san.dns", direction: "removed", before: "old.example" },
        { field: "san.dns", direction: "added", after: "new.example" },
    ]);
});

// ---------------------------------------------------------------------------------------------
// The Extended Key Usage

test("a usage in only one side is added or removed, one change per usage", () => {
    assert.deepEqual(changesOf({ eku: ["serverAuth"] }, { eku: ["serverAuth", "clientAuth"] }), [{ field: "eku", direction: "added", after: "clientAuth" }]);
    assert.deepEqual(changesOf({ eku: ["serverAuth", "clientAuth"] }, { eku: ["serverAuth"] }), [{ field: "eku", direction: "removed", before: "clientAuth" }]);
    assert.deepEqual(changesOf({ eku: ["serverAuth"] }, { eku: ["clientAuth", "codeSigning"] }), [
        { field: "eku", direction: "removed", before: "serverAuth" },
        { field: "eku", direction: "added", after: "clientAuth" },
        { field: "eku", direction: "added", after: "codeSigning" },
    ]);
    // A set, as the SAN lists are: repeats and order are not compared.
    assert.deepEqual(changesOf({ eku: ["serverAuth", "serverAuth", "clientAuth"] }, { eku: ["clientAuth", "serverAuth"] }), []);
});

test("null (no extension) against a list, [] included, is one changed with the whole value on each side, in both directions", () => {
    for (const list of [["serverAuth"], ["serverAuth", "clientAuth"], []]) {
        assert.deepEqual(changesOf({ eku: list }, { eku: null }), [{ field: "eku", direction: "changed", before: list, after: null }], JSON.stringify(list));
        assert.deepEqual(changesOf({ eku: null }, { eku: list }), [{ field: "eku", direction: "changed", before: null, after: list }], JSON.stringify(list));
    }
    assert.deepEqual(changesOf({ eku: null }, { eku: null }), []);
    assert.deepEqual(changesOf({ eku: [] }, { eku: [] }), []);
});

test("a list that loses all its usages is a removed per usage and ends in [], never in null, so the two ways of ending with nothing differ in their direction", () => {
    const lost = changesOf({ eku: ["serverAuth", "clientAuth"] }, { eku: [] });
    assert.deepEqual(lost, [
        { field: "eku", direction: "removed", before: "serverAuth" },
        { field: "eku", direction: "removed", before: "clientAuth" },
    ]);
    assert.ok(lost.every((/** @type {any} */ change) => !("after" in change)));

    // The extension gone is another thing: one changed, to null, which allows any purpose.
    const gone = changesOf({ eku: ["serverAuth", "clientAuth"] }, { eku: null });
    assert.deepEqual(gone.map((/** @type {any} */ change) => change.direction), ["changed"]);
    assert.notDeepEqual(lost.map((/** @type {any} */ change) => change.direction), gone.map((/** @type {any} */ change) => change.direction));
});

// ---------------------------------------------------------------------------------------------
// The chain

/**
 * The changes to the chain between two lists of links, given as numbers (see `hashOf`).
 * @param {number[]} was
 * @param {number[]} is
 * @returns {any[]}
 */
function chainOf(was, is) {
    return compare(make({ chain: was.map(hashOf) }), make({ chain: is.map(hashOf) })).changes;
}

test("a replaced intermediate is a removed and an added at the same position", () => {
    assert.deepEqual(chainOf([10], [11]), [
        { field: "chain", direction: "removed", before: { position: 0, sha256: hashOf(10) } },
        { field: "chain", direction: "added", after: { position: 0, sha256: hashOf(11) } },
    ]);
    assert.deepEqual(chainOf([10, 12], [10, 11]), [
        { field: "chain", direction: "removed", before: { position: 1, sha256: hashOf(12) } },
        { field: "chain", direction: "added", after: { position: 1, sha256: hashOf(11) } },
    ]);
});

test("a link only before sends is removed with its position in before, and a link that moves only because another was dropped before it is no change", () => {
    assert.deepEqual(chainOf([10, 11], [11]), [{ field: "chain", direction: "removed", before: { position: 0, sha256: hashOf(10) } }]);
    assert.deepEqual(chainOf([10, 11], [10]), [{ field: "chain", direction: "removed", before: { position: 1, sha256: hashOf(11) } }]);
    assert.deepEqual(chainOf([10], []), [{ field: "chain", direction: "removed", before: { position: 0, sha256: hashOf(10) } }]);
});

test("a link only after sends is added with its position in after, and a link that moves only because another was added before it is no change", () => {
    assert.deepEqual(chainOf([11], [10, 11]), [{ field: "chain", direction: "added", after: { position: 0, sha256: hashOf(10) } }]);
    assert.deepEqual(chainOf([10], [10, 11]), [{ field: "chain", direction: "added", after: { position: 1, sha256: hashOf(11) } }]);
    assert.deepEqual(chainOf([], [10]), [{ field: "chain", direction: "added", after: { position: 0, sha256: hashOf(10) } }]);
    assert.deepEqual(chainOf([], []), []);
    assert.deepEqual(chainOf([10, 11], [10, 11]), []);
});

test("the same links in another relative order are one changed whose two sides list their sha256 in the order of each side", () => {
    assert.deepEqual(chainOf([10, 11], [11, 10]), [{ field: "chain", direction: "changed", before: [hashOf(10), hashOf(11)], after: [hashOf(11), hashOf(10)] }]);
    assert.deepEqual(chainOf([10, 11, 12], [12, 10, 11]), [{ field: "chain", direction: "changed", before: [hashOf(10), hashOf(11), hashOf(12)], after: [hashOf(12), hashOf(10), hashOf(11)] }]);
});

test("a dropped link together with a reorder of the others is a removed and a changed that lists only the links both sides send", () => {
    assert.deepEqual(chainOf([10, 11, 12], [12, 10]), [
        { field: "chain", direction: "removed", before: { position: 1, sha256: hashOf(11) } },
        { field: "chain", direction: "changed", before: [hashOf(10), hashOf(12)], after: [hashOf(12), hashOf(10)] },
    ]);
    // A new link and a reorder, and a replacement next to a reorder: removed, added, changed.
    assert.deepEqual(chainOf([10, 11], [11, 13, 10]), [
        { field: "chain", direction: "added", after: { position: 1, sha256: hashOf(13) } },
        { field: "chain", direction: "changed", before: [hashOf(10), hashOf(11)], after: [hashOf(11), hashOf(10)] },
    ]);
    assert.deepEqual(chainOf([10, 11, 12], [14, 12, 11]), [
        { field: "chain", direction: "removed", before: { position: 0, sha256: hashOf(10) } },
        { field: "chain", direction: "added", after: { position: 0, sha256: hashOf(14) } },
        { field: "chain", direction: "changed", before: [hashOf(11), hashOf(12)], after: [hashOf(12), hashOf(11)] },
    ]);
});

test("the position of a link counts the certificates other than the target, wherever the target is among them", () => {
    const chain = [hashOf(10), hashOf(11)];
    // The target first, in the middle or last gives the same links, so there is no change.
    for (const targetAt of [0, 1, 2]) {
        assert.deepEqual(compare(make({ chain }), make({ chain, targetAt })).changes, [], `target at ${targetAt}`);
    }
    // The positions are those among the other certificates, not the index of the observation.
    assert.deepEqual(compare(make({ chain, targetAt: 1 }), make({ chain: [chain[0]], targetAt: 1 })).changes, [
        { field: "chain", direction: "removed", before: { position: 1, sha256: hashOf(11) } },
    ]);
    assert.deepEqual(compare(make({ chain: [chain[1]], targetAt: 1 }), make({ chain, targetAt: 1 })).changes, [
        { field: "chain", direction: "added", after: { position: 0, sha256: hashOf(10) } },
    ]);
});

test("a certificate repeated in one observation is one link, at the position where it first appears", () => {
    assert.deepEqual(chainOf([10, 10, 11], [11]), [{ field: "chain", direction: "removed", before: { position: 0, sha256: hashOf(10) } }]);
    assert.deepEqual(chainOf([10, 11, 10], [10, 11]), []);
    assert.deepEqual(chainOf([11, 10, 10], [10, 11]), [{ field: "chain", direction: "changed", before: [hashOf(11), hashOf(10)], after: [hashOf(10), hashOf(11)] }]);
    // The position counts the copies: the link after a repeated one is at 2.
    assert.deepEqual(chainOf([10, 10, 11], [10]), [{ field: "chain", direction: "removed", before: { position: 2, sha256: hashOf(11) } }]);
});

test("the chain changes come after every field of the target", () => {
    const delta = compare(make({ chain: [hashOf(10)], target: { serial: "01", sha256: hashOf(1) } }), make({ chain: [hashOf(11)], target: { serial: "02", sha256: hashOf(3) } }));
    assert.deepEqual(delta.changes.map((/** @type {any} */ change) => change.field), ["serial", "sha256", "chain", "chain"]);
});

test("identical is about the targets only: the same target with a chain on one side and none on the other is identical and has a chain change", () => {
    const delta = compare(make({ chain: [hashOf(10)] }), make());
    assert.equal(delta.identical, true);
    assert.deepEqual(delta.changes, [{ field: "chain", direction: "removed", before: { position: 0, sha256: hashOf(10) } }]);
    const reverse = compare(make(), make({ chain: [hashOf(10)] }));
    assert.equal(reverse.identical, true);
    assert.deepEqual(reverse.changes, [{ field: "chain", direction: "added", after: { position: 0, sha256: hashOf(10) } }]);
});

// ---------------------------------------------------------------------------------------------
// What takes no part

test("warnings, derived, observation.at and observation.source take no part: two observations of the same material that differ only in them give no change", () => {
    const base = make({ chain: [hashOf(10)] });
    const other = make({
        chain: [hashOf(10)],
        at: "2030-12-31T23:59:59Z",
        source: { kind: "host", ref: "example.test:443", servername: "example.test", provider: "x" },
        warnings: [{ code: "KIND_UNRELIABLE", certificate: 0, message: "m" }, { code: "EKU_UNRELIABLE", certificate: 0, message: "n" }],
    });
    for (const certificate of other.certificates) certificate.derived = { daysRemaining: -400, lifetimeFraction: null };
    const delta = compare(base, other);
    assert.deepEqual(delta.changes, []);
    assert.equal(delta.identical, true);
    // They are still the legend: the at and the source of each side are those of its observation.
    assert.deepEqual(delta.before, { at: "2026-09-15T14:02:11Z", source: { kind: "file", ref: "service.pem" } });
    assert.deepEqual(delta.after, { at: "2030-12-31T23:59:59Z", source: { kind: "host", ref: "example.test:443", servername: "example.test", provider: "x" } });

    // Warnings alone, in either direction, are no change.
    const warned = make({ warnings: [{ code: "DUPLICATE_CERTIFICATE", certificate: null, message: "m" }] });
    assert.deepEqual(compare(make(), warned).changes, []);
    assert.deepEqual(compare(warned, make()).changes, []);
});

test("issuedBy, index and target are positions inside one observation and are not compared", () => {
    const chain = [hashOf(10), hashOf(11)];
    const first = make({ chain, targetAt: 0 });
    const last = make({ chain, targetAt: 2 });
    first.certificates[0].issuedBy = [1];
    last.certificates[2].issuedBy = [0, 1];
    assert.notEqual(first.target, last.target);
    const indexOfLink = (/** @type {any} */ observation) => observation.certificates.find((/** @type {any} */ certificate) => certificate.sha256 === hashOf(10)).index;
    assert.notEqual(indexOfLink(first), indexOfLink(last));
    assert.deepEqual(compare(first, last).changes, []);
});

// ---------------------------------------------------------------------------------------------
// The errors

test("ContractMismatchError is exported with the other errors, is an Error and not a TypeError, and says which of contract and format differs", () => {
    assert.equal(library.ContractMismatchError, ContractMismatchError);
    assert.ok(Object.keys(library).includes("ParseError") && Object.keys(library).includes("ContractMismatchError"));

    const contract = (() => {
        try {
            diff(make(), { ...make(), contract: /** @type {any} */ (2) });
        } catch (error) {
            return /** @type {ContractMismatchError} */ (error);
        }
        return assert.fail("no error");
    })();
    assert.ok(contract instanceof ContractMismatchError && contract instanceof Error);
    assert.equal(contract instanceof TypeError, false);
    assert.equal(contract.name, "ContractMismatchError");
    assert.equal(contract.field, "contract");
    assert.match(contract.message, /contract/);
    assert.match(contract.message, /before has 1 and after has 2/);

    const format = (() => {
        try {
            diff({ ...make(), format: /** @type {any} */ ("pkcs7 secret text") }, make());
        } catch (error) {
            return /** @type {ContractMismatchError} */ (error);
        }
        return assert.fail("no error");
    })();
    assert.ok(format instanceof ContractMismatchError);
    assert.equal(format.field, "format");
    assert.match(format.message, /format/);
    assert.doesNotMatch(format.message, /pkcs7|secret/, "the format is text of the caller's and is not quoted");

    // Both differ: the contract is the one named.
    assert.throws(() => diff({ ...make(), contract: /** @type {any} */ (3), format: /** @type {any} */ ("other") }, make()), { name: "ContractMismatchError", field: "contract" });
    assert.throws(() => diff(make(), { ...make(), contract: /** @type {any} */ (0), format: /** @type {any} */ ("other") }), { name: "ContractMismatchError", field: "contract" });
});

test("a difference between the two certificates is never an error, and the contract and the format are decided before anything else is read", () => {
    assert.doesNotThrow(() => diff(make(), make({ target: { kind: "ca", sha256: hashOf(7) }, chain: [hashOf(10)] })));
    // Another contract may have another shape, so nothing else is read, and nothing else is needed.
    assert.throws(() => diff(/** @type {any} */ ({ contract: 2, format: "x509" }), make()), ContractMismatchError);
    assert.throws(() => diff(make(), /** @type {any} */ ({ contract: 1, format: "pkcs7" })), ContractMismatchError);
    // Both of the same unknown version: a call this version cannot answer, not a mismatch.
    const unknown = /** @type {any} */ ({ contract: 2, format: "x509" });
    assert.throws(() => diff(unknown, unknown), { name: "TypeError", message: "contract must be 1 in both observations" });
    const elsewhere = /** @type {any} */ ({ contract: 1, format: "pkcs7" });
    assert.throws(() => diff(elsewhere, { ...elsewhere }), { name: "TypeError", message: 'format must be "x509" in both observations' });
    // An argument that is not an observation is refused before the versions are compared.
    assert.throws(() => diff(/** @type {any} */ ({ contract: "1", format: "x509" }), { ...make(), contract: /** @type {any} */ (2) }), { name: "TypeError", message: "before.contract must be a whole number" });
    assert.throws(() => diff({ ...make(), contract: /** @type {any} */ (2) }, /** @type {any} */ (null)), { name: "TypeError", message: "after must be an observation: an object" });
});

/**
 * An observation that is wrong in one way.
 * @param {(observation: any) => void} spoil
 */
function spoiled(spoil) {
    const observation = make({ chain: [hashOf(10)] });
    spoil(observation);
    return observation;
}

test("an argument that is not an observation is a TypeError that names what is missing, for before and for after", () => {
    /** @type {[string, (observation: any) => void, RegExp][]} */
    const cases = [
        ["no contract", (o) => delete o.contract, /^\w+\.contract must be a whole number$/],
        ["a contract that is text", (o) => { o.contract = "1"; }, /^\w+\.contract must be a whole number$/],
        ["a contract with a fraction", (o) => { o.contract = 1.5; }, /^\w+\.contract must be a whole number$/],
        ["no format", (o) => delete o.format, /^\w+\.format must be text$/],
        ["a format that is a number", (o) => { o.format = 1; }, /^\w+\.format must be text$/],
        ["no observation", (o) => delete o.observation, /^\w+\.observation must be an object$/],
        ["an observation that is a list", (o) => { o.observation = []; }, /^\w+\.observation must be an object$/],
        ["no at", (o) => delete o.observation.at, /^\w+\.observation\.at must be text$/],
        ["an at that is a number", (o) => { o.observation.at = 0; }, /^\w+\.observation\.at must be text$/],
        ["no source", (o) => delete o.observation.source, /^\w+\.observation\.source must be an object$/],
        ["a source that is text", (o) => { o.observation.source = "file"; }, /^\w+\.observation\.source must be an object$/],
        ["a source that holds a function", (o) => { o.observation.source = { kind: "file", ref: () => 1 }; }, /^\w+\.observation\.source holds something JSON cannot, at \/ref: it is a function$/],
        ["no target", (o) => delete o.target, /^\w+\.target must be the position of a certificate in \w+\.certificates$/],
        ["a target that is text", (o) => { o.target = "0"; }, /^\w+\.target must be the position of a certificate/],
        ["a target with a fraction", (o) => { o.target = 0.5; }, /^\w+\.target must be the position of a certificate/],
        ["a negative target", (o) => { o.target = -1; }, /^\w+\.target must be the position of a certificate/],
        ["a target past the certificates", (o) => { o.target = 2; }, /^\w+\.target must be the position of a certificate/],
        ["no certificates", (o) => delete o.certificates, /^\w+\.target must be the position of a certificate/],
        ["certificates that is an object", (o) => { o.certificates = { 0: o.certificates[0] }; }, /^\w+\.target must be the position of a certificate/],
        ["a target that is null", (o) => { o.certificates[0] = null; }, /^\w+\.target must be the position of a certificate/],
        ["a kind that is a number", (o) => { o.certificates[0].kind = 1; }, /^\w+\.certificates\[0\]\.kind must be text$/],
        ["no selfSigned", (o) => delete o.certificates[0].selfSigned, /^\w+\.certificates\[0\]\.selfSigned must be true or false$/],
        ["a selfSigned that is text", (o) => { o.certificates[0].selfSigned = "false"; }, /^\w+\.certificates\[0\]\.selfSigned must be true or false$/],
        ["no subject", (o) => delete o.certificates[0].subject, /^\w+\.certificates\[0\]\.subject must be an object$/],
        ["a subject that is null", (o) => { o.certificates[0].subject = null; }, /^\w+\.certificates\[0\]\.subject must be an object$/],
        ["a subject.cn that is a number", (o) => { o.certificates[0].subject.cn = 5; }, /^\w+\.certificates\[0\]\.subject\.cn must be text or null$/],
        ["no subject.cn", (o) => delete o.certificates[0].subject.cn, /^\w+\.certificates\[0\]\.subject\.cn must be text or null$/],
        ["a subject.dn that is null", (o) => { o.certificates[0].subject.dn = null; }, /^\w+\.certificates\[0\]\.subject\.dn must be text$/],
        ["an issuer.dn that is a list", (o) => { o.certificates[0].issuer.dn = []; }, /^\w+\.certificates\[0\]\.issuer\.dn must be text$/],
        ["a serial that is a number", (o) => { o.certificates[0].serial = 1; }, /^\w+\.certificates\[0\]\.serial must be text$/],
        ["no notBefore", (o) => delete o.certificates[0].notBefore, /^\w+\.certificates\[0\]\.notBefore must be text$/],
        ["no notAfter", (o) => delete o.certificates[0].notAfter, /^\w+\.certificates\[0\]\.notAfter must be text$/],
        ["no san", (o) => delete o.certificates[0].san, /^\w+\.certificates\[0\]\.san must be an object$/],
        ["a san.dns that is text", (o) => { o.certificates[0].san.dns = "a.example"; }, /^\w+\.certificates\[0\]\.san\.dns must be a list of text$/],
        ["a san.ip that is missing", (o) => delete o.certificates[0].san.ip, /^\w+\.certificates\[0\]\.san\.ip must be a list of text$/],
        ["a san.email with a number", (o) => { o.certificates[0].san.email = ["a@a", 1]; }, /^\w+\.certificates\[0\]\.san\.email\[1\] must be text$/],
        ["a san.uri with null", (o) => { o.certificates[0].san.uri = [null]; }, /^\w+\.certificates\[0\]\.san\.uri\[0\] must be text$/],
        ["no eku", (o) => delete o.certificates[0].eku, /^\w+\.certificates\[0\]\.eku must be a list of text$/],
        ["an eku that is text", (o) => { o.certificates[0].eku = "serverAuth"; }, /^\w+\.certificates\[0\]\.eku must be a list of text$/],
        ["an eku with a number", (o) => { o.certificates[0].eku = [1]; }, /^\w+\.certificates\[0\]\.eku\[0\] must be text$/],
        ["no key", (o) => delete o.certificates[0].key, /^\w+\.certificates\[0\]\.key must be an object$/],
        ["a key.algorithm that is a number", (o) => { o.certificates[0].key.algorithm = 1; }, /^\w+\.certificates\[0\]\.key\.algorithm must be text or null$/],
        ["a key.size that is text", (o) => { o.certificates[0].key.size = "256"; }, /^\w+\.certificates\[0\]\.key\.size must be a whole number or null$/],
        ["a key.size with a fraction", (o) => { o.certificates[0].key.size = 256.5; }, /^\w+\.certificates\[0\]\.key\.size must be a whole number or null$/],
        ["no key.size", (o) => delete o.certificates[0].key.size, /^\w+\.certificates\[0\]\.key\.size must be a whole number or null$/],
        ["a key.curve that is a number", (o) => { o.certificates[0].key.curve = 1; }, /^\w+\.certificates\[0\]\.key\.curve must be text or null$/],
        ["a sha256 in capitals", (o) => { o.certificates[0].sha256 = hashOf(255).toUpperCase(); }, /^\w+\.certificates\[0\]\.sha256 must be 64 lowercase hexadecimal characters$/],
        ["a sha256 that is short", (o) => { o.certificates[0].sha256 = "ab"; }, /^\w+\.certificates\[0\]\.sha256 must be 64 lowercase hexadecimal characters$/],
        ["a spkiSha256 that is a number", (o) => { o.certificates[0].spkiSha256 = 1; }, /^\w+\.certificates\[0\]\.spkiSha256 must be 64 lowercase hexadecimal characters$/],
        ["a chain link that is null", (o) => { o.certificates.push(null); }, /^\w+\.certificates\[2\] must be an object$/],
        ["a chain link with no sha256", (o) => delete o.certificates[1].sha256, /^\w+\.certificates\[1\]\.sha256 must be 64 lowercase hexadecimal characters$/],
        ["a chain link with a short sha256", (o) => { o.certificates[1].sha256 = "ab"; }, /^\w+\.certificates\[1\]\.sha256 must be 64 lowercase hexadecimal characters$/],
    ];
    for (const [what, spoil, message] of cases) {
        assert.throws(() => diff(spoiled(spoil), make()), { name: "TypeError", message });
        assert.throws(() => diff(make(), spoiled(spoil)), { name: "TypeError", message });
        assert.throws(() => diff(spoiled(spoil), make()), (/** @type {Error} */ error) => error.message.startsWith("before"), `${what}: the message starts with the argument`);
        assert.throws(() => diff(make(), spoiled(spoil)), (/** @type {Error} */ error) => error.message.startsWith("after"), `${what}: the message starts with the argument`);
    }

    for (const [what, given] of /** @type {[string, unknown][]} */ ([
        ["null", null], ["undefined", undefined], ["a list", []], ["text", "observation"], ["a number", 5], ["a function", () => 1],
        ["an instance of a class", new (class Observation {})()],
    ])) {
        assert.throws(() => diff(/** @type {any} */ (given), make()), { name: "TypeError", message: "before must be an observation: an object" }, `${what} as before`);
        assert.throws(() => diff(make(), /** @type {any} */ (given)), { name: "TypeError", message: "after must be an observation: an object" }, `${what} as after`);
    }
    assert.throws(() => diff(/** @type {any} */ (undefined), /** @type {any} */ (undefined)), { name: "TypeError", message: "before must be an observation: an object" });
    assert.throws(() => /** @type {any} */ (diff)(make()), { name: "TypeError", message: "after must be an observation: an object" });
});

test("diff reads only the fields it uses: what an observation holds besides them is not needed, and is not read", () => {
    const needed = make({ chain: [hashOf(10)] });
    delete needed.warnings;
    for (const certificate of needed.certificates) {
        delete certificate.index;
        delete certificate.issuedBy;
        delete certificate.derived;
    }
    assert.deepEqual(compare(needed, make({ chain: [hashOf(10)] })).changes, []);

    // Anything at all in the others is left alone, including what could not be copied or would throw.
    const junk = make({ chain: [hashOf(10)] });
    junk.warnings = [{ code: undefined, run() {} }, 5, null];
    junk.extra = Symbol("x");
    junk.certificates[0].derived = { daysRemaining: Number.NaN, lifetimeFraction: 10n };
    junk.certificates[1].issuedBy = "elsewhere";
    junk.certificates[0].unknown = () => 1;
    Object.defineProperty(junk, "warnings", { get() { throw new Error("read"); }, enumerable: true });
    Object.defineProperty(junk.certificates[0], "index", { get() { throw new Error("read"); }, enumerable: true });
    assert.deepEqual(compare(junk, make({ chain: [hashOf(10)] })).changes, []);

    // An observation without a prototype, and the same object as both arguments.
    const bare = Object.assign(Object.create(null), make());
    assert.deepEqual(compare(bare, bare).changes, []);
    const again = make({ chain: [hashOf(10)] });
    const same = compare(again, again);
    assert.equal(same.identical, true);
    assert.deepEqual(same.changes, []);
});

test("an accessor is never called: a field that is one reads as missing", () => {
    let calls = 0;
    const observation = make();
    Object.defineProperty(observation.certificates[0], "kind", { get() { calls += 1; return "end-entity"; }, enumerable: true });
    assert.throws(() => diff(observation, make()), { name: "TypeError", message: "before.certificates[0].kind must be text" });
    const list = make();
    Object.defineProperty(list.certificates[0].san.dns, "0", { get() { calls += 1; return "a.example"; }, enumerable: true });
    assert.throws(() => diff(make(), list), { name: "TypeError", message: "after.certificates[0].san.dns[0] must be text" });
    const contract = make();
    Object.defineProperty(contract, "contract", { get() { calls += 1; return 1; }, enumerable: true });
    assert.throws(() => diff(contract, make()), { name: "TypeError", message: "before.contract must be a whole number" });
    assert.equal(calls, 0);
});

test("an object that throws when it is read is a TypeError that says it cannot be read, and quotes nothing of what the object threw", () => {
    const revoked = Proxy.revocable({}, {});
    revoked.revoke();
    assert.throws(() => diff(/** @type {any} */ (revoked.proxy), make()), { name: "TypeError", message: "before cannot be read" });

    const trap = new Proxy({}, { getOwnPropertyDescriptor() { throw new RangeError("secret text"); } });
    assert.throws(() => diff(make(), /** @type {any} */ (trap)), (/** @type {Error} */ error) => error.name === "TypeError" && error.message === "after cannot be read" && !/secret/.test(error.message));

    const inside = make();
    inside.certificates = new Proxy([], { getOwnPropertyDescriptor() { throw new Error("secret text"); } });
    assert.throws(() => diff(inside, make()), { name: "TypeError", message: "before cannot be read" });
    const list = make();
    list.certificates[0].san.dns = new Proxy(["a.example"], { getOwnPropertyDescriptor() { throw new Error("secret text"); } });
    assert.throws(() => diff(make(), list), { name: "TypeError", message: "after cannot be read" });
    const source = make();
    source.observation.source = new Proxy({ kind: "file" }, { ownKeys() { throw new Error("secret text"); } });
    assert.throws(() => diff(source, make()), (/** @type {Error} */ error) => error.name === "TypeError" && !/secret/.test(error.message));
});

test("a source is copied as JSON, so a key that JSON.parse makes, such as __proto__, stays a key of the side", () => {
    const source = JSON.parse('{"kind":"file","ref":"a.pem","__proto__":{"polluted":true}}');
    const delta = compare(make({ source }), make());
    assert.ok(Object.hasOwn(delta.before.source, "__proto__"));
    assert.equal(delta.before.source.polluted, undefined);
    assert.notEqual(delta.before.source, source);
    assert.deepEqual(JSON.parse(serializeDelta(delta)).before.source.ref, "a.pem");
});

test("an observation can hold up to a million values in its lists and certificates together, and one more is a TypeError, whatever lists they are in", () => {
    // A list of one text repeated: cheap to make, and the Set that compares it has one element.
    const names = (/** @type {number} */ length) => Array.from({ length }, () => "a.example");
    // What the pair holds besides that list: the usage and the certificate of the first observation,
    // and the name, the usage and the certificate of the second.
    const rest = 2 + 3;

    // The other side lists the same name, so that however the comparison goes wrong it has no change
    // to make for each of the copies.
    const exact = make({ target: { "san.dns": names(MAX_VALUES - rest) } });
    const same = make({ target: { "san.dns": ["a.example"] } });
    assert.deepEqual(compare(exact, same).changes, [], "at the limit the lists are read in full");
    const past = make({ target: { "san.dns": names(MAX_VALUES - rest + 1) } });
    // The first observation still fits; the second is the one that goes past.
    assert.throws(() => diff(past, same), { name: "TypeError", message: "after.certificates is past the million values that are read" });
    assert.throws(() => diff(make({ target: { "san.dns": names(MAX_VALUES + 1) } }), same), { name: "TypeError", message: "before.certificates[0].san.dns is past the million values that are read" });

    // The limit is for both together, and the other lists count too.
    const half = make({ target: { "san.uri": names(600_000) } });
    assert.throws(() => diff(half, half), { name: "TypeError", message: /^after\.certificates\[0\]\.san\.uri is past the million values/ });
    assert.throws(() => diff(make({ target: { eku: names(MAX_VALUES) } }), make()), /^TypeError: before\.certificates\[0\]\.eku is past the million values/);
    // The certificates count as well.
    const many = make();
    many.certificates = [many.certificates[0], ...new Array(MAX_VALUES).fill({ sha256: hashOf(10) })];
    assert.throws(() => diff(many, make()), { name: "TypeError", message: "before.certificates is past the million values that are read" });
});

test("a comparison with hundreds of thousands of changes is made in full: the changes are not passed as arguments of a call", () => {
    // Two lists with nothing in common give a change for every name of both, and a call that takes
    // them all as arguments overflows the stack at about a hundred thousand.
    const names = (/** @type {string} */ prefix) => Array.from({ length: 100_000 }, (_, index) => `${prefix}${index}.example`);
    const delta = diff(make({ target: { "san.dns": names("a") } }), make({ target: { "san.dns": names("b") } }));
    assert.equal(delta.changes.length, 200_000);
    assert.deepEqual(delta.changes[0], { field: "san.dns", direction: "removed", before: "a0.example" });
    assert.deepEqual(delta.changes[100_000], { field: "san.dns", direction: "added", after: "b0.example" });

    // The same for the chain: every link replaced.
    // Only the sha256 of a link is read, so the links are left at that.
    const sending = (/** @type {number} */ from) => {
        const observation = make();
        observation.certificates = [observation.certificates[0], ...Array.from({ length: 100_000 }, (_, index) => ({ sha256: hashOf(from + index) }))];
        return observation;
    };
    const chain = diff(sending(1000), sending(1_000_000));
    assert.equal(chain.changes.length, 200_000);
    assert.deepEqual(chain.changes[199_999], { field: "chain", direction: "added", after: { position: 99_999, sha256: hashOf(1_099_999) } });
});

test("a list with a gap or an element that is not text is a TypeError at the element, and the length of a sparse list is not walked", () => {
    const gap = make();
    gap.certificates[0].san.dns = ["a.example", , "c.example"]; // eslint-disable-line no-sparse-arrays
    assert.throws(() => diff(gap, make()), { name: "TypeError", message: "before.certificates[0].san.dns[1] must be text" });

    // A list that claims more than a million values is refused before its elements are read.
    const claimed = make();
    claimed.certificates[0].san.dns = new Array(MAX_VALUES + 1);
    assert.throws(() => diff(claimed, make()), { name: "TypeError", message: /past the million values/ });
});

// ---------------------------------------------------------------------------------------------
// The bytes

test("the same two observations always give the same bytes through serializeDelta, whatever the order of the keys they were built with", () => {
    const before = make({ chain: [hashOf(10), hashOf(11)], target: { "san.dns": ["a.example", "b.example"], eku: ["serverAuth"], serial: "01" }, source: { kind: "host", ref: "example.test:443", servername: null } });
    const after = make({ chain: [hashOf(11), hashOf(12)], target: { "san.dns": ["b.example", "c.example"], eku: null, serial: "02", sha256: hashOf(3) }, source: { kind: "file", ref: "new.pem" } });

    const written = serializeDelta(compare(before, after));
    const reversed = serializeDelta(compare(withKeysReversed(before), withKeysReversed(after)));
    assert.equal(reversed, written);
    assert.notDeepEqual(Object.keys(withKeysReversed(before)), Object.keys(before), "the second construction orders the keys the other way");
    assert.notDeepEqual(Object.keys(withKeysReversed(before.certificates[0])), Object.keys(before.certificates[0]));
    // It is a text that validates, and writing it again changes nothing.
    assert.deepEqual(errorsOf(JSON.parse(written)), []);
    assert.equal(serializeDelta(JSON.parse(written)), written);
});

// ---------------------------------------------------------------------------------------------
// The README

const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");

test("the README documents diff, the convention of its two arguments, ContractMismatchError and what takes no part, and its example runs", () => {
    const section = readme.slice(readme.indexOf("### Comparing two observations"));
    assert.ok(section.length > 500, "the README has the section");
    assert.match(section, /`diff\(before, after\)`/);
    assert.match(section, /first argument is `before` and the second is `after`, for the whole result/);
    assert.match(section, /`ContractMismatchError`/);
    assert.match(section, /`field` says which/);
    assert.match(section, /`warnings`/);
    assert.match(section, /never an error/);
    assert.doesNotMatch(readme, /does not compare two observations yet/);

    const block = /```js\n([\s\S]*?)```/.exec(section)?.[1] ?? assert.fail("the README has no example of diff");
    assert.match(block, /^import \{ diff, inspect, serializeDelta \} from "certdrift";$/m);
    /** @type {unknown[][]} */
    const printed = [];
    const fixture = (/** @type {string} */ name) => readFileSync(new URL(`fixtures/${name}`, import.meta.url));
    const run = new Function("diff", "inspect", "serializeDelta", "deployedPem", "renewedPem", "console", block.replace(/^import .*$/m, ""));
    run(library.diff, library.inspect, library.serializeDelta, fixture("pagos.pem"), fixture("pagos-san-swapped.pem"), { log: (/** @type {unknown[]} */ ...shown) => printed.push(shown) });
    assert.equal(printed.length, 1);
    const written = JSON.parse(String(printed[0][0]));
    assert.deepEqual(errorsOf(written), []);
    assert.ok(written.changes.some((/** @type {any} */ change) => change.field === "san.dns" && change.direction === "removed"));
});
